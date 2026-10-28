"""cml_build_lab: a whole lab from a compact spec in one preview-first call."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cml_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    get_settings,
)
from cml_mcp.build import (
    UNLICENSED_DEFINITIONS,
    VSWITCH_FILE,
    BuildError,
    NodeSpec,
    NodeStaging,
    boot_order,
    build_topology,
    is_cat9kv,
    serial_of,
    to_yaml,
    unique_serial,
    with_serial,
)
from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.licence import (
    compact_usage,
    explain_licence_error,
    licence_blocker,
    licence_usage,
    nodes_ram_mb,
    ram_check,
    ram_headroom,
)
from cml_mcp.recipes import placeholders, redact_values, resolve_secrets, secret_names_by_value
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.lab_writes import Wait, known_definitions, title_taken
from cml_mcp.tools.smart import Timeout

# Where cml_build_lab fills ${LAB_*} lab secrets: what reaches the device. Labels, tags and the rest show in
# the preview and stay as written.
SECRET_FIELDS = {"config", "files", "credentials"}


def node_secret_refs(nodes: list[NodeSpec]) -> dict[str, list[str]]:
    """{LAB_* name: labels of the nodes whose config, files or credentials reference it}."""
    refs: dict[str, list[str]] = {}
    for n in nodes:
        for name in sorted(placeholders(n.model_dump(include=SECRET_FIELDS))):
            refs.setdefault(name, []).append(n.label)
    return dict(sorted(refs.items()))


def with_node_secrets(nodes: list[NodeSpec], secrets_file: str | None) -> list[NodeSpec]:
    """`nodes` with ${LAB_*} filled into their config, files and credentials, for what goes to CML only.
    Raises InvalidRequest naming every missing variable. The specs were validated with their references;
    the filled ones are not validated again, since a validation error would quote the value."""
    parts = [n.model_dump(include=SECRET_FIELDS) for n in nodes]
    filled = resolve_secrets(parts, secrets_file, what="This lab")
    return [
        n.model_copy(
            update={
                "config": f["config"],
                "files": f["files"],
                "credentials": n.credentials.model_copy(update=f["credentials"]) if n.credentials else None,
            }
        )
        for n, f in zip(nodes, filled, strict=True)
    ]


async def assign_cat9kv_serials(
    app: CmlApp, title: str, nodes: list[NodeSpec]
) -> tuple[list[NodeSpec], dict[str, str]]:
    """Give every cat9000v without its own conf/vswitch.xml a copy of the definition's default with a unique
    serial (stable per lab title + label), so Catalyst Center doesn't merge them.
    Returns (nodes, {label: serial})."""
    serials: dict[str, str] = {}
    defaults: dict[str, str | None] = {}
    out: list[NodeSpec] = []
    for n in nodes:
        if not is_cat9kv(n.definition):
            out.append(n)
            continue
        given = n.files.get(VSWITCH_FILE)
        if given is not None:
            if s := serial_of(given):
                serials[n.label] = s
            out.append(n)
            continue
        if n.definition not in defaults:
            defaults[n.definition] = await default_file(app, n.definition, VSWITCH_FILE)
        base = defaults[n.definition]
        if not base or serial_of(base) is None:
            out.append(n)  # unknown layout: leave CML's default alone
            continue
        serial = unique_serial(title, n.label)
        serials[n.label] = serial
        out.append(n.model_copy(update={"files": {**n.files, VSWITCH_FILE: with_serial(base, serial)}}))
    return out, serials


async def default_file(app: CmlApp, definition: str, name: str) -> str | None:
    """A definition's default day-0 file (GET /node_definitions/{id} returns YAML)."""
    import yaml

    try:
        raw = await app.api.get(f"/node_definitions/{definition}")
    except UpstreamError:
        return None
    nd = yaml.safe_load(raw) if isinstance(raw, str) else raw
    files = (((nd or {}).get("configuration") or {}).get("provisioning") or {}).get("files") or []
    for f in files:
        if isinstance(f, dict) and f.get("name") == name:
            return str(f.get("content") or "")
    return None


async def build_lab_flow(
    ctx: Context,
    *,
    tool: str,
    tool_args: dict[str, Any],
    title: str,
    nodes: list[NodeSpec],
    links: list[str],
    description: str | None,
    start: bool,
    wait: bool,
    timeout: float | None,  # noqa: ASYNC109 - overall wait, handled by poll_until
    confirm: str | None,
    annotations: list[dict[str, Any]] | None = None,
    redact: dict[str, str] | None = None,
    lab_notes: str | None = None,
    lab_secrets: dict[str, list[str]] | None = None,
    blockers: list[str] | None = None,
    node_staging: NodeStaging | None = None,
) -> dict[str, Any]:
    """Preview/apply a lab build (shared by cml_build_lab and cml_build_recipe). `lab_notes` become the
    lab's notes (cml_build_recipe records the recipe and its substitutions there). `lab_secrets` ({LAB_* name:
    node labels}) were filled into `nodes`; `blockers` are the caller's own (e.g. a missing lab secret).
    `redact` (lab secret value -> ${LAB_*}) cleans the preview's blockers and notes too. `node_staging` and
    the nodes' priorities set the boot order (the preview's boot_order)."""
    app: CmlApp = get_client(ctx)
    defs = await known_definitions(app)
    nodes, serials = await assign_cat9kv_serials(app, title, nodes)
    connectors = None
    if any(n.definition == "external_connector" for n in nodes):
        connectors = await app.api.get("/system/external_connectors")
    blockers = list(blockers or [])
    notes: list[str] = []
    wiring: list[str] = []
    topology: dict[str, Any] = {}
    try:
        topology, wiring = build_topology(
            title,
            nodes,
            links,
            defs,
            description,
            connectors=connectors,
            notes=notes,
            annotations=annotations,
            node_staging=node_staging,
        )
    except BuildError as e:
        blockers.append(str(e))
    if lab_notes and topology:
        topology["lab"]["notes"] = lab_notes
    if await title_taken(app, title):
        blockers.append(f"A lab titled {title!r} already exists")
    needed = sum(1 for n in nodes if n.definition not in UNLICENSED_DEFINITIONS)
    licences: dict[str, Any] | None = None
    memory: dict[str, Any] | None = None
    if start:
        licences = await licence_usage(app)
        if problem := licence_blocker(licences, needed):
            blockers.append(problem)
        else:
            licences = compact_usage(licences)
        specs = [{"node_definition": n.definition, "ram": n.ram} for n in nodes]
        memory = ram_check(await ram_headroom(app), nodes_ram_mb(specs, defs))
    plan = Plan(
        f"Build lab {title!r}: {len(nodes)} nodes, {len(links)} links" + (", then start it" if start else ""),
        details={
            "nodes": {n.label: n.definition for n in nodes},
            "links": wiring,
            "start": start,
            "licensed_nodes": needed,
            **({"licences": licences} if licences else {}),
            **({"ram": memory} if memory else {}),
            **({"notes": redact_values(notes, redact or {})} if notes else {}),
            **({"annotations": len(annotations)} if annotations else {}),
            **({"cat9000v_serials": serials} if serials else {}),
            **boot_details(nodes, node_staging),
            **({"lab_secrets": lab_secrets} if lab_secrets else {}),
        },
        # a node's config can reach a blocker or note (e.g. an external connector's name)
        blockers=redact_values(blockers, redact or {}),
        blast_radius=len(nodes),
        side_effects=[
            *([memory["warning"]] if memory and memory.get("warning") else []),
            *(
                [
                    "The server fills the lab_secrets into those nodes from its LAB_* variables or "
                    "CML_LAB_SECRETS_FILE; the values are never shown"
                ]
                if lab_secrets
                else []
            ),
        ],
    )
    limit = timeout or get_settings(ctx).wait_timeout

    async def apply() -> Any:
        """`redact` (lab secret value -> ${LAB_*}): upstream errors and warnings about the imported topology
        may echo configs; they are cleaned before they reach the audit log or the caller."""
        if not redact:
            return await apply_build()
        try:
            return redact_values(await apply_build(), redact)
        except UpstreamError as e:
            raise UpstreamError(redact_values(str(e), redact), e.status_code) from None
        except InvalidRequest as e:
            raise InvalidRequest(redact_values(str(e), redact)) from None

    async def apply_build() -> Any:
        res = await app.api.post(
            "/import",
            None,
            params={"title": title},
            content=to_yaml(topology),
            headers={"Content-Type": "application/x-yaml"},
        )
        out: dict[str, Any] = {"id": res.get("id"), "title": title, "links": wiring}
        if res.get("warnings"):
            out["warnings"] = res["warnings"]
        if start:
            try:
                await app.api.put(f"/labs/{res['id']}/start")
            except UpstreamError as e:
                raise await explain_licence_error(
                    app, e, f"Lab {title!r} was created ({res['id']}) but not started"
                ) from e
            if wait:
                out["convergence"] = await wait_converged(app, str(res["id"]), timeout=limit, ctx=ctx)
            else:
                out["started"] = True
                out["next"] = "cml_wait_for_converged"
        return out

    return await preview_or_apply(ctx, tool=tool, args=tool_args, confirm=confirm, plan=plan, apply=apply)


def boot_details(nodes: list[NodeSpec], node_staging: NodeStaging | None) -> dict[str, Any]:
    """The preview's node_staging and boot_order, when the build sets either (else nothing)."""
    if node_staging is None and all(n.priority is None for n in nodes):
        return {}
    out: dict[str, Any] = {
        "node_staging": node_staging.model_dump() if node_staging else {"enabled": False},
        "boot_order": boot_order([{"label": n.label, "priority": n.priority} for n in nodes]),
    }
    if node_staging is None or not node_staging.enabled:
        out["boot_order_note"] = (
            "node staging is off, so CML starts every node at once and ignores the priorities: pass "
            "node_staging={'enabled': true} (or cml_set_lab_boot later)"
        )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Build lab from spec", task=True)
    async def cml_build_lab(
        ctx: Context,
        title: Annotated[str, Field(min_length=1, max_length=64, description="Title of the new lab")],
        nodes: Annotated[
            list[NodeSpec],
            Field(
                min_length=1,
                description="Nodes: [{label, definition, config?, files?, credentials?, image?, tags?, "
                "ram?, cpus?, parameters?, x?, y?, priority?}]",
            ),
        ],
        links: Annotated[
            list[str],
            Field(
                description="Links as 'r1 r2' (first free interfaces) or 'r1:Ethernet0/1 r2:Ethernet0/1' "
                "(exact interfaces)"
            ),
        ] = [],  # noqa: B006 - FastMCP copies defaults per call
        description: Annotated[str | None, Field(description="Lab description")] = None,
        start: Annotated[bool, Field(description="Start the lab after creating it")] = False,
        wait: Wait = True,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        node_staging: Annotated[
            NodeStaging | None,
            Field(
                description="Boot in node priority order (higher first; preview: boot_order): {enabled, "
                "start_remaining, abort_on_failure} (CML node staging). Default: off, all nodes at once"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build a complete lab from a compact spec: node labels + definitions (+ optional day-0
        config, extra config files, login credentials, image, tags, resources) and links between
        them. Interfaces are allocated automatically from each definition's interface names unless
        given ('donotuse' slots are skipped), nodes are laid out in a grid, and the result is imported
        as one lab; optionally started (and waited on, unless wait=false). The preview shows the exact
        wiring ('r1:Ethernet0/0<->r2:Ethernet0/0') and node-licence use.
        External network: add {"label": "ext", "definition": "external_connector", "config":
        "System Bridge"} (names from cml_list_external_connectors) and link a node to it.
        `config` fills the definition's main file: IOS-XE/NX-OS CLI, the FTDv day0-config JSON
        (EULA, Hostname, AdminPassword, IPv4Mode/Addr/Mask/Gw, FmcIp, FmcRegKey, ManageLocally),
        Alpine node.cfg shell lines. If the day-0 config changes the login, pass `credentials` so
        cml_run_commands can log in. Slow images (FTDv 15-30 min, cat9000v ~10 min): use wait=false
        and then cml_wait_for_converged. Example nodes: [{"label": "r1", "definition": "iol-xe"},
        {"label": "sw1", "definition": "ioll2-xe"}], links: ["r1 sw1"].
        Secrets: write ${LAB_*} references in config, files or credentials (e.g. 'secret
        ${LAB_CLI_PASSWORD}'), never values; the server fills them in only in what it sends to CML. The
        preview's lab_secrets lists them per node; a missing one blocks."""
        tool_args = {
            "title": title,
            "nodes": [n.model_dump() for n in nodes],
            "links": links,
            "description": description,
            "start": start,
            "wait": wait,
            "timeout": timeout,
            "node_staging": node_staging.model_dump() if node_staging else None,
        }
        # ${LAB_*} secrets are filled only in what goes to CML: the call, preview, confirm token, result and
        # audit log keep the references (`nodes` arrive validated with them, so no error can quote a value)
        secrets_file = get_settings(ctx).lab_secrets_file
        refs = node_secret_refs(nodes)
        blockers: list[str] = []
        if refs:
            try:
                nodes = with_node_secrets(nodes, secrets_file)
            except InvalidRequest as e:  # names the missing variables, never a value
                blockers.append(str(e))
        return await build_lab_flow(
            ctx,
            tool="cml_build_lab",
            tool_args=tool_args,
            title=title,
            nodes=nodes,
            links=links,
            description=description,
            start=start,
            wait=wait,
            timeout=timeout,
            confirm=confirm,
            redact=secret_names_by_value(secrets_file) if refs else None,
            lab_secrets=refs,
            blockers=blockers,
            node_staging=node_staging,
        )
