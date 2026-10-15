"""cml_build_lab: a whole lab from a compact spec in one preview-first call."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    get_settings,
    preview_or_apply,
)

from cml_mcp.build import UNLICENSED_DEFINITIONS, BuildError, NodeSpec, build_topology, to_yaml
from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.licence import explain_licence_error, licence_blocker, licence_usage
from cml_mcp.tools.lab_writes import Wait, known_definitions, title_taken
from cml_mcp.tools.smart import Timeout


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
) -> dict[str, Any]:
    """Preview/apply a lab build (shared by cml_build_lab and cml_build_recipe)."""
    app: CmlApp = get_client(ctx)
    defs = await known_definitions(app)
    connectors = None
    if any(n.definition == "external_connector" for n in nodes):
        connectors = await app.api.get("/system/external_connectors")
    blockers: list[str] = []
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
        )
    except BuildError as e:
        blockers.append(str(e))
    if await title_taken(app, title):
        blockers.append(f"A lab titled {title!r} already exists")
    needed = sum(1 for n in nodes if n.definition not in UNLICENSED_DEFINITIONS)
    licences: dict[str, Any] | None = None
    if start:
        licences = await licence_usage(app)
        if problem := licence_blocker(licences, needed):
            blockers.append(problem)
    plan = Plan(
        f"Build lab {title!r}: {len(nodes)} nodes, {len(links)} links" + (", then start it" if start else ""),
        details={
            "nodes": {n.label: n.definition for n in nodes},
            "links": wiring,
            "start": start,
            "licensed_nodes": needed,
            **({"licences": licences} if licences else {}),
            **({"notes": notes} if notes else {}),
            **({"annotations": len(annotations)} if annotations else {}),
        },
        blockers=blockers,
    )
    limit = timeout or get_settings(ctx).wait_timeout

    async def apply() -> Any:
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


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Build lab from spec")
    async def cml_build_lab(
        ctx: Context,
        title: Annotated[str, Field(min_length=1, max_length=64, description="Title of the new lab")],
        nodes: Annotated[
            list[NodeSpec],
            Field(
                min_length=1,
                description="Nodes: [{label, definition, config?, files?, credentials?, image?, tags?, "
                "ram?, cpus?, parameters?, x?, y?}]",
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
        {"label": "sw1", "definition": "ioll2-xe"}], links: ["r1 sw1"]."""
        return await build_lab_flow(
            ctx,
            tool="cml_build_lab",
            tool_args={
                "title": title,
                "nodes": [n.model_dump() for n in nodes],
                "links": links,
                "description": description,
                "start": start,
                "wait": wait,
                "timeout": timeout,
            },
            title=title,
            nodes=nodes,
            links=links,
            description=description,
            start=start,
            wait=wait,
            timeout=timeout,
            confirm=confirm,
        )
