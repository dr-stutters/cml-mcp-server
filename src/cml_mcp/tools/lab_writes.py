"""Lab write tools: create, import, start, stop, extract configs. All preview-first."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
import contextlib
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
    poll_until,
)
from cml_mcp.build import to_yaml
from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.licence import (
    compact_usage,
    explain_licence_error,
    licence_blocker,
    licence_usage,
    licensed,
    nodes_ram_mb,
    ram_check,
    ram_headroom,
)
from cml_mcp.recipes import placeholders, redact_values, resolve_secrets, secret_names_by_value
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import LabRef, parse_topology_yaml, state_counts
from cml_mcp.tools.smart import Timeout

Wait = Annotated[bool, Field(description="Wait until the operation has finished")]


async def known_definitions(app: CmlApp) -> dict[str, dict[str, Any]]:
    defs: list[dict[str, Any]] = await app.api.get("/simplified_node_definitions")
    return {str(d["id"]): d for d in defs}


async def title_taken(app: CmlApp, title: str) -> list[str]:
    return [lab["id"] for lab in await app.list_labs() if lab.get("lab_title") == title]


LAB_RUNNING = ("STARTED", "QUEUED", "BOOTED")


def lab_fingerprint(lab: dict[str, Any]) -> Any:
    return {"state": lab.get("state"), "modified": lab.get("modified"), "nodes": lab.get("node_count")}


async def wait_for_lab_state(
    app: CmlApp,
    lab_id: str,
    states: tuple[str, ...],
    timeout: float,  # noqa: ASYNC109 - overall wait, handled by poll_until
    ctx: Context,
) -> str:
    result: str = await poll_until(
        lambda: app.api.get(f"/labs/{lab_id}/state"),
        done=lambda s: s in states,
        describe=lambda s: f"lab state {s}",
        timeout=timeout,
        interval=2.0,
        max_interval=5.0,
        ctx=ctx,
        what=f"lab to reach {'/'.join(states)}",
    )
    return result


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create lab")
    async def cml_create_lab(
        ctx: Context,
        title: Annotated[
            str, Field(min_length=1, max_length=64, description="Lab title (unique, by convention)")
        ],
        description: Annotated[str | None, Field(description="Free-form description")] = None,
        notes: Annotated[str | None, Field(description="Lab notes (Markdown)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an empty lab, then add nodes with cml_add_node and wire them with cml_connect_nodes.
        For a whole topology in one step use cml_build_lab (compact spec) or cml_import_lab (YAML).
        Preview-first; refuses a title another lab already uses."""
        app: CmlApp = get_client(ctx)
        dupes = await title_taken(app, title)
        body = {k: v for k, v in {"title": title, "description": description, "notes": notes}.items() if v}
        plan = Plan(
            f"Create empty lab {title!r}",
            details=body,
            blockers=[f"A lab titled {title!r} already exists ({', '.join(dupes)})"] if dupes else [],
        )

        async def apply() -> Any:
            lab = await app.api.post("/labs", body)
            return {"id": lab.get("id"), "title": lab.get("lab_title"), "state": lab.get("state")}

        return await preview_or_apply(
            ctx,
            tool="cml_create_lab",
            args={"title": title, "description": description, "notes": notes},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Import lab from YAML")
    async def cml_import_lab(
        ctx: Context,
        topology_yaml: Annotated[
            str, Field(description="CML topology YAML (as produced by cml_export_lab or the CML UI)")
        ],
        title: Annotated[str | None, Field(description="Title for the new lab (overrides lab.title)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a new lab from CML topology YAML (nodes, interfaces, links, configs, annotations),
        e.g. a copy of an exported lab or a file from a lab repository. The preview checks the YAML,
        lists node definitions used and flags any this controller doesn't have. The lab is created
        stopped; start it with cml_start_lab.
        Lab secrets: write ${LAB_*} references (e.g. "AdminPassword": "${LAB_FTD_ADMIN_PASSWORD}"), never
        the values. The server fills them into the nodes (day-0 configs, logins) from its LAB_* variables
        or CML_LAB_SECRETS_FILE only in what it sends to CML; the preview lists which secret goes to which
        node, and names any the server doesn't have."""
        app: CmlApp = get_client(ctx)
        topo = parse_topology_yaml(topology_yaml)
        final_title = str(title or (topo.get("lab") or {}).get("title") or "Imported lab")[:64]
        defs = await known_definitions(app)
        nodes = topo.get("nodes") or []
        used: dict[str, int] = {}
        for n in nodes:
            d = str(n.get("node_definition"))
            used[d] = used.get(d, 0) + 1
        blockers = [
            f"Unknown node definition {d!r} (see cml_list_node_definitions)" for d in used if d not in defs
        ]
        dupes = await title_taken(app, final_title)
        if dupes:
            blockers.append(
                f"A lab titled {final_title!r} already exists ({', '.join(dupes)}); pass another title"
            )
        # ${LAB_*} secrets are filled only in the nodes and only in what goes to CML: the preview, the
        # confirm token and the audit log keep the placeholders, and lab notes and annotations keep them
        # as written (where a credential is kept, as in recipe annotations)
        secrets_file = get_settings(ctx).lab_secrets_file
        filled: dict[str, list[str]] = {}
        for n in nodes:
            for name in sorted(placeholders(n)):
                filled.setdefault(name, []).append(str(n.get("label") or n.get("id")))
        if filled:
            try:
                resolve_secrets(nodes, secrets_file, what="This topology")
            except InvalidRequest as e:  # names the missing variables, never a value
                blockers.append(str(e))
        plan = Plan(
            f"Import lab {final_title!r} ({len(nodes)} nodes, {len(topo.get('links') or [])} links)",
            details={
                "title": final_title,
                "node_definitions": used,
                **({"lab_secrets": dict(sorted(filled.items()))} if filled else {}),
            },
            side_effects=[
                "The server fills the lab_secrets into those nodes from its LAB_* variables or "
                "CML_LAB_SECRETS_FILE; the values are never shown"
            ]
            if filled
            else [],
            blockers=blockers,
        )

        async def post(body: str) -> dict[str, Any]:
            res = await app.api.post(
                "/import",
                None,
                params={"title": final_title},
                content=body,
                headers={"Content-Type": "application/x-yaml"},
            )
            return {"id": res.get("id"), "title": final_title, "warnings": res.get("warnings") or []}

        async def apply() -> Any:
            """Without placeholders the YAML goes to CML as given. With them, the parsed topology is filled
            and re-serialised (a value is YAML-quoted wherever it lands); CML's warnings and errors may
            echo configs, so they are cleaned before they reach the audit log or the caller."""
            if not filled:
                return await post(topology_yaml)
            body = to_yaml({**topo, "nodes": resolve_secrets(nodes, secrets_file, what="This topology")})
            redact = secret_names_by_value(secrets_file)
            try:
                return redact_values(await post(body), redact)
            except UpstreamError as e:
                raise UpstreamError(redact_values(str(e), redact), e.status_code) from None
            except InvalidRequest as e:
                raise InvalidRequest(redact_values(str(e), redact)) from None

        return await preview_or_apply(
            ctx,
            tool="cml_import_lab",
            args={"topology_yaml": topology_yaml, "title": title},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Start lab", idempotent=True, task=True)
    async def cml_start_lab(
        ctx: Context,
        lab: LabRef,
        wait: Wait = True,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Start every node in a lab (boot order follows node priority), then by default wait until
        all nodes have booted (converged) and report how long it took. With wait=false it returns at
        once; follow up with cml_wait_for_converged. The preview shows how many nodes will start and
        the RAM they need."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        nodes = await app.list_nodes(lid)
        defs = await known_definitions(app)
        stopped = [n for n in nodes if n.get("state") not in ("BOOTED", "STARTED", "QUEUED")]
        ram = nodes_ram_mb(stopped, defs)
        blockers = [] if nodes else ["The lab has no nodes"]
        needed = sum(1 for n in stopped if licensed(n))
        usage = await licence_usage(app) if needed else None
        problem = licence_blocker(usage, needed, exclude=lid) if usage else None
        if problem:
            blockers.append(problem)
        memory = ram_check(await ram_headroom(app), ram) if ram else None
        plan = Plan(
            f"Start lab {info.get('lab_title')!r}: {len(stopped)} of {len(nodes)} nodes to start",
            details={
                "node_states": state_counts(nodes),
                "ram_needed_mb": ram,
                **({"ram": memory} if memory else {}),
                "licensed_nodes_to_start": needed,
                **({"licences": usage if problem else compact_usage(usage)} if usage else {}),
                "wait": wait,
            },
            side_effects=[memory["warning"]] if memory and memory.get("warning") else [],
            fingerprint=lab_fingerprint(info),
            blockers=blockers,
        )
        limit = timeout or get_settings(ctx).wait_timeout

        async def apply() -> Any:
            try:
                await app.api.put(f"/labs/{lid}/start")
            except UpstreamError as e:
                raise await explain_licence_error(app, e, f"Could not start {info.get('lab_title')!r}") from e
            if not wait:
                return {"started": True, "next": "cml_wait_for_converged"}
            return await wait_converged(app, lid, timeout=limit, ctx=ctx)

        return await preview_or_apply(
            ctx,
            tool="cml_start_lab",
            args={"lab": lab, "wait": wait, "timeout": timeout},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Stop lab", idempotent=True)
    async def cml_stop_lab(
        ctx: Context,
        lab: LabRef,
        wait: Wait = True,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stop every node in a lab (like powering them off; disks are kept, so a restart keeps
        saved state). Unsaved running configuration is lost: run cml_extract_node_configs first to keep
        it. Waits until the lab is STOPPED unless wait=false."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        nodes = await app.list_nodes(lid)
        running = [n.get("label") for n in nodes if n.get("state") in ("BOOTED", "STARTED", "QUEUED")]
        plan = Plan(
            f"Stop lab {info.get('lab_title')!r} ({len(running)} running nodes)",
            details={"running_nodes": running, "wait": wait},
            fingerprint=lab_fingerprint(info),
            side_effects=[
                "Running state is lost; configs not saved with cml_extract_node_configs are lost "
                "when the lab is later wiped"
            ],
        )
        limit = timeout or get_settings(ctx).wait_timeout

        async def apply() -> Any:
            await app.api.put(f"/labs/{lid}/stop")
            if not wait:
                return {"stopping": True}
            state = await wait_for_lab_state(app, lid, ("STOPPED", "DEFINED_ON_CORE"), limit, ctx)
            return {"state": state}

        return await preview_or_apply(
            ctx,
            tool="cml_stop_lab",
            args={"lab": lab, "wait": wait, "timeout": timeout},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Stop several labs", idempotent=True)
    async def cml_stop_labs(
        ctx: Context,
        labs: Annotated[
            list[str] | None,
            Field(max_length=50, description="Labs to stop (titles or ids); or use all_running=true"),
        ] = None,
        all_running: Annotated[
            bool, Field(description="Stop every running lab this account can see (except `keep`)")
        ] = False,
        keep: Annotated[
            list[str] | None, Field(max_length=50, description="With all_running: labs to leave running")
        ] = None,
        wait: Wait = True,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stop several labs with one preview and one confirm ('stop everything I'm not using'). The
        preview lists each lab with its running nodes, owner, and the licences and RAM stopping it
        frees; labs that are already stopped are skipped and protected labs (CML_PROTECTED_LABS)
        refused. Running state is lost, as with cml_stop_lab; other people's labs are listed with
        their owner, so check with the user before including them. cml_get_resource_usage shows which
        labs hold the most RAM."""
        from cml_mcp.safety import _patterns, lab_matches

        if bool(labs) == all_running:
            raise InvalidRequest("Give either `labs` or all_running=true.")
        if keep and not all_running:
            raise InvalidRequest("`keep` only applies with all_running=true.")
        app: CmlApp = get_client(ctx)
        visible = await app.list_labs()
        if all_running:
            kept = {(await app.resolve_lab(k, exact=True))["id"] for k in keep or []}
            targets = [lab for lab in visible if lab.get("state") in LAB_RUNNING and lab["id"] not in kept]
        else:
            targets = []
            for ref in dict.fromkeys(labs or []):
                lab = await app.resolve_lab(ref, exact=True)
                if lab["id"] not in {t["id"] for t in targets}:
                    targets.append(lab)
        protected = _patterns(getattr(get_settings(ctx), "protected_labs", None))
        users: dict[str, Any] = {}
        with contextlib.suppress(UpstreamError):  # owner names are a convenience
            users = {str(u.get("id")): u.get("username") for u in await app.api.get("/users")}
        defs = await known_definitions(app)
        rows: list[dict[str, Any]] = []
        refused: list[str] = []
        skipped: list[str] = []
        for lab in targets:
            title = str(lab.get("lab_title"))
            if lab.get("state") not in LAB_RUNNING:
                skipped.append(title)
                continue
            if p := lab_matches(lab, protected):
                refused.append(f"{title} (CML_PROTECTED_LABS {p!r})")
                continue
            nodes = await app.list_nodes(str(lab["id"]))
            running = [n for n in nodes if n.get("state") in ("BOOTED", "STARTED", "QUEUED")]
            rows.append(
                {
                    "id": lab["id"],
                    "lab": title,
                    "owner": users.get(str(lab.get("owner")), lab.get("owner")),
                    "running_nodes": len(running),
                    "licences_freed": sum(1 for n in running if licensed(n)),
                    "ram_freed_mb": nodes_ram_mb(running, defs),
                }
            )
        plan = Plan(
            f"Stop {len(rows)} lab(s): " + ", ".join(r["lab"] for r in rows),
            details={
                "labs": [{k: v for k, v in r.items() if k != "id"} for r in rows],
                "licences_freed": sum(r["licences_freed"] for r in rows),
                "ram_freed_mb": sum(r["ram_freed_mb"] for r in rows),
                **({"already_stopped": skipped} if skipped else {}),
                **({"refused_protected": refused} if refused else {}),
                "wait": wait,
            },
            fingerprint=sorted((lab["id"], lab.get("state"), lab.get("modified")) for lab in targets),
            blockers=[] if rows else ["Nothing to stop: no running lab matched"],
            blast_radius=sum(r["running_nodes"] for r in rows),
            side_effects=[
                "Running state is lost; configs not saved with cml_extract_node_configs are lost "
                "when a lab is later wiped"
            ],
        )
        limit = timeout or get_settings(ctx).wait_timeout

        async def apply() -> Any:
            """Stop each lab; one refusal (deleted meanwhile, no permission) doesn't stop the rest."""
            stopped: list[dict[str, Any]] = []
            failed: list[dict[str, Any]] = []
            for r in rows:
                try:
                    await app.api.put(f"/labs/{r['id']}/stop")
                    stopped.append(r)
                except UpstreamError as e:
                    failed.append({"lab": r["lab"], "id": r["id"], "error": str(e)})
            out: dict[str, Any] = {}
            if wait and stopped:
                states = await asyncio.gather(
                    *(
                        wait_for_lab_state(app, str(r["id"]), ("STOPPED", "DEFINED_ON_CORE"), limit, ctx)
                        for r in stopped
                    ),
                    return_exceptions=True,
                )
                out["stopped"] = [
                    {
                        "lab": r["lab"],
                        "id": r["id"],
                        "state": st if isinstance(st, str) else f"not confirmed: {st}",
                    }
                    for r, st in zip(stopped, states, strict=True)
                ]
            else:
                out["stopping"] = [{"lab": r["lab"], "id": r["id"]} for r in stopped]
            if failed:
                out["failed"] = failed
            return out

        return await preview_or_apply(
            ctx,
            tool="cml_stop_labs",
            args={"labs": labs, "all_running": all_running, "keep": keep, "wait": wait, "timeout": timeout},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Save running configs")
    async def cml_extract_node_configs(
        ctx: Context,
        lab: LabRef,
        node: Annotated[
            str | None, Field(description="Only this node (label or id); default all booted")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Save the running configuration of booted nodes into their stored day-0 configuration (what
        the CML UI calls 'extract configuration'), so it survives a wipe and shows up in
        cml_export_lab. Overwrites the stored configs of those nodes."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        if node:
            targets = [await app.resolve_node(lid, node, exact=True)]
        else:
            targets = await app.list_nodes(lid)
        booted = [n for n in targets if n.get("state") == "BOOTED"]
        skipped = [n.get("label") for n in targets if n.get("state") != "BOOTED"]
        plan = Plan(
            f"Save running config of {len(booted)} node(s) in {info.get('lab_title')!r}",
            details={"nodes": [n.get("label") for n in booted], "skipped_not_booted": skipped},
            fingerprint=[(n["id"], n.get("state")) for n in targets],
            blockers=[] if booted else ["No booted nodes to extract configuration from"],
        )

        async def apply() -> Any:
            saved, failed = [], {}
            for n in booted:
                try:
                    await app.api.put(f"/labs/{lid}/nodes/{n['id']}/extract_configuration", timeout=120)
                    saved.append(n.get("label"))
                except Exception as e:  # report per node, keep going
                    failed[str(n.get("label"))] = str(e)[:200]
            return {"saved": saved, **({"failed": failed} if failed else {})}

        return await preview_or_apply(
            ctx,
            tool="cml_extract_node_configs",
            args={"lab": lab, "node": node},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
