"""Lab write tools: create, import, start, stop, extract configs. All preview-first."""

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
    poll_until,
)

from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.licence import explain_licence_error, licence_blocker, licence_usage, licensed
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import LabRef, parse_topology_yaml, state_counts
from cml_mcp.tools.smart import Timeout

Wait = Annotated[bool, Field(description="Wait until the operation has finished (default true)")]


async def known_definitions(app: CmlApp) -> dict[str, dict[str, Any]]:
    defs: list[dict[str, Any]] = await app.api.get("/simplified_node_definitions")
    return {str(d["id"]): d for d in defs}


async def title_taken(app: CmlApp, title: str) -> list[str]:
    return [lab["id"] for lab in await app.list_labs() if lab.get("lab_title") == title]


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
        stopped; start it with cml_start_lab."""
        app: CmlApp = get_client(ctx)
        topo = parse_topology_yaml(topology_yaml)
        final_title = str(title or (topo.get("lab") or {}).get("title") or "Imported lab")[:64]
        defs = await known_definitions(app)
        used: dict[str, int] = {}
        for n in topo.get("nodes") or []:
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
        plan = Plan(
            f"Import lab {final_title!r} ({len(topo.get('nodes') or [])} nodes, "
            f"{len(topo.get('links') or [])} links)",
            details={"title": final_title, "node_definitions": used},
            blockers=blockers,
        )

        async def apply() -> Any:
            res = await app.api.post(
                "/import",
                None,
                params={"title": final_title},
                content=topology_yaml,
                headers={"Content-Type": "application/x-yaml"},
            )
            return {"id": res.get("id"), "title": final_title, "warnings": res.get("warnings") or []}

        return await preview_or_apply(
            ctx,
            tool="cml_import_lab",
            args={"topology_yaml": topology_yaml, "title": title},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Start lab", idempotent=True)
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
        ram = sum(
            int(
                n.get("ram") or (defs.get(str(n.get("node_definition"))) or {}).get("sim", {}).get("ram") or 0
            )
            for n in stopped
        )
        blockers = [] if nodes else ["The lab has no nodes"]
        needed = sum(1 for n in stopped if licensed(n))
        usage = await licence_usage(app) if needed else None
        if usage and (problem := licence_blocker(usage, needed, exclude=lid)):
            blockers.append(problem)
        plan = Plan(
            f"Start lab {info.get('lab_title')!r}: {len(stopped)} of {len(nodes)} nodes to start",
            details={
                "node_states": state_counts(nodes),
                "ram_needed_mb": ram,
                "licensed_nodes_to_start": needed,
                **({"licences": usage} if usage else {}),
                "wait": wait,
            },
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
