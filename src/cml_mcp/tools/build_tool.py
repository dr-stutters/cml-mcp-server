"""cml_build_lab: a whole lab from a compact spec in one preview-first call."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import Confirm, Plan, ToolRegistrar, get_client, get_settings, preview_or_apply

from cml_mcp.build import BuildError, NodeSpec, build_topology, to_yaml
from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.tools.lab_writes import known_definitions, title_taken
from cml_mcp.tools.smart import Timeout


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Build lab from spec")
    async def cml_build_lab(
        ctx: Context,
        title: Annotated[str, Field(min_length=1, max_length=64, description="Title of the new lab")],
        nodes: Annotated[
            list[NodeSpec],
            Field(
                min_length=1, description="Nodes: [{label, definition, config?, image?, tags?, ram?, cpus?}]"
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
        start: Annotated[
            bool, Field(description="Start the lab after creating it and wait until booted")
        ] = False,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build a complete lab from a compact spec: node labels + definitions (+ optional day-0
        config, image, tags, resources) and links between them. Interfaces are allocated
        automatically from each definition's interface names unless given, nodes are laid out in a
        grid, and the result is imported as one lab; optionally started and waited on. The preview
        shows the exact wiring ('r1:Ethernet0/0<->r2:Ethernet0/0'). Example nodes:
        [{"label": "r1", "definition": "iol-xe"}, {"label": "sw1", "definition": "ioll2-xe"}],
        links: ["r1 sw1"]."""
        app: CmlApp = get_client(ctx)
        defs = await known_definitions(app)
        blockers: list[str] = []
        wiring: list[str] = []
        topology: dict[str, Any] = {}
        try:
            topology, wiring = build_topology(title, nodes, links, defs, description)
        except BuildError as e:
            blockers.append(str(e))
        if await title_taken(app, title):
            blockers.append(f"A lab titled {title!r} already exists")
        plan = Plan(
            f"Build lab {title!r}: {len(nodes)} nodes, {len(links)} links"
            + (", then start it" if start else ""),
            details={
                "nodes": {n.label: n.definition for n in nodes},
                "links": wiring,
                "start": start,
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
                await app.api.put(f"/labs/{res['id']}/start")
                out["convergence"] = await wait_converged(app, str(res["id"]), timeout=limit, ctx=ctx)
            return out

        return await preview_or_apply(
            ctx,
            tool="cml_build_lab",
            args={
                "title": title,
                "nodes": [n.model_dump() for n in nodes],
                "links": links,
                "description": description,
                "start": start,
                "timeout": timeout,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
