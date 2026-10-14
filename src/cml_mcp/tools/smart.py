"""Task-oriented read tools: wait for convergence, diff two labs."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import InvalidRequest, ToolRegistrar, get_client, get_settings

from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.diff import diff_topologies
from cml_mcp.tools.common import LabRef, parse_topology_yaml, shaped

Timeout = Annotated[
    float | None,
    Field(ge=5, le=3600, description="Seconds to wait before giving up (default CML_WAIT_TIMEOUT, 600)"),
]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Wait for convergence")
    async def cml_wait_for_converged(
        ctx: Context,
        lab: LabRef,
        node: Annotated[str | None, Field(description="Wait for just this node (label or id)")] = None,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
    ) -> ToolResult:
        """Wait until a started lab (or one node) has converged, i.e. every node finished booting
        (state BOOTED), sending progress while it waits. Returns the time waited and node states. Use
        it after cml_start_lab(wait=false) or before running commands. Fails fast if the lab isn't
        started; on timeout, the lab keeps booting - check with cml_list_nodes or the console log."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        node_id = (await app.resolve_node(info["id"], node))["id"] if node else None
        result = await wait_converged(
            app, info["id"], node_id=node_id, timeout=timeout or get_settings(ctx).wait_timeout, ctx=ctx
        )
        return shaped({"lab": info.get("lab_title"), **({"node": node} if node else {}), **result})

    @reg.read(title="Diff labs")
    async def cml_diff_lab(
        ctx: Context,
        lab: LabRef,
        other_lab: Annotated[str | None, Field(description="Compare against this lab (title or id)")] = None,
        baseline_yaml: Annotated[
            str | None,
            Field(description="Or compare against this topology YAML (e.g. an earlier cml_export_lab)"),
        ] = None,
        include_configs: Annotated[
            bool, Field(description="Also diff the nodes' day-0 configurations")
        ] = True,
    ) -> ToolResult:
        """Compare a lab with another lab or with a saved topology YAML (e.g. an earlier
        cml_export_lab): nodes only in one side, per-node changes (definition, image, RAM/CPU, tags,
        interfaces, unified config diff) and links only in one side, matched by node label and
        interface name. Use it to check drift from a baseline or what a rebuild changed."""
        if (other_lab is None) == (baseline_yaml is None):
            raise InvalidRequest("Give exactly one of other_lab or baseline_yaml to compare against.")
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        a = parse_topology_yaml(await app.api.get(f"/labs/{info['id']}/download", expect="text"))
        if other_lab is not None:
            other = await app.resolve_lab(other_lab)
            b = parse_topology_yaml(await app.api.get(f"/labs/{other['id']}/download", expect="text"))
            b_name = str(other.get("lab_title"))
        else:
            b = parse_topology_yaml(baseline_yaml or "")
            b_name = "baseline"
        return shaped(
            diff_topologies(
                a, b, include_configs=include_configs, a_name=str(info.get("lab_title")), b_name=b_name
            )
        )
