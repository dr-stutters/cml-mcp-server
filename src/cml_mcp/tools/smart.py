"""Task-oriented read tools: wait for convergence, diff two labs."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import re
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    InvalidRequest,
    ToolRegistrar,
    UpstreamError,
    get_client,
    get_settings,
    poll_until,
)

from cml_mcp.client import CmlApp
from cml_mcp.console import clean, mask_secrets
from cml_mcp.convergence import wait_converged
from cml_mcp.diff import diff_topologies
from cml_mcp.licence import licensed
from cml_mcp.tools.common import LabRef, parse_topology_yaml, shaped, strip_console_prefixes
from cml_mcp.tools.configs import device_configs

Timeout = Annotated[
    float | None,
    Field(ge=5, le=3600, description="Seconds to wait before giving up (default CML_WAIT_TIMEOUT, 600)"),
]


async def use_running_configs(app: CmlApp, lab: dict[str, Any], topology: dict[str, Any]) -> list[str]:
    """Replace each booted node's stored config in an exported topology with its running config;
    returns '<lab>/<node>' for nodes whose running config couldn't be read (they keep day-0)."""
    nodes = [n for n in await app.list_nodes(lab["id"]) if licensed(n)]
    booted = [n for n in nodes if n.get("state") == "BOOTED"]
    try:
        got = await device_configs(app, lab["id"], booted, purpose="cml_diff_lab", strict=False)
    except UpstreamError:
        got = {}  # every node keeps its day-0 config and is listed as unavailable
    for n in topology.get("nodes") or []:
        if str(n.get("label")) in got:
            n["configuration"] = got[str(n.get("label"))]
    title = lab.get("lab_title")
    return [f"{title}/{n.get('label')}" for n in nodes if str(n.get("label")) not in got]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Wait for convergence", task=True)
    async def cml_wait_for_converged(
        ctx: Context,
        lab: LabRef,
        node: Annotated[str | None, Field(description="Wait for just this node (label or id)")] = None,
        console_pattern: Annotated[
            str | None,
            Field(
                description="With `node`: after BOOTED, also wait until the node's console log matches "
                "this regular expression (e.g. FTDv 'login:' after its second reboot, or "
                "'%SYS-5-RESTART')"
            ),
        ] = None,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
    ) -> ToolResult:
        """Wait until a started lab (or one node) has converged, i.e. every node finished booting
        (state BOOTED), sending progress while it waits. Returns the time waited and node states. Use
        it after cml_start_lab(wait=false) or before running commands. CML marks a node BOOTED when
        its boot marker appears on the console; some images (FTDv, cat9000v) need a few more minutes
        before the CLI is usable - add console_pattern to wait for a later message. Slow images: FTDv
        15-30 min, cat9000v ~10 min, cat8000v ~5 min, IOL under 1 min. Fails fast if the lab isn't
        started; on timeout, the lab keeps booting - call again, or check cml_get_node_console_log."""
        if console_pattern and not node:
            raise InvalidRequest("console_pattern needs a node to watch")
        pattern = None
        if console_pattern:
            try:
                pattern = re.compile(console_pattern, re.IGNORECASE)
            except re.error as e:
                raise InvalidRequest(f"console_pattern is not a valid regular expression: {e}") from e
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        node_id = (await app.resolve_node(lid, node))["id"] if node else None
        limit = timeout or get_settings(ctx).wait_timeout
        started = time.monotonic()

        async def tail() -> str:
            log = await app.api.get(f"/labs/{lid}/nodes/{node_id}/consoles/0/log", {"lines": 200})
            return clean(strip_console_prefixes(str(log or "")))

        # Only output that appears from now on counts, unless the node has already booted: then an
        # earlier boot's 'login:' must not end the wait for this one.
        anchor = ""
        if pattern is not None:
            converged = await app.api.get(f"/labs/{lid}/nodes/{node_id}/check_if_converged")
            if converged is not True:
                lines = [ln for ln in (await tail()).splitlines() if ln.strip()]
                anchor = "\n".join(lines[-3:])

        def fresh(text: str) -> str:
            if anchor and anchor in text:
                return text[text.rindex(anchor) + len(anchor) :]
            return text

        result = await wait_converged(app, lid, node_id=node_id, timeout=limit, ctx=ctx)
        if pattern is not None:
            text = await poll_until(
                tail,
                done=lambda t: bool(pattern.search(fresh(t))),
                describe=lambda t: f"waiting for {console_pattern!r} on the console",
                timeout=max(5.0, limit - (time.monotonic() - started)),
                interval=10.0,
                max_interval=30.0,
                ctx=ctx,
                what=f"console output matching {console_pattern!r}",
            )
            new_text = fresh(text)
            hit = pattern.search(new_text)
            line = new_text[: hit.end()].rsplit("\n", 1)[-1] if hit else ""
            result["console_match"] = mask_secrets(line.strip()[-200:])
            result["waited_seconds"] = round(time.monotonic() - started, 1)
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
        running_configs: Annotated[
            bool,
            Field(
                description="Compare the live running configs (read from each booted node's console) "
                "instead of the stored day-0 configs; a baseline_yaml side keeps its stored configs"
            ),
        ] = False,
    ) -> ToolResult:
        """Compare a lab with another lab or with a saved topology YAML (e.g. an earlier
        cml_export_lab): nodes only in one side, per-node changes (definition, image, RAM/CPU, tags,
        interfaces, unified config diff) and links only in one side, matched by node label and
        interface name. Use it to check drift from a baseline or what a rebuild changed. Config
        secrets are masked. running_configs=true diffs what the devices run now (slower: one
        console session per node)."""
        if (other_lab is None) == (baseline_yaml is None):
            raise InvalidRequest("Give exactly one of other_lab or baseline_yaml to compare against.")
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        a = parse_topology_yaml(await app.api.get(f"/labs/{info['id']}/download", expect="text"))
        missing: list[str] = []
        if running_configs:
            missing += await use_running_configs(app, info, a)
        if other_lab is not None:
            other = await app.resolve_lab(other_lab)
            b = parse_topology_yaml(await app.api.get(f"/labs/{other['id']}/download", expect="text"))
            b_name = str(other.get("lab_title"))
            if running_configs:
                missing += await use_running_configs(app, other, b)
        else:
            b = parse_topology_yaml(baseline_yaml or "")
            b_name = "baseline"
        result = diff_topologies(
            a,
            b,
            include_configs=include_configs or running_configs,
            a_name=str(info.get("lab_title")),
            b_name=b_name,
        )
        if missing:
            result["running_config_unavailable"] = sorted(set(missing))
        return shaped(result)
