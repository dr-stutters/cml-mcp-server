"""Waiting for labs and nodes to converge (all nodes BOOTED), shared by several tools."""

from __future__ import annotations

import time
from typing import Any

from fastmcp import Context
from stutters_mcp_core import InvalidRequest, poll_until

from cml_mcp.client import CmlApp
from cml_mcp.tools.common import state_counts

RUNNING = ("STARTED", "QUEUED", "BOOTED")

# Definitions that report BOOTED before their data plane forwards (verified live on CML 2.10:
# cat9000v-uadp's routed uplink forwards 2-3 minutes after BOOTED).
SLOW_FORWARDING = ("cat9000v",)


async def wait_converged(
    app: CmlApp,
    lab_id: str,
    *,
    node_id: str | None = None,
    timeout: float,  # noqa: ASYNC109 - overall wait, passed to poll_until
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Poll check_if_converged until true. Raises InvalidRequest if the lab/node isn't started and
    UpstreamTimeout (from poll_until) if it takes longer than `timeout`."""
    start = time.monotonic()
    path = f"/labs/{lab_id}/nodes/{node_id}" if node_id else f"/labs/{lab_id}"

    async def fetch() -> dict[str, Any]:
        converged = await app.api.get(f"{path}/check_if_converged")
        if node_id:
            node = await app.api.get(f"/labs/{lab_id}/nodes/{node_id}", {"exclude_configurations": "true"})
            return {"converged": converged is True, "state": node.get("state"), "nodes": [node]}
        lab_state = await app.api.get(f"/labs/{lab_id}/state")
        nodes = await app.list_nodes(lab_id)
        return {"converged": converged is True, "state": lab_state, "nodes": nodes}

    first = await fetch()
    if first["state"] not in RUNNING:
        what = "Node" if node_id else "Lab"
        raise InvalidRequest(
            f"{what} is {first['state']}, not started, so it will never converge. Start it first "
            f"({'cml_set_node_state' if node_id else 'cml_start_lab'})."
        )

    def describe(r: dict[str, Any]) -> str:
        counts = state_counts(r["nodes"])
        return f"{counts.get('BOOTED', 0)}/{len(r['nodes'])} nodes booted"

    result = first
    if not first["converged"]:
        result = await poll_until(
            fetch,
            done=lambda r: bool(r["converged"]),
            describe=describe,
            timeout=timeout,
            interval=3.0,
            max_interval=10.0,
            ctx=ctx,
            what="convergence",
        )
    not_booted = [
        {"label": n.get("label"), "state": n.get("state")}
        for n in result["nodes"]
        if n.get("state") != "BOOTED"
    ]
    out: dict[str, Any] = {
        "converged": True,
        "waited_seconds": round(time.monotonic() - start, 1),
        "node_states": state_counts(result["nodes"]),
    }
    if not_booted:
        out["not_booted"] = not_booted
    if hint := slow_forwarding_hint(result["nodes"]):
        out["hint"] = hint
    return out


def slow_forwarding_hint(nodes: list[dict[str, Any]]) -> str | None:
    slow = sorted(
        str(n.get("label"))
        for n in nodes
        if n.get("state") == "BOOTED" and str(n.get("node_definition") or "").startswith(SLOW_FORWARDING)
    )
    if not slow:
        return None
    return (
        f"{', '.join(slow)}: cat9000v reports BOOTED 2-3 minutes before its interfaces forward traffic. "
        "If pings or RADIUS fail right after boot, wait a few minutes and retry (cml_check_reachability)."
    )
