"""Node-licence accounting: how many licensed nodes run where, and readable 'out of licences' errors.

CML counts every running node against the licence except external connectors and unmanaged
switches. The cap isn't reported by the API (an EVAL Personal licence says '20 nodes' but allows 5),
so CML_NODE_LICENSE_LIMIT can tell the server what it is.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from stutters_mcp_core import InvalidRequest, UpstreamError

from cml_mcp.build import UNLICENSED_DEFINITIONS
from cml_mcp.client import CmlApp

RUNNING_STATES = ("STARTED", "QUEUED", "BOOTED")


def licensed(node: dict[str, Any]) -> bool:
    return str(node.get("node_definition")) not in UNLICENSED_DEFINITIONS


async def licence_usage(app: CmlApp) -> dict[str, Any]:
    """{running_licensed_nodes, by_lab: {title: n}, limit, free} across every lab on the controller."""
    nodes: list[dict[str, Any]] = await app.api.get("/nodes", {"operational": "false"})
    titles = {lab["id"]: lab.get("lab_title") for lab in await app.list_labs()}
    running = [n for n in nodes if n.get("state") in RUNNING_STATES and licensed(n)]
    by_lab = Counter(str(titles.get(n.get("lab_id"), n.get("lab_id"))) for n in running)
    limit = app.settings.node_license_limit
    out: dict[str, Any] = {"running_licensed_nodes": len(running), "by_lab": dict(by_lab)}
    if limit:
        out["limit"] = limit
        out["free"] = max(0, limit - len(running))
    return out


def licence_blocker(usage: dict[str, Any], needed: int) -> str | None:
    """A preview blocker when starting `needed` more licensed nodes would exceed the known limit."""
    limit = usage.get("limit")
    if not limit or needed <= 0 or usage["running_licensed_nodes"] + needed <= limit:
        return None
    running = ", ".join(f"{t!r} ({n})" for t, n in usage["by_lab"].items()) or "none"
    return (
        f"Starting needs {needed} node licence(s) but only {usage.get('free', 0)} of {limit} are free "
        f"(running: {running}). Stop another lab first (cml_stop_lab); external connectors and "
        "unmanaged switches don't count."
    )


async def explain_licence_error(app: CmlApp, err: UpstreamError, what: str) -> Exception:
    """Turn CML's '5 of 5 node licenses are in use' into an actionable error; other errors pass."""
    if "licen" not in str(err).lower():
        return err
    try:
        usage = await licence_usage(app)
        running = ", ".join(f"{t!r} ({n})" for t, n in usage["by_lab"].items()) or "none"
    except UpstreamError:
        running = "unknown"
    return InvalidRequest(
        f"{what}: CML refused for lack of node licences ({err}). Labs with running licensed nodes: "
        f"{running}. Stop one (cml_stop_lab) and retry; external connectors and unmanaged switches "
        "don't count."
    )
