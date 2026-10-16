"""Network checks through the consoles: reachability matrix, external connectors."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
import re
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import InvalidRequest, ResponseFormat, ToolRegistrar, get_client, list_result
from cml_mcp._core.http import page_of
from cml_mcp.client import CmlApp
from cml_mcp.console import read_only_problem
from cml_mcp.netops import Command, console_batch, ping_command, ping_result
from cml_mcp.tools.common import LabRef, shaped

TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Check reachability", idempotent=False, task=True)
    async def cml_check_reachability(
        ctx: Context,
        lab: LabRef,
        nodes: Annotated[
            list[str], Field(min_length=1, max_length=20, description="Source node labels or ids")
        ],
        targets: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=20,
                description="IP addresses or hostnames to ping from every node, e.g. ['198.18.128.1', "
                "'198.18.134.35']",
            ),
        ],
        count: Annotated[int, Field(ge=1, le=10, description="Echo requests per target")] = 3,
        vrf: Annotated[
            str | None,
            Field(
                description="VRF to ping in (IOS-XE 'Mgmt-vrf', NX-OS 'management'). On FTD, "
                "'management' pings from the management interface ('ping system')"
            ),
        ] = None,
        wait_seconds: Annotated[
            int,
            Field(
                ge=0,
                le=900,
                description="Repeat the matrix (10 s pause between rounds) until every target answers; "
                "a soft limit, the last round may run past it. Proves a routing protocol has converged "
                "after a boot or change (0: once)",
            ),
        ] = 0,
    ) -> ToolResult:
        """Ping a list of targets from one or more booted nodes through their consoles and return a
        matrix: per node and target, ok and success percent. Uses the right ping syntax per OS
        (IOS/IOS-XE 'repeat', NX-OS 'count', Linux '-c', FTD 'ping'/'ping system'). Use it to prove a
        lab reaches outside appliances (e.g. through an external connector) or that routing works
        end to end; 'all_ok' summarises (ok = at least one reply, since the first echo is often lost to
        ARP). Raw output is included only for failures. A BOOTED lab isn't a converged network: right
        after cml_wait_for_converged, OSPF/BGP may still be forming adjacencies - pass wait_seconds to
        retry until the matrix is all ok (the result says how long it took)."""
        bad = [t for t in targets if not TARGET.fullmatch(t)]
        if bad:
            raise InvalidRequest(f"Not an IP address or hostname: {', '.join(map(repr, bad))}")
        if vrf is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", vrf):
            raise InvalidRequest("vrf must be a plain VRF name")
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        sources = [await app.resolve_node(lid, n) for n in nodes]

        def commands(_node: dict[str, Any], cred: Any) -> list[Command]:
            cmds: list[tuple[str, float | None]] = [ping_command(cred.os, t, count, vrf) for t in targets]
            for cmd, _ in cmds:  # guard: generated commands must pass the read-tier allow-list
                if problem := read_only_problem(cmd):
                    raise InvalidRequest(f"{cmd!r}: {problem}")
            return [*cmds]

        started = time.monotonic()
        attempts = 0
        while True:
            attempts += 1
            rows = await _matrix(app, lid, sources, commands, targets, count)
            all_ok = bool(rows) and all(r.get("ok") for r in rows)
            waited = time.monotonic() - started
            if all_ok or waited + 10 > wait_seconds:
                break
            await asyncio.sleep(10)
        out: dict[str, Any] = {"lab": info.get("lab_title"), "all_ok": all_ok, "results": rows}
        if wait_seconds:
            out["attempts"] = attempts
            out["waited_seconds"] = round(waited, 1)
        return shaped(out)

    async def _matrix(
        app: CmlApp,
        lid: str,
        sources: list[dict[str, Any]],
        commands: Any,
        targets: list[str],
        count: int,
    ) -> list[dict[str, Any]]:
        batch = await console_batch(
            app, lid, sources, commands, timeout=15 + 3 * count, purpose="cml_check_reachability"
        )
        rows: list[dict[str, Any]] = []
        for res in batch:
            if res.get("error"):
                rows.append({"node": res["node"], "error": res["error"]})
            for target, out in zip(targets, res.get("outputs") or [], strict=False):
                if "error" in out:
                    rows.append({"node": res["node"], "target": target, "ok": False, "error": out["error"]})
                    continue
                verdict = ping_result(out["output"])
                row = {"node": res["node"], "target": target, **verdict}
                if not verdict.get("ok") and "unparsed" not in verdict:
                    row["output"] = out["output"][-300:]
                rows.append(row)
        return rows

    @reg.read(title="List external connectors")
    async def cml_list_external_connectors(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the controller's external connectors: the networks an 'external_connector' node can
        attach a lab to. Per connector: label (the value to put in the node's config, e.g. 'NAT' or
        'System Bridge'), Linux bridge, forwarding mode (NAT = outbound only behind the controller,
        BRIDGE = layer 2 on the host network), host interface, and whether IP snooping (which feeds
        cml_get_layer3_addresses) is on."""
        app: CmlApp = get_client(ctx)
        data: list[dict[str, Any]] = await app.api.get("/system/external_connectors")
        rows = []
        for c in data:
            op = c.get("operational") or {}
            rows.append(
                {
                    "label": c.get("label"),
                    "device_name": c.get("device_name"),
                    "forwarding": op.get("forwarding"),
                    "host_interface": op.get("interface"),
                    "ip_networks": op.get("ip_networks") or [],
                    "snooped": c.get("snooped"),
                    "protected": c.get("protected"),
                    "allowed": c.get("allowed"),
                    "tags": c.get("tags") or [],
                    "id": c.get("id"),
                }
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
