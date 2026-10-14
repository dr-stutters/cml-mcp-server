"""Link read tools: links, conditioning, packet captures."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import NotFound, ResponseFormat, ToolRegistrar, get_client, list_result
from stutters_mcp_core.http import page_of

from cml_mcp.client import CmlApp
from cml_mcp.tools.common import LabRef, LinkRef, load_topo, shaped


def condition_view(cond: dict[str, Any]) -> dict[str, Any]:
    """Configured conditioning without the null fields (operational copy dropped)."""
    return {k: v for k, v in cond.items() if k != "operational" and v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List links")
    async def cml_list_links(
        ctx: Context,
        lab: LabRef,
        node: Annotated[str | None, Field(description="Only links touching this node (label or id)")] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the links of a lab as 'node:interface' pairs with link id and state (STARTED = up),
        and whether conditioning (latency/loss/bandwidth) is active. Link ids or 'r1<->r2' endpoint
        strings work in the link tools."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        topo = await load_topo(app, lid)
        node_id = (await app.resolve_node(lid, node))["id"] if node else None
        topo_data = await app.api.get(f"/labs/{lid}/topology", {"exclude_configurations": "true"})
        conditioned = {
            lk["id"] for lk in topo_data.get("links") or [] if (lk.get("conditioning") or {}).get("enabled")
        }
        rows = []
        for lk in topo.links:
            if node_id and node_id not in (lk.get("node_a"), lk.get("node_b")):
                continue
            row = topo.link_row(lk)
            row["conditioned"] = lk["id"] in conditioned
            rows.append(row)
        rows.sort(key=lambda r: (r["a"], r["b"]))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get link")
    async def cml_get_link(ctx: Context, lab: LabRef, link: LinkRef) -> ToolResult:
        """One link in detail: its two endpoints ('node:interface'), state, the configured link
        conditioning (bandwidth kbps, latency/jitter ms, loss/duplicate/corrupt %) and the packet
        capture status (running?, packets captured, filter). Read packets with
        cml_list_capture_packets."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        topo = await load_topo(app, lid)
        out: dict[str, Any] = topo.link_row(lk)
        out["label"] = lk.get("label")
        cond = await app.api.get(f"/labs/{lid}/links/{lk['id']}/condition")
        out["conditioning"] = condition_view(cond or {})
        cap = await app.api.get(f"/labs/{lid}/links/{lk['id']}/capture/status")
        cfg = (cap or {}).get("config") or {}
        out["capture"] = {
            "running": bool((cap or {}).get("starttime")),
            "started": (cap or {}).get("starttime"),
            "packets_captured": (cap or {}).get("packetscaptured"),
            "max_packets": cfg.get("maxpackets"),
            "max_time": cfg.get("maxtime"),
            "filter": cfg.get("bpfilter") or None,
        }
        return shaped(out)

    @reg.read(title="List captured packets")
    async def cml_list_capture_packets(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        protocol: Annotated[str | None, Field(description="Only this protocol, e.g. ICMP, OSPF, ARP")] = None,
        contains: Annotated[
            str | None, Field(description="Only packets whose source/destination/info contains this text")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Decoded packets (number, relative time, source, destination, protocol, length, summary like
        Wireshark's info column) from the packet capture on a link: the running one or the last one
        that finished. Start a capture with cml_start_capture first."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lk = await app.resolve_link(info["id"], link)
        key = lk.get("link_capture_key") or lk["id"]
        try:
            packets: list[dict[str, Any]] = await app.api.get(f"/pcap/{key}/packets") or []
        except NotFound as e:
            raise NotFound(
                "No packet capture exists for this link yet; start one with cml_start_capture.", 404
            ) from e
        rows = []
        for p in packets:
            if protocol and str(p.get("protocol", "")).lower() != protocol.lower():
                continue
            hay = f"{p.get('source')} {p.get('destination')} {p.get('info')}".lower()
            if contains and contains.lower() not in hay:
                continue
            rows.append(
                {
                    "no": p.get("no"),
                    "time": p.get("time"),
                    "source": p.get("source"),
                    "destination": p.get("destination"),
                    "protocol": p.get("protocol"),
                    "length": p.get("length"),
                    "info": p.get("info"),
                }
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
