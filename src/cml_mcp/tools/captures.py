"""Packet capture analysis: decoded summaries of a link capture (read) and capture-in-one-call (write)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
import contextlib
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
)

from cml_mcp.client import CmlApp
from cml_mcp.pcap import PcapError, matches, pcap_truncated, read_pcap, summarise
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import LabRef, LinkRef, shaped

Host = Annotated[str | None, Field(description="Only packets from or to this IP or MAC address")]
Src = Annotated[str | None, Field(description="Only packets from this IP or MAC address")]
Dst = Annotated[str | None, Field(description="Only packets to this IP or MAC address")]
Proto = Annotated[
    str | None,
    Field(description="Only this protocol: RADIUS, EAPOL, OSPF, DHCP, ARP, ICMP, TCP, UDP, sftunnel, SSH..."),
]
Port = Annotated[int | None, Field(ge=0, le=65535, description="Only TCP/UDP packets with this port")]
Highlights = Annotated[int, Field(ge=0, le=200, description="Decoded packets listed per protocol")]
Packets = Annotated[
    int, Field(ge=0, le=500, description="Also list this many matching packets (decoded rows), oldest first")
]


MAX_PCAP_BYTES = 64 * 2**20


async def fetch_capture(app: CmlApp, link: dict[str, Any]) -> bytes:
    """The link's capture as pcap bytes. CML keys captures by link_capture_key, which 2.10 sets to the
    link id (older controllers had a separate key)."""
    key = link.get("link_capture_key") or link["id"]
    try:
        data = await app.api.request("GET", f"/pcap/{key}", expect="bytes")
    except NotFound as e:
        raise NotFound("No packet capture exists for this link yet; start one (cml_capture).", 404) from e
    data = bytes(data or b"")
    if len(data) > MAX_PCAP_BYTES:
        raise InvalidRequest(
            f"The capture is {len(data) // 2**20} MB; capture less (max_packets, bpf_filter) to analyse it"
        )
    return data


def analyse(
    data: bytes,
    *,
    host: str | None,
    src: str | None,
    dst: str | None,
    protocol: str | None,
    port: int | None,
    highlights: int,
    packets: int,
) -> dict[str, Any]:
    try:
        all_packets = read_pcap(data) if data else []
    except PcapError as e:
        raise InvalidRequest(f"Could not read the capture: {e}") from e
    picked = [p for p in all_packets if matches(p, host=host, src=src, dst=dst, protocol=protocol, port=port)]
    truncated = pcap_truncated(all_packets)
    summary = summarise(picked, highlights=highlights, whole=all_packets, truncated=truncated)
    out = {"captured_packets": len(all_packets), **summary}
    if truncated:
        out["truncated"] = f"only the first {len(all_packets)} packets were decoded"
    filters = {
        k: v
        for k, v in {"host": host, "src": src, "dst": dst, "protocol": protocol, "port": port}.items()
        if v is not None
    }
    if filters:
        out = {"filters": filters, **out}
        if "findings" in out:
            out["findings_scope"] = "the whole capture (filters would hide the answers)"
    if packets:
        out["packet_list"] = [p.row() for p in picked[:packets]]
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Summarize packet capture")
    async def cml_summarize_capture(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        host: Host = None,
        src: Src = None,
        dst: Dst = None,
        protocol: Proto = None,
        port: Port = None,
        highlights: Highlights = 20,
        packets: Packets = 0,
    ) -> ToolResult:
        """Analyse the packet capture on a link (the running one or the last one): packet count,
        protocol mix, top conversations and decoded highlights - RADIUS (code, User-Name, NAS,
        Calling-Station-Id, VLAN, Cisco AV-pairs, the EAP inside; passwords, State, Class and
        authenticators are never shown), EAPOL/EAP (identity, method), OSPF (hello: router id,
        area, DR/BDR, neighbours), DHCP (Discover/Offer/Request/ACK, client MAC, address), ARP,
        ICMP and TCP flags (sftunnel 8305, SSH, NETCONF); repeated packets are one row with a count.
        `findings` says what didn't complete (DHCP Discover without Offer, unanswered ARP / ping /
        TCP SYN / RADIUS request, EAP failures) - start there for "what's failing". Filters narrow
        everything to matching packets. Proves a MAB/802.1X exchange with ISE, FTD registration or
        an OSPF adjacency without reading raw packet lists. Capture first with cml_capture or
        cml_start_capture."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lk = await app.resolve_link(info["id"], link)
        data = await fetch_capture(app, lk)
        result = await asyncio.to_thread(
            analyse,
            data,
            host=host,
            src=src,
            dst=dst,
            protocol=protocol,
            port=port,
            highlights=highlights,
            packets=packets,
        )
        return shaped({"lab": info.get("lab_title"), "link": lk.get("label"), **result})

    @reg.write(title="Capture and summarize", task=True)
    async def cml_capture(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        seconds: Annotated[int, Field(ge=1, le=600, description="Capture for this long")] = 30,
        max_packets: Annotated[
            int, Field(ge=1, le=100_000, description="Stop earlier after this many packets")
        ] = 5000,
        bpf_filter: Annotated[
            str | None,
            Field(
                max_length=500,
                description="Capture filter (Berkeley packet filter), e.g. 'udp port 1812 or udp port 1813'",
            ),
        ] = None,
        host: Host = None,
        protocol: Proto = None,
        port: Port = None,
        highlights: Highlights = 20,
        packets: Packets = 0,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Capture on a running link and analyse it in one call: start a capture, wait `seconds`
        (or until max_packets), stop it and return the same summary as cml_summarize_capture.
        Trigger the traffic you want to see while it runs (e.g. a port bounce for MAB, an FMC
        registration, an OSPF restart). Replaces the link's previous capture. Preview-first."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        status = await app.api.get(f"/labs/{lid}/links/{lk['id']}/capture/status") or {}
        body: dict[str, Any] = {"maxpackets": max_packets, "maxtime": seconds}
        if bpf_filter:
            body["bpfilter"] = bpf_filter
        blockers = []
        if lk.get("state") != "STARTED":
            blockers.append(f"Link is {lk.get('state')}; captures need a running link (start the lab first)")
        if status.get("starttime"):
            blockers.append("A capture is already running on this link; stop it first with cml_stop_capture")
        plan = Plan(
            f"Capture on link {lk.get('label')} for up to {seconds}s and summarize it",
            details=body,
            side_effects=["Replaces the link's previous capture"],
            blockers=blockers,
        )

        async def apply() -> Any:
            path = f"/labs/{lid}/links/{lk['id']}/capture"
            await app.api.put(f"{path}/start", body)
            started = time.monotonic()
            seen_running = False
            try:
                while (elapsed := time.monotonic() - started) < seconds:
                    await asyncio.sleep(max(0.2, min(2.0, seconds - elapsed)))
                    st = await app.api.get(f"{path}/status") or {}
                    if st.get("starttime"):
                        seen_running = True
                    elif seen_running or time.monotonic() - started > 5:
                        break  # stopped by itself (max_packets / max_time), or never showed as running
                    await ctx.report_progress(min(seconds, time.monotonic() - started), seconds)
            finally:  # never leave a capture running (errors, cancellation)
                try:
                    st = await app.api.get(f"{path}/status") or {}
                    if st.get("starttime"):
                        await app.api.put(f"{path}/stop")
                except Exception:  # noqa: BLE001 - don't hide the original error
                    pass
            captured = round(time.monotonic() - started, 1)
            current = await app.resolve_link(lid, lk["id"])
            data = await fetch_capture(app, current)
            return {
                "link": lk.get("label"),
                "captured_seconds": captured,
                **await asyncio.to_thread(
                    analyse,
                    data,
                    host=host,
                    src=None,
                    dst=None,
                    protocol=protocol,
                    port=port,
                    highlights=highlights,
                    packets=packets,
                ),
            }

        return await preview_or_apply(
            ctx,
            tool="cml_capture",
            args={
                "lab": lab,
                "link": link,
                "seconds": seconds,
                "max_packets": max_packets,
                "bpf_filter": bpf_filter,
                "host": host,
                "protocol": protocol,
                "port": port,
                "highlights": highlights,
                "packets": packets,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )


WIRELESS_DEFINITIONS = ("wireless-ap", "wireless-client")


async def wireless_status(app: CmlApp, key: str) -> dict[str, Any]:
    try:
        st = await app.api.get(f"/wireless/pcap/{key}")
    except (NotFound, InvalidRequest, UpstreamError):
        return {}
    return st if isinstance(st, dict) else {}


def wireless_running(status: dict[str, Any]) -> str | None:
    """'N frames, started T' when a session is still inside its max time, else None."""
    start, cfg = status.get("starttime"), status.get("config") or {}
    if not start or not cfg.get("maxtime"):
        return None
    try:
        from datetime import UTC, datetime

        t0 = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
    except ValueError:
        return None
    if (datetime.now(UTC) - t0).total_seconds() > float(cfg["maxtime"]) + 2:
        return None
    return f"{status.get('packetscaptured') or 0} frames so far, started {start}"


def register_wireless(reg: ToolRegistrar) -> None:
    @reg.write(title="Capture wireless traffic", task=True)
    async def cml_capture_wireless(
        ctx: Context,
        lab: LabRef,
        node: Annotated[
            str, Field(description="A wireless node (wireless-ap or wireless-client) to capture at")
        ],
        seconds: Annotated[int, Field(ge=1, le=600, description="Capture for this long")] = 30,
        max_packets: Annotated[
            int, Field(ge=1, le=100_000, description="Stop earlier after this many frames")
        ] = 5000,
        bpf_filter: Annotated[
            str | None, Field(max_length=128, description="Capture filter (Berkeley packet filter)")
        ] = None,
        host: Host = None,
        protocol: Proto = None,
        highlights: Highlights = 20,
        packets: Packets = 0,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Capture the simulated 802.11 medium at a wireless node (CML wireless-ap / wireless-client) and
        summarize it in one call: beacons and probes with SSIDs, authentication / association (status
        codes), deauthentication and disassociation (reason codes), the EAPOL 4-way handshake and the
        802.1X EAP exchange (identity, method), and unencrypted data (DHCP, ARP, ICMP); encrypted data
        is counted as protected. Trigger the event while it runs (e.g. reconnect the client with
        cml_configure_node mode='exec' 'sudo wpa_cli -i wlan0 reassociate'). Replaces the node's
        previous wireless capture. Preview-first."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        blockers = []
        if n.get("node_definition") not in WIRELESS_DEFINITIONS:
            blockers.append(
                f"{n.get('label')!r} is a {n.get('node_definition')} node; wireless captures run at "
                f"{' or '.join(WIRELESS_DEFINITIONS)} nodes"
            )
        if n.get("state") != "BOOTED":
            blockers.append(f"Node is {n.get('state')}; it must be BOOTED")
        key = n["id"]  # CML keys wireless capture sessions by the node id
        status = {} if blockers else await wireless_status(app, key)
        if busy := wireless_running(status):
            blockers.append(
                f"A wireless capture is running at {n.get('label')!r} ({busy}); wait for it to end, it stops "
                "by itself after its max time"
            )
        body: dict[str, Any] = {
            "node_id": key,
            "maxpackets": max_packets,
            "maxtime": seconds,
            "encap": "radiotap",
        }
        if bpf_filter:
            body["bpfilter"] = bpf_filter
        plan = Plan(
            f"Capture 802.11 frames at {n.get('label')!r} for up to {seconds}s and summarize them",
            details={**body, "previous_session": bool(status)},
            side_effects=["Removes the node's previous (finished) wireless capture session"],
            blockers=blockers,
        )

        async def apply() -> Any:
            current = await wireless_status(app, key)
            if busy := wireless_running(current):
                raise InvalidRequest(f"A wireless capture started meanwhile at {n.get('label')!r} ({busy})")
            if current:  # a finished session lingers and blocks a new one (409)
                with contextlib.suppress(NotFound):
                    await app.api.request("DELETE", f"/wireless/pcap/{key}", expect="text")
            await app.api.post("/wireless/pcap", body)
            started = time.monotonic()
            try:
                # CML stops the session itself after maxtime/maxpackets; poll for progress, then allow a
                # short grace so its own timer has fired before the file is read
                while (elapsed := time.monotonic() - started) < seconds + 2:
                    await asyncio.sleep(max(0.2, min(2.0, seconds + 2 - elapsed)))
                    try:
                        st = await app.api.get(f"/wireless/pcap/{key}") or {}
                    except UpstreamError:
                        continue
                    if (st.get("packetscaptured") or 0) >= max_packets:
                        break
                    await ctx.report_progress(min(seconds, time.monotonic() - started), seconds)
                captured = round(time.monotonic() - started, 1)
                data = await app.api.request("GET", f"/wireless/pcap/{key}/download", expect="bytes")
            finally:  # never leave a session behind (it would block the next capture)
                with contextlib.suppress(Exception):
                    await app.api.request("DELETE", f"/wireless/pcap/{key}", expect="text")
            data = bytes(data or b"")
            if len(data) > MAX_PCAP_BYTES:
                raise InvalidRequest(
                    "The capture is too large to analyse; capture less (max_packets, bpf_filter)"
                )
            return {
                "node": n.get("label"),
                "captured_seconds": captured,
                **await asyncio.to_thread(
                    analyse,
                    data,
                    host=host,
                    src=None,
                    dst=None,
                    protocol=protocol,
                    port=None,
                    highlights=highlights,
                    packets=packets,
                ),
            }

        return await preview_or_apply(
            ctx,
            tool="cml_capture_wireless",
            args={
                "lab": lab,
                "node": node,
                "seconds": seconds,
                "max_packets": max_packets,
                "bpf_filter": bpf_filter,
                "host": host,
                "protocol": protocol,
                "highlights": highlights,
                "packets": packets,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
