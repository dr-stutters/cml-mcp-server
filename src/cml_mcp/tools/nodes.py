"""Node and interface read tools."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
    text_result,
)
from stutters_mcp_core.http import page_of

from cml_mcp.client import CmlApp
from cml_mcp.console import clean
from cml_mcp.licence import licensed
from cml_mcp.netops import address_commands, console_batch, parse_addresses
from cml_mcp.tools.common import (
    LabRef,
    NodeRef,
    config_text,
    drop_keys,
    load_topo,
    shaped,
    strip_console_prefixes,
)


def node_row(n: dict[str, Any], stats: dict[str, Any] | None = None) -> dict[str, Any]:
    op = n.get("operational") or {}
    row: dict[str, Any] = {
        "label": n.get("label"),
        "id": n["id"],
        "definition": n.get("node_definition"),
        "image": n.get("image_definition") or op.get("image_definition"),
        "state": n.get("state"),
        "boot_progress": n.get("boot_progress"),
        "cpus": n.get("cpus") or op.get("cpus"),
        "ram_mb": n.get("ram") or op.get("ram"),
        "tags": n.get("tags") or None,
    }
    if stats:
        row["cpu_usage_pct"] = stats.get("cpu_usage")
        row["ram_usage_pct"] = stats.get("ram_usage")
    return {k: v for k, v in row.items() if v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List nodes")
    async def cml_list_nodes(
        ctx: Context,
        lab: LabRef,
        state: Annotated[
            str | None,
            Field(description="Filter by state: DEFINED_ON_CORE, STOPPED, STARTED, QUEUED, BOOTED"),
        ] = None,
        definition: Annotated[
            str | None, Field(description="Filter by node definition id, e.g. iol-xe")
        ] = None,
        label: Annotated[str | None, Field(description="Filter: label contains (case-insensitive)")] = None,
        tag: Annotated[str | None, Field(description="Filter: nodes carrying this tag")] = None,
        include_usage: Annotated[bool, Field(description="Add live CPU/RAM usage for running nodes")] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the nodes of a lab: label, id, node definition, image, state (BOOTED = up and ready),
        boot progress, vCPUs, RAM and tags; optionally live CPU/RAM usage. Labels and ids from here
        work in every node tool."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        nodes = await app.list_nodes(info["id"], operational=True)
        stats: dict[str, Any] = {}
        if include_usage:
            stats = (await app.api.get(f"/labs/{info['id']}/simulation_stats")).get("nodes") or {}
        rows = []
        for n in nodes:
            if state and n.get("state") != state.upper():
                continue
            if definition and n.get("node_definition") != definition:
                continue
            if label and label.lower() not in str(n.get("label", "")).lower():
                continue
            if tag and tag not in (n.get("tags") or []):
                continue
            rows.append(node_row(n, stats.get(n["id"])))
        rows.sort(key=lambda r: str(r.get("label")).lower())
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get node")
    async def cml_get_node(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        include_config: Annotated[
            bool, Field(description="Include the node's day-0 configuration text")
        ] = False,
    ) -> ToolResult:
        """Everything about one node: definition, image, state, boot progress, resources (vCPU, RAM,
        disk), compute host, tags, each interface with its MAC, state and the 'node:interface' it is
        wired to, and optionally its day-0 configuration. For the boot output use
        cml_get_node_console_log."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        n = await app.resolve_node(lid, node)
        topo = await load_topo(app, lid, operational=True)
        peers = topo.peers()
        interfaces = []
        for i in topo.interfaces.values():
            if i.get("node") != n["id"]:
                continue
            peer = peers.get(i["id"])
            interfaces.append(
                {
                    "label": i.get("label"),
                    "id": i["id"],
                    "type": i.get("type"),
                    "slot": i.get("slot"),
                    "mac": (i.get("operational") or {}).get("mac_address") or i.get("mac_address"),
                    "state": i.get("state"),
                    "connected_to": peer[0] if peer else None,
                    "link_id": peer[1] if peer else None,
                }
            )
        out: dict[str, Any] = drop_keys({k: v for k, v in n.items() if k != "configuration"})
        out["interfaces"] = interfaces
        if include_config:
            full = await app.api.get(f"/labs/{lid}/nodes/{n['id']}")
            out["configuration"] = config_text(full)
            files = full.get("configuration")
            if isinstance(files, list) and len(files) > 1:
                out["configuration_files"] = [c.get("name") for c in files if isinstance(c, dict)]
        return shaped(out)

    @reg.read(title="Node console log")
    async def cml_get_node_console_log(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        lines: Annotated[int, Field(ge=1, le=5000, description="How many of the most recent lines")] = 100,
        console: Annotated[int, Field(ge=0, le=64, description="Serial console number (0 = main)")] = 0,
        grep: Annotated[
            str | None,
            Field(description="Only lines matching this regular expression (case-insensitive)"),
        ] = None,
    ) -> ToolResult:
        """The recent output of a running node's serial console (boot messages, syslog lines printed
        to the console, crash dumps), with terminal escape codes removed. Use it to see why a node is
        stuck booting or what it logged after a change; `grep` keeps only matching lines (e.g.
        'error|fail|%LINK'). Only works while the node is started."""
        pattern = None
        if grep:
            try:
                pattern = re.compile(grep, re.IGNORECASE)
            except re.error as e:
                raise InvalidRequest(f"grep is not a valid regular expression: {e}") from e
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        n = await app.resolve_node(info["id"], node)
        log = await app.api.get(
            f"/labs/{info['id']}/nodes/{n['id']}/consoles/{console}/log", {"lines": lines}
        )
        text = clean(strip_console_prefixes(str(log or "")))
        if pattern is not None:
            text = "\n".join(line for line in text.splitlines() if pattern.search(line))
            if not text:
                return text_result(f"(no lines matching {grep!r} in the last {lines} lines)")
        return text_result(text or f"(console {console} of {n.get('label')} has no output yet)")

    @reg.read(title="List interfaces")
    async def cml_list_interfaces(
        ctx: Context,
        lab: LabRef,
        node: Annotated[str | None, Field(description="Only this node's interfaces (label or id)")] = None,
        connected: Annotated[
            bool | None, Field(description="True: only wired interfaces; False: only free ones")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List interfaces in a lab (optionally of one node): node, label, type (physical/loopback),
        slot, MAC, state, and the 'node:interface' it connects to. Use it to find free ports before
        cml_connect_nodes, or to map MACs to nodes."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        topo = await load_topo(app, info["id"], operational=True)
        node_id = (await app.resolve_node(info["id"], node))["id"] if node else None
        peers = topo.peers()
        rows = []
        for i in topo.interfaces.values():
            if node_id and i.get("node") != node_id:
                continue
            peer = peers.get(i["id"])
            if connected is not None and bool(peer) != connected:
                continue
            rows.append(
                {
                    "node": topo.node_label(i.get("node")),
                    "label": i.get("label"),
                    "id": i["id"],
                    "type": i.get("type"),
                    "slot": i.get("slot"),
                    "mac": (i.get("operational") or {}).get("mac_address") or i.get("mac_address"),
                    "state": i.get("state"),
                    "connected_to": peer[0] if peer else None,
                }
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Layer-3 addresses")
    async def cml_get_layer3_addresses(
        ctx: Context,
        lab: LabRef,
        node: Annotated[str | None, Field(description="Only this node (label or id)")] = None,
        source: Annotated[
            Literal["snooped", "cli", "both"],
            Field(
                description="'snooped' (default): what CML learned from traffic on external-connector "
                "segments; 'cli': ask each booted node over its console (show ip interface brief, FTD "
                "show network, Linux ip addr); 'both'"
            ),
        ] = "snooped",
    ) -> ToolResult:
        """IPv4/IPv6 addresses of a lab's running nodes, per interface. 'snooped' addresses are learned
        by CML from DHCP/ARP/ND it sees on external-connector (bridge/NAT) segments, with MACs - fast,
        but only for interfaces that sent traffic there. 'cli' logs in to every booted node and reads
        its configured IPv4 addresses (all interfaces, including internal links and loopbacks) -
        slower but complete. Use 'cli' or 'both' to find the management address to give another
        system (FMC, Catalyst Center, ISE)."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        out: dict[str, Any] = {"lab": info.get("lab_title")}
        if source in ("cli", "both"):
            nodes = [await app.resolve_node(lid, node)] if node else await app.list_nodes(lid)
            nodes = [n for n in nodes if licensed(n) and n.get("state") in ("BOOTED", "STARTED")]
            batch = await console_batch(
                app, lid, nodes, lambda _n, cred: address_commands(cred.os), timeout=30
            )
            cli_rows: list[dict[str, Any]] = []
            for res in batch:
                if res.get("error"):
                    cli_rows.append({"node": res["node"], "error": res["error"]})
                    continue
                for o in res.get("outputs") or []:
                    for row in parse_addresses(o["command"], o.get("output", "")):
                        cli_rows.append({"node": res["node"], **row})
            out["cli"] = cli_rows
            if source == "cli":
                return object_result(out, shape=False)
        if node:
            n = await app.resolve_node(lid, node)
            data = {n["id"]: await app.api.get(f"/labs/{lid}/nodes/{n['id']}/layer3_addresses")}
        else:
            data = await app.api.get(f"/labs/{lid}/layer3_addresses") or {}
        rows = []
        for node_id, entry in data.items():
            name = entry.get("name") or node_id
            for mac, iface in (entry.get("interfaces") or {}).items():
                rows.append(
                    {
                        "node": name,
                        "interface": iface.get("label"),
                        "mac": mac,
                        "ipv4": iface.get("ip4") or [],
                        "ipv6": iface.get("ip6") or [],
                    }
                )
        learned = [r for r in rows if r["ipv4"] or r["ipv6"]]
        out["addresses"] = learned
        if not learned:
            out["note"] = (
                f"No addresses learned yet on {len(rows)} interfaces. CML only learns addresses it sees "
                "in DHCP/ARP/ND traffic on external-connector segments; use source='cli' to ask the nodes."
            )
        return object_result(out, shape=False)
