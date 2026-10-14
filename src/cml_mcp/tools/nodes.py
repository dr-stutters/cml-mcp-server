"""Node and interface read tools."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
    text_result,
)
from stutters_mcp_core.http import page_of

from cml_mcp.client import CmlApp
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
    ) -> ToolResult:
        """The recent output of a running node's serial console (boot messages, syslog lines printed
        to the console, crash dumps). Use it to see why a node is stuck booting or what it logged
        after a change. Only works while the node is started."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        n = await app.resolve_node(info["id"], node)
        log = await app.api.get(
            f"/labs/{info['id']}/nodes/{n['id']}/consoles/{console}/log", {"lines": lines}
        )
        text = strip_console_prefixes(str(log or ""))
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
    ) -> ToolResult:
        """IPv4/IPv6 addresses CML has learned for running nodes, per interface with its MAC. CML learns
        them by snooping DHCP/ARP/ND on the lab's links, so statically addressed nodes that have not
        sent traffic (or labs without an external connector) may show none; use the console or the
        node's own CLI then."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
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
        out: dict[str, Any] = {"lab": info.get("lab_title"), "addresses": learned}
        if not learned:
            out["note"] = (
                f"No addresses learned yet on {len(rows)} interfaces. CML only learns addresses it sees "
                "in DHCP/ARP/ND traffic; static addresses show up after the node sends traffic."
            )
        return object_result(out, shape=False)
