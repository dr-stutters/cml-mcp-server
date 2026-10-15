"""Server definition: SPEC, INSTRUCTIONS and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server
from stutters_mcp_core.spec import SpecSource

from cml_mcp.client import CmlApp
from cml_mcp.config import Settings
from cml_mcp.tools import (
    build_tool,
    captures,
    cli,
    configs,
    dangerous,
    definitions,
    lab_writes,
    labs,
    links,
    network,
    nodes,
    planning,
    samples,
    smart,
    system,
    topology_writes,
)

INSTRUCTIONS = """
Tools for Cisco Modeling Labs (CML 2.x), a network simulation platform.
Object model: labs contain nodes (routers, switches, hosts); nodes have interfaces; a link joins
two interfaces. Labs and nodes can be given by title/label or by UUID; links by id or as
'nodeA<->nodeB' ('r1:Ethernet0/0<->r2:Ethernet0/0' when there are several).
Start with cml_list_labs, then cml_get_lab_topology (compact summary; detail='full' for everything).
Nodes: cml_list_nodes / cml_get_node / cml_get_node_console_log; wiring: cml_list_interfaces,
cml_list_links / cml_get_link (conditioning, capture status), cml_list_capture_packets.
Captures: cml_capture (capture + decoded summary in one call), cml_summarize_capture (RADIUS, EAPOL,
OSPF, DHCP, ARP, ICMP decoded; secrets never shown).
What can be built: cml_list_node_definitions (iol-xe / ioll2-xe boot in under a minute).
Device CLI: cml_run_commands runs show/ping/traceroute on booted nodes via the CML console server
(no IP reachability needed; IOS/IOS-XE, NX-OS, FTD, Linux); config changes go through
cml_configure_node (write tier; mode='exec' for FTD 'configure manager add ...').
What changed on a device: cml_diff_node_config (running config vs day-0, startup, another node, a baseline).
Outside networks: cml_list_external_connectors, then an external_connector node in cml_build_lab.
Proving connectivity: cml_check_reachability; addresses: cml_get_layer3_addresses(source='cli').
Slow images (FTDv 15-30 min, cat9000v ~10): build/start with wait=false, then cml_wait_for_converged.
Running nodes are capped by the licence; external connectors and unmanaged switches don't count.
cml_plan_licences(target) says which labs to stop before starting a lab or recipe.
CML returns whole collections; list tools page client-side with limit/offset.
Call cml_status first if anything fails. cml_search_spec / cml_get_definition describe the REST API
(paths are relative to /api/v0) and cml_api_call reaches endpoints no other tool covers.
"""

SPEC = ServerSpec(
    name="cml-mcp-server",
    prefix="cml",
    product="Cisco Modeling Labs",
    env_prefix="CML_",
    instructions=INSTRUCTIONS,
)


def spec_sources(app: CmlApp) -> list[SpecSource]:
    async def load(a: CmlApp) -> dict[str, Any]:
        return await a.openapi()

    async def version(a: CmlApp) -> str:
        return await a.version()

    return [
        SpecSource(
            "cml",
            load,
            client=lambda a: a.api,
            version=version,
            description="CML controller REST API (/api/v0)",
        )
    ]


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    return build_server(
        SPEC,
        settings,
        client_factory=lambda s: CmlApp(s, transport=transport),
        register=[
            system.register,
            labs.register,
            nodes.register,
            links.register,
            captures.register,
            definitions.register,
            smart.register,
            lab_writes.register,
            topology_writes.register,
            build_tool.register,
            cli.register,
            configs.register,
            network.register,
            samples.register,
            planning.register,
            dangerous.register,
        ],
        status=CmlApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )
