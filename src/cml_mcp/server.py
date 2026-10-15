"""Server definition: SPEC, INSTRUCTIONS and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server
from stutters_mcp_core.spec import SpecSource

from cml_mcp.client import CmlApp
from cml_mcp.config import Settings
from cml_mcp.redaction import LabSecretRedactor
from cml_mcp.tools import (
    annotations,
    build_tool,
    captures,
    cli,
    configs,
    dangerous,
    definitions,
    images,
    lab_writes,
    labs,
    link_scenarios,
    links,
    network,
    nodes,
    planning,
    recipes_tools,
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
Diagrams: cml_export_topology (mermaid / drawio / json with addresses); cml_list_annotations and
cml_annotate_lab (notes, per-node addresses, recipe purpose) make a lab self-describing.
What changed on a device: cml_diff_node_config (running config vs day-0, startup, another node, a baseline).
Outside networks: cml_list_external_connectors, then an external_connector node in cml_build_lab.
Degraded networks: cml_apply_link_scenario (wan-good, wan-satellite, lossy-wifi, brownout, flap) and
cml_clear_link_scenarios; cml_get_link_scenarios shows values, expected ping deltas and flap jobs.
Proving connectivity: cml_check_reachability (success % and average RTT);
addresses: cml_get_layer3_addresses(source='cli').
Slow images (FTDv 15-30 min, cat9000v ~10): build/start with wait=false, then cml_wait_for_converged.
Running nodes are capped by the licence; external connectors and unmanaged switches don't count.
cml_plan_licences(target) says which labs to stop before starting a lab or recipe.
Test labs for the other suite servers: cml_list_recipes, cml_build_recipe, cml_verify_recipe, and the
prompt cml_build_test_lab (recipe -> licences -> build/start -> converge -> verify -> hand-off).
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
    mcp = build_server(
        SPEC,
        settings,
        client_factory=lambda s: CmlApp(s, transport=transport),
        register=[
            system.register,
            labs.register,
            nodes.register,
            links.register,
            link_scenarios.register,
            captures.register,
            captures.register_wireless,
            annotations.register,
            definitions.register,
            images.register,
            smart.register,
            lab_writes.register,
            topology_writes.register,
            build_tool.register,
            cli.register,
            configs.register,
            network.register,
            samples.register,
            planning.register,
            recipes_tools.register,
            dangerous.register,
        ],
        status=CmlApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )
    mcp.add_middleware(LabSecretRedactor(settings.lab_secrets_file))
    return mcp
