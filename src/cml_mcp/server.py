"""Server definition: SPEC, INSTRUCTIONS and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server
from stutters_mcp_core.spec import SpecSource

from cml_mcp.client import CmlApp
from cml_mcp.config import Settings

INSTRUCTIONS = """
Tools for Cisco Modeling Labs (CML 2.x), a network simulation platform.
Object model: labs contain nodes (routers, switches, hosts); nodes have interfaces; a link joins
two interfaces. Labs and nodes can be given by title/label or by UUID; links by id or as
'nodeA<->nodeB' ('r1:Ethernet0/0<->r2:Ethernet0/0' when there are several).
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
        register=[],
        status=CmlApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )
