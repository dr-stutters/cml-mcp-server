"""L23: long CML tools registered as MCP background tasks when MCP_TASKS=true."""

import respx
from fastmcp import Client
from stutters_mcp_core.testing import call_tool

from cml_mcp.server import create_server

from .conftest import make_settings

LONG = {
    "cml_upload_image",
    "cml_build_lab",
    "cml_build_recipe",
    "cml_start_lab",
    "cml_wait_for_converged",
    "cml_verify_recipe",
    "cml_capture",
    "cml_capture_wireless",
    "cml_check_reachability",
}


async def test_long_tools_are_tasks_when_enabled(api: respx.MockRouter) -> None:
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, mcp_tasks=True)
    data = await call_tool(create_server(s), "cml_status")
    assert set(data["server"]["tasks"]["tools"]) == LONG


async def test_tasks_off_by_default_and_tools_still_callable(api: respx.MockRouter) -> None:
    s = make_settings(mcp_enable_writes=True)
    data = await call_tool(create_server(s), "cml_status")
    assert "tasks" not in data["server"]
    async with Client(create_server(make_settings(mcp_enable_writes=True, mcp_tasks=True))) as c:
        # a non-task tool still works
        res = await c.call_tool("cml_list_recipes", {"response_format": "json"})
        assert not res.is_error
