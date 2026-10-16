"""CLI through the console server on a throwaway lab: IOL router + Alpine host."""

from collections.abc import Iterator

import pytest
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import rw
from .labkit import confirm_call, create_lab, delete_lab

pytestmark = pytest.mark.live
TITLE = "mcp-test-live-cli"


@pytest.fixture(scope="module")
def lab() -> Iterator[str]:
    from cml_mcp._core.testing import live_settings

    from .conftest import ROOT

    settings = live_settings(Settings, "CML_", _env_file=ROOT / ".env", mcp_cache_dir="")
    lab_id = create_lab(settings, TITLE, start=True)
    yield lab_id
    delete_lab(settings, lab_id)


async def test_show_and_ping(settings: Settings, lab: str) -> None:
    data = await call_tool(
        create_server(settings),
        "cml_run_commands",
        {
            "lab": lab,
            "nodes": ["r1", "r2"],
            "commands": ["show ip interface brief", "ping 10.99.0.2 repeat 3"],
        },
    )
    by_node = {r["node"]: r for r in data["results"]}
    assert by_node["r1"]["prompt"] == "r1#"
    brief = by_node["r1"]["outputs"][0]["output"]
    assert "10.99.0.1" in brief and "\n\n" not in brief
    assert "Success rate" in by_node["r1"]["outputs"][1]["output"]


async def test_configure_then_verify(settings: Settings, lab: str) -> None:
    async with Client(create_server(rw(settings))) as c:
        result = await confirm_call(
            c,
            "cml_configure_node",
            {
                "lab": lab,
                "node": "r1",
                "lines": [
                    "interface Loopback7",
                    "ip address 7.7.7.7 255.255.255.255",
                    "this is not a command",
                ],
            },
        )
    assert result["applied"] == 2
    assert result["rejected"][0]["line"] == "this is not a command"
    data = await call_tool(
        create_server(settings),
        "cml_run_commands",
        {"lab": lab, "nodes": ["r1"], "commands": ["show running-config interface Loopback7"]},
    )
    assert "7.7.7.7" in data["results"][0]["outputs"][0]["output"]


async def test_not_booted_and_forbidden(settings: Settings, lab: str) -> None:
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError, match="read tier"):
        await call_tool(
            create_server(settings), "cml_run_commands", {"lab": lab, "nodes": ["r1"], "commands": ["reload"]}
        )
