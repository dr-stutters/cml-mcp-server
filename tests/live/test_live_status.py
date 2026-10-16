import pytest

from cml_mcp._core.testing import call_tool
from cml_mcp.config import Settings
from cml_mcp.server import create_server

pytestmark = pytest.mark.live


async def test_status(settings: Settings) -> None:
    data = await call_tool(create_server(settings), "cml_status")
    assert data["cml"]["version"].startswith("2.")
    assert data["cml"]["user"]
    assert data["cml"]["health"]["valid"] is True


async def test_spec_search(settings: Settings) -> None:
    data = await call_tool(create_server(settings), "cml_search_spec", {"query": "link condition"})
    names = [r["name"] for r in data["results"]]
    assert any("/condition" in n for n in names)
