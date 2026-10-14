"""Dangerous tools on a throwaway 'mcp-test-live-danger' lab: wipe/config/delete node, link, lab."""

from collections.abc import Iterator

import pytest
from fastmcp import Client
from stutters_mcp_core.testing import call_tool

from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import rw
from .labkit import confirm_call, create_lab, delete_lab, find_lab

pytestmark = pytest.mark.live
TITLE = "mcp-test-live-danger"


@pytest.fixture
def lab(settings: Settings) -> Iterator[str]:
    lab_id = create_lab(settings, TITLE, start=True)
    yield lab_id
    if find_lab(settings, TITLE):
        delete_lab(settings, lab_id)


async def test_wipe_reconfigure_delete(settings: Settings, lab: str) -> None:
    s = rw(settings, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        await confirm_call(c, "cml_wipe_node", {"lab": TITLE, "node": "r2", "force": True})
        await confirm_call(
            c, "cml_set_node_config", {"lab": TITLE, "node": "r2", "configuration": "hostname r2-new\nend\n"}
        )
        node = await call_tool(
            create_server(s), "cml_get_node", {"lab": TITLE, "node": "r2", "include_config": True}
        )
        assert node["state"] == "DEFINED_ON_CORE" and "r2-new" in node["configuration"]

        gone = await confirm_call(c, "cml_delete_link", {"lab": TITLE, "link": "r1<->r2"})
        assert gone["deleted"] == "r1:Ethernet0/0<->r2:Ethernet0/0"
        await confirm_call(c, "cml_delete_node", {"lab": TITLE, "node": "r2"})
        nodes = await call_tool(create_server(s), "cml_list_nodes", {"lab": TITLE, "response_format": "json"})
        assert [r["label"] for r in nodes["results"]] == ["r1"]

        await confirm_call(c, "cml_wipe_lab", {"lab": TITLE, "force": True})
        deleted = await confirm_call(c, "cml_delete_lab", {"lab": TITLE})
        assert deleted["deleted"] == lab
    labs = await call_tool(create_server(s), "cml_list_labs", {"title": TITLE, "response_format": "json"})
    assert labs["total"] == 0
