"""Write tools end to end on a throwaway 'mcp-test-live-write' lab (always deleted afterwards)."""

from collections.abc import Iterator

import pytest
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import rw
from .labkit import confirm_call, delete_lab, find_lab

pytestmark = pytest.mark.live
TITLE = "mcp-test-live-write"


@pytest.fixture
def cleanup(settings: Settings) -> Iterator[None]:
    if lab_id := find_lab(settings, TITLE):
        delete_lab(settings, lab_id)
    yield
    if lab_id := find_lab(settings, TITLE):
        delete_lab(settings, lab_id)


async def test_build_start_change_stop(settings: Settings, cleanup: None) -> None:
    s = rw(settings)
    async with Client(create_server(s)) as c:
        built = await confirm_call(
            c,
            "cml_build_lab",
            {
                "title": TITLE,
                "nodes": [
                    {"label": "r1", "definition": "iol-xe", "config": "hostname r1\nend\n"},
                    {"label": "r2", "definition": "iol-xe", "config": "hostname r2\nend\n"},
                    {"label": "sw1", "definition": "unmanaged_switch"},
                ],
                "links": ["r1 r2", "r1 sw1"],
                "start": True,
            },
        )
        assert built["links"] == ["r1:Ethernet0/0<->r2:Ethernet0/0", "r1:Ethernet0/1<->sw1:port0"]
        assert built["convergence"]["converged"] is True

        await confirm_call(c, "cml_add_node", {"lab": TITLE, "definition": "alpine", "label": "h1"})
        link = await confirm_call(c, "cml_connect_nodes", {"lab": TITLE, "node_a": "h1", "node_b": "sw1"})
        assert link["a"] == "h1:eth0" and link["b"] == "sw1:port1"

        cond = await confirm_call(
            c, "cml_set_link_condition", {"lab": TITLE, "link": "r1<->r2", "latency_ms": 25, "loss_pct": 1.0}
        )
        assert cond["latency"] == 25
        await confirm_call(c, "cml_start_capture", {"lab": TITLE, "link": "r1<->r2", "max_time": 30})
        detail = await call_tool(create_server(s), "cml_get_link", {"lab": TITLE, "link": "r1<->r2"})
        assert detail["conditioning"]["latency"] == 25 and detail["capture"]["running"] is True
        await confirm_call(c, "cml_stop_capture", {"lab": TITLE, "link": "r1<->r2"})
        await confirm_call(c, "cml_set_link_condition", {"lab": TITLE, "link": "r1<->r2", "clear": True})

        down = await confirm_call(
            c, "cml_set_link_state", {"lab": TITLE, "link": "r1<->sw1", "state": "down"}
        )
        assert down["state"] == "STOPPED"
        up = await confirm_call(c, "cml_set_link_state", {"lab": TITLE, "link": "r1<->sw1", "state": "up"})
        assert up["state"] == "STARTED"

        saved = await confirm_call(c, "cml_extract_node_configs", {"lab": TITLE, "node": "r1"})
        assert saved["saved"] == ["r1"]
        node = await call_tool(
            create_server(s), "cml_get_node", {"lab": TITLE, "node": "r1", "include_config": True}
        )
        assert "Current configuration" in node["configuration"] or "hostname r1" in node["configuration"]

        await confirm_call(c, "cml_update_node", {"lab": TITLE, "node": "r2", "tags": ["mcp-test"]})
        stopped = await confirm_call(c, "cml_set_node_state", {"lab": TITLE, "node": "r2", "state": "stop"})
        assert stopped["state"] == "STOPPED"
        result = await confirm_call(c, "cml_stop_lab", {"lab": TITLE})
        assert result["state"] == "STOPPED"
