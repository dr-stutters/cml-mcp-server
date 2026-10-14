"""Read tools against a throwaway, started two-router lab (created and deleted by the fixture)."""

from collections.abc import Iterator
from typing import Any

import pytest
from stutters_mcp_core.testing import call_tool, live_settings

from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import ROOT
from .labkit import create_lab, delete_lab

pytestmark = pytest.mark.live
TITLE = "mcp-test-live-read"


@pytest.fixture(scope="module")
def lab() -> Iterator[str]:
    settings = live_settings(Settings, "CML_", _env_file=ROOT / ".env", mcp_cache_dir="")
    lab_id = create_lab(settings, TITLE, start=True)
    yield lab_id
    delete_lab(settings, lab_id)


async def call(settings: Settings, name: str, args: dict[str, Any] | None = None) -> Any:
    return await call_tool(create_server(settings), name, args or {})


async def test_list_and_get_lab(settings: Settings, lab: str) -> None:
    labs = await call(settings, "cml_list_labs", {"title": TITLE, "response_format": "json"})
    assert [r["id"] for r in labs["results"]] == [lab]
    info = await call(settings, "cml_get_lab", {"lab": TITLE})
    assert info["converged"] is True and info["node_states"] == {"BOOTED": 2}


async def test_topology_nodes_interfaces_links(settings: Settings, lab: str) -> None:
    topo = await call(settings, "cml_get_lab_topology", {"lab": lab})
    assert topo["links"][0]["a"] == "r1:Ethernet0/0" and topo["links"][0]["b"] == "r2:Ethernet0/0"
    nodes = await call(settings, "cml_list_nodes", {"lab": lab, "response_format": "json"})
    assert {r["label"] for r in nodes["results"]} == {"r1", "r2"}
    node = await call(settings, "cml_get_node", {"lab": lab, "node": "r1", "include_config": True})
    assert "10.99.0.1" in node["configuration"]
    ifaces = await call(
        settings, "cml_list_interfaces", {"lab": lab, "node": "r1", "response_format": "json"}
    )
    assert any(r.get("connected_to") == "r2:Ethernet0/0" for r in ifaces["results"])
    link = await call(settings, "cml_get_link", {"lab": lab, "link": "r1<->r2"})
    assert link["state"] == "STARTED" and link["capture"]["running"] is False


async def test_console_events_export_diff(settings: Settings, lab: str) -> None:
    log = await call(settings, "cml_get_node_console_log", {"lab": lab, "node": "r2", "lines": 50})
    assert "%" in log  # IOS syslog lines
    events = await call(settings, "cml_list_lab_events", {"lab": lab, "response_format": "json"})
    assert events["total"] > 0
    export = await call(settings, "cml_export_lab", {"lab": lab})
    assert "node_definition: iol-xe" in export
    diff = await call(settings, "cml_diff_lab", {"lab": lab, "baseline_yaml": export})
    assert diff["identical"] is True
    testbed = await call(settings, "cml_get_pyats_testbed", {"lab": lab})
    assert "terminal_server" in testbed


async def test_wait_l3_and_resources(settings: Settings, lab: str) -> None:
    waited = await call(settings, "cml_wait_for_converged", {"lab": lab, "timeout": 60})
    assert waited["converged"] is True
    l3 = await call(settings, "cml_get_layer3_addresses", {"lab": lab})
    assert "addresses" in l3
    usage = await call(settings, "cml_get_resource_usage")
    assert usage["computes"][0]["running_nodes"] >= 2


async def test_definitions(settings: Settings) -> None:
    defs = await call(settings, "cml_list_node_definitions", {"search": "iol", "response_format": "json"})
    assert "iol-xe" in [r["id"] for r in defs["results"]]
    d = await call(settings, "cml_get_node_definition", {"definition": "iol-xe"})
    assert d["images"]
    images = await call(
        settings, "cml_list_image_definitions", {"definition": "iol-xe", "response_format": "json"}
    )
    assert images["total"] >= 1
