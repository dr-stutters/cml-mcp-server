import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError
from stutters_mcp_core.testing import call_tool

from cml_mcp.server import create_server

from .conftest import LAB, LID, LINK, R1, make_settings


async def call(name: str, args: dict[str, Any] | None = None, **settings: Any) -> Any:
    return await call_tool(create_server(make_settings(**settings)), name, args or {})


async def call_error(name: str, args: dict[str, Any]) -> str:
    async with Client(create_server(make_settings())) as c:
        with pytest.raises(ToolError) as e:
            await c.call_tool(name, args)
    return str(e.value)


# --- labs -------------------------------------------------------------------------------


async def test_list_labs_json_and_filters(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_labs", {"response_format": "json"})
    assert data["total"] == 1
    row = data["results"][0]
    assert row == {
        "id": LID,
        "title": "mcp-test-probe",
        "state": "STARTED",
        "node_count": 2,
        "link_count": 1,
        "owner": "admin",
        "modified": row["modified"],
    }
    assert (await call("cml_list_labs", {"title": "nomatch", "response_format": "json"}))["total"] == 0
    assert (await call("cml_list_labs", {"state": "STOPPED", "response_format": "json"}))["total"] == 0


async def test_list_labs_markdown(lab_api: respx.MockRouter) -> None:
    text = await call("cml_list_labs")
    assert "| id | title | state | node_count | link_count |" in text
    assert "mcp-test-probe" in text


async def test_lab_resolution_by_title_substring_and_errors(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_lab", {"lab": "PROBE"})
    assert data["id"] == LID and data["converged"] is True
    assert data["node_states"] == {"BOOTED": 2}
    assert data["running_nodes"] == 2 and data["allocated_ram_mb"] == 2048
    msg = await call_error("cml_get_lab", {"lab": "missing"})
    assert "No lab named 'missing'" in msg and "cml_list_labs" in msg


async def test_ambiguous_lab_title(lab_api: respx.MockRouter) -> None:
    two = [
        {"id": "11111111-1111-4111-8111-111111111111", "lab_title": "core-a"},
        {"id": "22222222-2222-4222-8222-222222222222", "lab_title": "core-b"},
    ]
    lab_api.get("/labs").mock(return_value=httpx.Response(200, json=two))
    msg = await call_error("cml_get_lab", {"lab": "core"})
    assert "2 labs match 'core'" in msg


async def test_topology_summary(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_lab_topology", {"lab": LID})
    r1 = next(n for n in data["nodes"] if n["label"] == "r1")
    assert r1["connections"] == {"Ethernet0/0": "r2:Ethernet0/0"}
    assert r1["free_interfaces"] == 3
    assert data["links"] == [{"id": LINK, "a": "r1:Ethernet0/0", "b": "r2:Ethernet0/0", "state": "STARTED"}]


async def test_topology_full_keeps_links_and_hides_keys(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_lab_topology", {"lab": LID, "detail": "full"})
    assert data["links"][0]["id"] == LINK
    assert "link_capture_key" not in json.dumps(data)


async def test_export_masks_pyats_passwords(lab_api: respx.MockRouter) -> None:
    yaml_text = (
        "nodes:\n  - pyats:\n      username: admin\n      password: s3cret\n      enable_password: null\n"
    )
    lab_api.get(f"/labs/{LID}/download").mock(return_value=httpx.Response(200, text=yaml_text))
    text = await call("cml_export_lab", {"lab": LID})
    assert "s3cret" not in text and "password: ********" in text and "enable_password: null" in text
    raw = await call("cml_export_lab", {"lab": LID, "include_credentials": True})
    assert "s3cret" in raw


async def test_pyats_testbed_masks_passwords(lab_api: respx.MockRouter) -> None:
    text = await call("cml_get_pyats_testbed", {"lab": LID})
    assert "cisco\n" not in text.replace("username: cisco\n", "")
    assert "change_me" in text  # usernames stay
    assert text.count("********") == 3


async def test_lab_events_newest_first_with_names(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_lab_events", {"lab": LID, "response_format": "json", "limit": 500})
    rows = data["results"]
    assert rows[0]["time"] >= rows[-1]["time"]
    assert all(not (r["event"] == "state" and "state" not in r) or r["type"] for r in rows)
    modified = [r for r in rows if r["event"] == "MODIFIED"]
    assert modified and modified[0]["element"] in ("r1", "r2") and "compute_id" in modified[0]["changes"]
    created_ifaces = [r for r in rows if r["event"] == "CREATED" and r["type"] == "Interface"]
    assert any(r["element"] == "r1:Ethernet0/0" for r in created_ifaces)
    only_r1 = await call("cml_list_lab_events", {"lab": LID, "element": "r1", "response_format": "json"})
    assert only_r1["total"] > 0
    assert all(r["element"] == "r1" or r["element"].startswith("r1:") for r in only_r1["results"])


# --- nodes ------------------------------------------------------------------------------


async def test_list_nodes_with_usage(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_nodes", {"lab": LID, "include_usage": True, "response_format": "json"})
    r1 = data["results"][0]
    assert r1["label"] == "r1" and r1["state"] == "BOOTED" and r1["image"] == "iol-xe-17-18-02"
    assert "cpu_usage_pct" in r1
    none = await call("cml_list_nodes", {"lab": LID, "definition": "iosv", "response_format": "json"})
    assert none["total"] == 0


async def test_get_node_with_interfaces_and_config(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_node", {"lab": LID, "node": "r1", "include_config": True})
    assert data["id"] == R1
    eth0 = next(i for i in data["interfaces"] if i["label"] == "Ethernet0/0")
    assert eth0["connected_to"] == "r2:Ethernet0/0" and eth0["link_id"] == LINK
    assert data["configuration"].startswith("hostname r1")
    assert "serial_consoles" not in json.dumps(data)


async def test_get_node_masks_pyats_password(lab_api: respx.MockRouter) -> None:
    from .conftest import NODES

    node = dict(NODES[0], pyats={"username": "u", "password": "topsecret", "enable_password": None})
    lab_api.get(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=node))
    data = await call("cml_get_node", {"lab": LID, "node": R1})
    assert data["pyats"] == {"username": "u", "password": "********"}


async def test_unknown_node(lab_api: respx.MockRouter) -> None:
    msg = await call_error("cml_get_node", {"lab": LID, "node": "r9"})
    assert "No node named 'r9'" in msg


async def test_console_log_strips_prefixes(lab_api: respx.MockRouter) -> None:
    text = await call("cml_get_node_console_log", {"lab": LID, "node": "r1", "lines": 5})
    assert "|00000" not in text and "%SYS-5-CONFIG_I" in text
    assert lab_api.calls.last.request.url.params["lines"] == "5"


async def test_list_interfaces_filters(lab_api: respx.MockRouter) -> None:
    data = await call(
        "cml_list_interfaces", {"lab": LID, "node": "r2", "connected": True, "response_format": "json"}
    )
    assert [(r["label"], r["connected_to"]) for r in data["results"]] == [("Ethernet0/0", "r1:Ethernet0/0")]
    free = await call("cml_list_interfaces", {"lab": LID, "connected": False, "response_format": "json"})
    assert free["total"] == 8  # 2 loopbacks + 3 free ports each


async def test_layer3_addresses(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_layer3_addresses", {"lab": LID})
    assert data["addresses"] == [] and "No addresses learned" in data["note"]
    learned = {
        R1: {"name": "r1", "interfaces": {"aa:bb": {"label": "Ethernet0/0", "ip4": ["10.0.12.1"], "ip6": []}}}
    }
    lab_api.get(f"/labs/{LID}/layer3_addresses").mock(return_value=httpx.Response(200, json=learned))
    data = await call("cml_get_layer3_addresses", {"lab": LID})
    assert data["addresses"] == [
        {"node": "r1", "interface": "Ethernet0/0", "mac": "aa:bb", "ipv4": ["10.0.12.1"], "ipv6": []}
    ]


# --- links ------------------------------------------------------------------------------


async def test_list_links(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_links", {"lab": LID, "response_format": "json"})
    assert data["results"] == [
        {"id": LINK, "a": "r1:Ethernet0/0", "b": "r2:Ethernet0/0", "state": "STARTED", "conditioned": False}
    ]


@pytest.mark.parametrize(
    "ref", [LINK, "r1<->r2", "r2 r1", "r1:Ethernet0/0<->r2:Ethernet0/0", "r1-Ethernet0/0<->r2-Ethernet0/0"]
)
async def test_get_link_by_any_reference(lab_api: respx.MockRouter, ref: str) -> None:
    data = await call("cml_get_link", {"lab": LID, "link": ref})
    assert data["id"] == LINK and data["a"] == "r1:Ethernet0/0"
    assert data["conditioning"] == {"enabled": False}
    assert data["capture"]["running"] is True and data["capture"]["max_packets"] == 30


async def test_link_not_found(lab_api: respx.MockRouter) -> None:
    msg = await call_error("cml_get_link", {"lab": LID, "link": "r1<->r9"})
    assert "No link between 'r1' and 'r9'" in msg


async def test_capture_packets_filtered(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_capture_packets", {"lab": LID, "link": "r1<->r2", "response_format": "json"})
    assert data["total"] > 0 and {"no", "protocol", "info"} <= set(data["results"][0])
    loop = await call(
        "cml_list_capture_packets", {"lab": LID, "link": LINK, "protocol": "loop", "response_format": "json"}
    )
    assert loop["total"] == sum(1 for p in data["results"] if p["protocol"] == "LOOP")


async def test_capture_packets_without_capture(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/pcap/{LINK}/packets").mock(return_value=httpx.Response(404, json={"code": 404}))
    msg = await call_error("cml_list_capture_packets", {"lab": LID, "link": LINK})
    assert "cml_start_capture" in msg


# --- system / definitions ---------------------------------------------------------------


async def test_resource_usage(lab_api: respx.MockRouter) -> None:
    lab_api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(
            200, json=[{"id": "iol-xe", "sim": {"ram": 1024, "cpus": 1}}, {"id": "cat9000v-uadp", "sim": {}}]
        )
    )
    lab_api.get("/nodes").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"lab_id": LID, "label": "r1", "node_definition": "iol-xe", "state": "BOOTED"},
                {
                    "lab_id": LID,
                    "label": "sw1",
                    "node_definition": "cat9000v-uadp",
                    "state": "BOOTED",
                    "ram": 18432,
                    "cpus": 4,
                },
                {"lab_id": LID, "label": "off", "node_definition": "iol-xe", "state": "STOPPED"},
            ],
        )
    )
    data = await call("cml_get_resource_usage")
    assert data["labs"] == [
        {"lab": LAB["lab_title"], "id": LID, "running_nodes": 2, "licensed": 2, "ram_mb": 19456, "cpus": 5}
    ]
    assert [n["node"] for n in data["top_nodes"]] == ["sw1", "r1"]
    assert data["cluster"]["cpu_count"] == 32
    c = data["computes"][0]
    assert c["running_nodes"] == 2 and c["allocated_memory_mb"] == 2048
    assert data["license_features"][0]["name"] == "CML - Personal License"


async def test_system_health_and_licensing(lab_api: respx.MockRouter) -> None:
    health = await call("cml_get_system_health")
    assert health["summary"]["valid"] is True
    lic = await call("cml_get_licensing")
    assert lic["registration"] == "NOT_REGISTERED" and lic["features"][0]["max"] == 1


async def test_node_definitions(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_node_definitions", {"search": "iol", "response_format": "json"})
    ids = [r["id"] for r in data["results"]]
    assert "iol-xe" in ids and "ioll2-xe" in ids
    iol = next(r for r in data["results"] if r["id"] == "iol-xe")
    assert iol["nature"] == "router" and iol["interfaces"] == "4 default / 32 max" and iol["images"] == 1
    switches = await call("cml_list_node_definitions", {"nature": "switch", "response_format": "json"})
    assert "unmanaged_switch" in [r["id"] for r in switches["results"]]


async def test_get_node_definition_parses_yaml(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_node_definition", {"definition": "iol-xe"})
    assert data["nature"] == "router"
    assert data["interfaces"]["default_count"] == 4
    assert data["boot"]["completed"] == ["Press RETURN to get started!"]
    assert [f["name"] for f in data["config_files"]] == ["config.json", "ios_config.txt"]
    assert data["images"][0]["id"] == "iol-xe-17-18-02"


async def test_image_definitions(lab_api: respx.MockRouter) -> None:
    data = await call("cml_list_image_definitions", {"definition": "iosv", "response_format": "json"})
    assert [r["id"] for r in data["results"]] == ["iosv-159-3-m12"]


# --- smart ------------------------------------------------------------------------------


async def test_wait_for_converged_already(lab_api: respx.MockRouter) -> None:
    data = await call("cml_wait_for_converged", {"lab": LID})
    assert data["converged"] is True and data["node_states"] == {"BOOTED": 2}


async def test_wait_for_converged_polls(lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    async def no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    answers = iter([False, False, True])
    lab_api.get(f"/labs/{LID}/check_if_converged").mock(
        side_effect=lambda r: httpx.Response(200, json=next(answers))
    )
    data = await call("cml_wait_for_converged", {"lab": LID, "timeout": 60})
    assert data["converged"] is True


async def test_wait_for_converged_refuses_stopped_lab(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/labs/{LID}/state").mock(return_value=httpx.Response(200, json="STOPPED"))
    lab_api.get(f"/labs/{LID}/check_if_converged").mock(return_value=httpx.Response(200, json=False))
    msg = await call_error("cml_wait_for_converged", {"lab": LID})
    assert "not started" in msg and "cml_start_lab" in msg


async def test_diff_lab_against_modified_baseline(lab_api: respx.MockRouter) -> None:
    from pathlib import Path

    import yaml

    text = (Path(__file__).parent.parent / "fixtures" / "lab_export.yaml").read_text()
    same = await call("cml_diff_lab", {"lab": LID, "baseline_yaml": text})
    assert same["identical"] is True
    base = yaml.safe_load(text)
    base["nodes"][0]["configuration"][0]["content"] = "hostname r1-old\nend"
    base["nodes"][1]["ram"] = 2048
    base["nodes"].append({"id": "n9", "label": "r9", "node_definition": "iosv", "interfaces": []})
    base["links"] = []
    diff = await call("cml_diff_lab", {"lab": LID, "baseline_yaml": yaml.safe_dump(base)})
    assert diff["identical"] is False
    assert diff["nodes"]["only_in_b"] == ["r9"]
    assert "-hostname r1" in diff["nodes"]["changed"]["r1"]["config_diff"]
    assert diff["nodes"]["changed"]["r2"]["ram"] == {"b": 2048}  # a=None is dropped
    assert diff["links"]["only_in_a"] == ["r1:Ethernet0/0<->r2:Ethernet0/0"]


async def test_diff_lab_needs_exactly_one_target(lab_api: respx.MockRouter) -> None:
    msg = await call_error("cml_diff_lab", {"lab": LID})
    assert "exactly one" in msg
    msg = await call_error("cml_diff_lab", {"lab": LID, "baseline_yaml": "just text"})
    assert "Not a CML topology" in msg


async def test_layer3_addresses_for_one_node(lab_api: respx.MockRouter) -> None:
    one = {"name": "r1", "interfaces": {"aa:bb": {"label": "Ethernet0/0", "ip4": ["10.0.12.1"], "ip6": []}}}
    lab_api.get(f"/labs/{LID}/nodes/{R1}/layer3_addresses").mock(return_value=httpx.Response(200, json=one))
    data = await call("cml_get_layer3_addresses", {"lab": LID, "node": "r1"})
    assert data["addresses"][0]["ipv4"] == ["10.0.12.1"]


async def test_link_endpoint_matching_is_case_insensitive(lab_api: respx.MockRouter) -> None:
    data = await call("cml_get_link", {"lab": LID, "link": "R1:ethernet0/0 <-> r2"})
    assert data["id"] == LINK


async def test_event_changes_hide_access_keys(lab_api: respx.MockRouter) -> None:
    ev = [
        {
            "lab_id": LID,
            "event": "MODIFIED",
            "element_type": "Node",
            "element_id": R1,
            "data": {"console_key": "secret-key", "ram": 2048},
            "previous": {"ram": 1024},
            "timestamp": "2026-10-14T12:00:00",
        }
    ]
    lab_api.get(f"/labs/{LID}/events").mock(return_value=httpx.Response(200, json=ev))
    data = await call("cml_list_lab_events", {"lab": LID, "response_format": "json"})
    assert "secret-key" not in json.dumps(data)
    assert data["results"][0]["changes"] == {"ram": {"from": 1024, "to": 2048}}


def test_mask_helpers() -> None:
    from cml_mcp.tools.labs import mask_export, mask_testbed

    assert mask_testbed("  - password: x\n  password: null\n") == "  - password: ********\n  password: null\n"
    assert "y" not in mask_export("    enable_password: y\n")
