"""L68 (#72): node priority, lab node staging and autostart (cml_set_lab_boot), the staged start order."""

import json
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from cml_mcp.build import NodeSpec, NodeStaging, boot_order, build_topology
from cml_mcp.recipes import get_recipe
from cml_mcp.server import create_server

from .conftest import LAB, LID, NODES, R2, fixture, make_settings

RW = {"mcp_enable_writes": True}
RWD = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
DEFS = {d["id"]: d for d in fixture("simplified_node_definitions.json")}


def data(res: Any) -> Any:
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


async def preview_apply(name: str, args: dict[str, Any], **settings: Any) -> tuple[dict[str, Any], Any]:
    async with Client(create_server(make_settings(**(settings or RW)))) as c:
        preview = data(await c.call_tool(name, args))
        if preview.get("status") != "preview":
            return preview, None
        applied = data(await c.call_tool(name, {**args, "confirm": preview["confirm"]}))
        return preview, applied


# --- build ---------------------------------------------------------------------------------------------


def test_boot_order_groups_by_priority_highest_first_unset_last() -> None:
    nodes = [
        {"label": "br1", "priority": 500},
        {"label": "host", "priority": None},
        {"label": "manager", "priority": 800},
        {"label": "validator", "priority": 900},
        {"label": "br2", "priority": 500},
    ]
    assert boot_order(nodes) == [
        {"priority": 900, "nodes": ["validator"]},
        {"priority": 800, "nodes": ["manager"]},
        {"priority": 500, "nodes": ["br1", "br2"]},
        {"priority": None, "nodes": ["host"]},
    ]


def test_build_topology_carries_priority_and_staging() -> None:
    nodes = [
        NodeSpec(label="r1", definition="iol-xe", priority=900),
        NodeSpec(label="r2", definition="iol-xe"),
    ]
    topo, _ = build_topology("t", nodes, ["r1 r2"], DEFS, node_staging=NodeStaging(enabled=True))
    assert topo["lab"]["version"] == "0.3.1"
    staging = topo["lab"]["node_staging"]
    assert staging == {"enabled": True, "start_remaining": True, "abort_on_failure": False}
    assert topo["nodes"][0]["priority"] == 900 and "priority" not in topo["nodes"][1]
    plain, _ = build_topology("t", [NodeSpec(label="r1", definition="iol-xe")], [], DEFS)
    assert plain["lab"]["version"] == "0.3.0" and "node_staging" not in plain["lab"]


@pytest.mark.parametrize("value", [-1, 10001])
def test_node_priority_range(value: int) -> None:
    with pytest.raises(ValueError, match="priority"):
        NodeSpec(label="r1", definition="iol-xe", priority=value)


async def test_build_lab_posts_priorities_and_shows_boot_order(lab_api: respx.MockRouter) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "built"}))
    args = {
        "title": "mcp-test-boot",
        "nodes": [
            {"label": "edge", "definition": "iol-xe", "priority": 500},
            {"label": "ctrl", "definition": "iol-xe", "priority": 900},
        ],
        "links": ["ctrl edge"],
        "node_staging": {"enabled": True, "abort_on_failure": True},
    }
    preview, applied = await preview_apply("cml_build_lab", args)
    assert preview["status"] == "preview", preview
    assert preview["preview"]["boot_order"] == [
        {"priority": 900, "nodes": ["ctrl"]},
        {"priority": 500, "nodes": ["edge"]},
    ]
    assert "boot_order_note" not in preview["preview"]
    assert applied["status"] == "applied"
    topo = yaml.safe_load(route.calls.last.request.content)
    assert topo["lab"]["version"] == "0.3.1"
    assert topo["lab"]["node_staging"] == {"enabled": True, "start_remaining": True, "abort_on_failure": True}
    assert {n["label"]: n.get("priority") for n in topo["nodes"]} == {"edge": 500, "ctrl": 900}


async def test_build_lab_priorities_without_staging_say_so(lab_api: respx.MockRouter) -> None:
    args = {"title": "mcp-test-boot2", "nodes": [{"label": "r1", "definition": "iol-xe", "priority": 1}]}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", args))
    assert preview["preview"]["node_staging"] == {"enabled": False}
    assert "node staging is off" in preview["preview"]["boot_order_note"]


# --- cml_update_node -------------------------------------------------------------------------------------


async def test_update_node_sets_priority(lab_api: respx.MockRouter) -> None:
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=httpx.Response(200, json=R2))
    preview, applied = await preview_apply("cml_update_node", {"lab": LID, "node": "r2", "priority": 900})
    assert preview["preview"]["changes"] == {"priority": {"from": None, "to": 900}}
    assert applied["status"] == "applied"
    assert json.loads(patch.calls.last.request.content) == {"priority": 900}


# --- cml_set_lab_boot -----------------------------------------------------------------------------------


def _lab(lab_api: respx.MockRouter, **lab: Any) -> None:
    lab_api.get(f"/labs/{LID}").mock(return_value=httpx.Response(200, json={**LAB, **lab}))


async def test_set_lab_boot_enables_staging(lab_api: respx.MockRouter) -> None:
    prioritised = [dict(NODES[0], priority=900), dict(NODES[1], priority=None)]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=prioritised))
    patch = lab_api.patch(f"/labs/{LID}").mock(return_value=httpx.Response(200, json=LAB))
    preview, applied = await preview_apply("cml_set_lab_boot", {"lab": LID, "staging": {"enabled": True}})
    assert preview["status"] == "preview", preview
    assert preview["preview"]["changes"] == {"node_staging.enabled": {"from": False, "to": True}}
    assert preview["preview"]["boot_order"] == [
        {"priority": 900, "nodes": ["r1"]},
        {"priority": None, "nodes": ["r2"]},
    ]
    assert applied["status"] == "applied" and applied["result"]["changed"] == ["node_staging.enabled"]
    assert json.loads(patch.calls.last.request.content) == {
        "node_staging": {"enabled": True, "start_remaining": True, "abort_on_failure": False}
    }


async def test_set_lab_boot_nothing_to_change(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply("cml_set_lab_boot", {"lab": LID, "staging": {"enabled": False}})
    assert preview["status"] == "blocked" and "Nothing to change" in preview["blockers"][0]
    preview, _ = await preview_apply("cml_set_lab_boot", {"lab": LID})
    assert preview["status"] == "blocked" and "give staging and/or autostart" in preview["blockers"][0]


async def test_set_lab_boot_autostart_on_needs_dangerous(lab_api: respx.MockRouter) -> None:
    args = {"lab": LID, "autostart": {"enabled": True, "priority": 100, "delay": 60}}
    blocked, _ = await preview_apply("cml_set_lab_boot", args)
    assert blocked["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in blocked["blockers"][0]
    patch = lab_api.patch(f"/labs/{LID}").mock(return_value=httpx.Response(200, json=LAB))
    preview, applied = await preview_apply("cml_set_lab_boot", args, **RWD)
    assert preview["status"] == "preview", preview
    assert any("after every CML host reboot" in s for s in preview["side_effects"])
    assert applied["status"] == "applied"
    assert json.loads(patch.calls.last.request.content) == {
        "autostart": {"enabled": True, "priority": 100, "delay": 60}
    }


async def test_set_lab_boot_autostart_off_or_retune_is_write_tier(lab_api: respx.MockRouter) -> None:
    _lab(lab_api, autostart={"enabled": True, "priority": 100, "delay": 60})
    patch = lab_api.patch(f"/labs/{LID}").mock(return_value=httpx.Response(200, json=LAB))
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_set_lab_boot", {"lab": LID, "autostart": {"delay": 120}}))
    assert preview["status"] == "preview", preview
    assert preview["preview"]["changes"] == {"autostart.delay": {"from": 60, "to": 120}}
    _, applied = await preview_apply("cml_set_lab_boot", {"lab": LID, "autostart": {"enabled": False}})
    assert applied["status"] == "applied"
    assert json.loads(patch.calls.last.request.content) == {
        "autostart": {"enabled": False, "priority": 100, "delay": 60}
    }


@pytest.mark.parametrize("autostart", [{"priority": 10001}, {"delay": -1}])
async def test_set_lab_boot_rejects_out_of_range(
    lab_api: respx.MockRouter, autostart: dict[str, int]
) -> None:
    args = {"lab": LID, "autostart": autostart}
    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool("cml_set_lab_boot", args, raise_on_error=False)
    assert res.is_error


# --- cml_start_lab preview -----------------------------------------------------------------------------


async def test_start_lab_preview_shows_staged_order(lab_api: respx.MockRouter) -> None:
    _lab(lab_api, node_staging={"enabled": True, "start_remaining": False, "abort_on_failure": False})
    stopped = [dict(NODES[0], state="STOPPED", priority=900), dict(NODES[1], state="STOPPED", priority=None)]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=stopped))
    lab_api.get("/nodes").mock(return_value=httpx.Response(200, json=[]))
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_start_lab", {"lab": LID}))
    assert preview["preview"]["boot_order"] == [
        {"priority": 900, "nodes": ["r1"]},
        {"priority": None, "nodes": ["r2"], "skipped": True},
    ]
    assert preview["preview"]["node_staging"]["start_remaining"] is False


async def test_start_lab_preview_notes_ignored_priorities(lab_api: respx.MockRouter) -> None:
    stopped = [dict(NODES[0], state="STOPPED", priority=900), dict(NODES[1], state="STOPPED")]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=stopped))
    lab_api.get("/nodes").mock(return_value=httpx.Response(200, json=[]))
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_start_lab", {"lab": LID}))
    assert "boot_order" not in preview["preview"]
    assert "node staging is off" in preview["preview"]["boot_order_note"]


# --- recipes --------------------------------------------------------------------------------------------


def _priorities(recipe: str) -> dict[str, int | None]:
    b = get_recipe(recipe)["build"]
    NodeStaging.model_validate(b["node_staging"])
    return {n.label: n.priority for n in (NodeSpec.model_validate(x) for x in b["nodes"])}


@pytest.mark.parametrize("recipe", ["cat-sdwan-controllers", "cat-sdwan-fabric", "cat-sdwan-secure"])
def test_sdwan_recipes_boot_controllers_before_edges(recipe: str) -> None:
    p = _priorities(recipe)
    assert get_recipe(recipe)["build"]["node_staging"]["enabled"] is True
    assert p["ext"] > p["validator"] > p["manager"] > p["controller"]
    edges = [label for label in ("hub1", "br1", "br2") if label in p]
    assert all(p["controller"] > p[e] for e in edges)
    assert all(v is not None for v in p.values()), "every node has a priority"


def test_firewall_and_ise_recipes_boot_the_manager_first() -> None:
    fmc = _priorities("fmc-local")
    assert fmc["mgmt-sw"] > fmc["fmc"] > fmc["ftd"]
    ftd = _priorities("ftd-fmc")
    assert ftd["ext-mgmt"] > ftd["ftd1"]
    ise = _priorities("ise-access")
    assert ise["ext"] > ise["sw1"] > ise["client"] and ise["sw1"] > ise["eaptls-client"]


async def test_build_recipe_imports_priorities_and_staging(api: respx.MockRouter) -> None:
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/system/external_connectors").mock(
        return_value=httpx.Response(200, json=[{"label": "System Bridge", "device_name": "bridge0"}])
    )
    imported = api.post("/import").mock(return_value=httpx.Response(200, json={"id": "L-new"}))
    args = {"recipe": "ftd-fmc", "start": False}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_recipe", args))
        assert preview["status"] == "preview", preview
        assert preview["preview"]["boot_order"][0]["priority"] == 1000
        await c.call_tool("cml_build_recipe", {**args, "confirm": preview["confirm"]})
    topo = yaml.safe_load(imported.calls.last.request.content)
    assert topo["lab"]["node_staging"]["enabled"] is True and topo["lab"]["version"] == "0.3.1"
    assert {n["label"]: n["priority"] for n in topo["nodes"]}["ftd1"] == 500
