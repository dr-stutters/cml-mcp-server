import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from cml_mcp.server import create_server
from cml_mcp.tools.topology_writes import late_link_warning

from .conftest import LID, LINK, NODES, R1, R2, fixture, make_settings

RW = {"mcp_enable_writes": True}
RWD = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}


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


async def test_tiers_control_registration(lab_api: respx.MockRouter) -> None:
    async def names(**kw: Any) -> set[str]:
        async with Client(create_server(make_settings(**kw))) as c:
            return {t.name for t in await c.list_tools()}

    ro, rw, rwd = await names(), await names(**RW), await names(**RWD)
    assert "cml_start_lab" not in ro and "cml_start_lab" in rw
    assert "cml_delete_lab" not in rw and "cml_delete_lab" in rwd
    assert len(ro) >= 25


async def test_create_lab_preview_then_apply(lab_api: respx.MockRouter) -> None:
    route = lab_api.post("/labs").mock(
        return_value=httpx.Response(
            200, json={"id": "abc", "lab_title": "mcp-test-x", "state": "DEFINED_ON_CORE"}
        )
    )
    preview, applied = await preview_apply("cml_create_lab", {"title": "mcp-test-x", "description": "d"})
    assert preview["status"] == "preview" and preview["preview"] == {
        "title": "mcp-test-x",
        "description": "d",
    }
    assert applied["status"] == "applied" and applied["result"]["id"] == "abc"
    assert json.loads(route.calls.last.request.content) == {"title": "mcp-test-x", "description": "d"}


async def test_create_lab_blocks_duplicate_title(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply("cml_create_lab", {"title": "mcp-test-probe"})
    assert preview["status"] == "blocked" and "already exists" in preview["blockers"][0]


async def test_import_lab_checks_definitions_and_posts_yaml(lab_api: respx.MockRouter) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new", "warnings": []}))
    yaml_text = "lab: {title: x}\nnodes:\n  - {id: n0, label: a, node_definition: iol-xe}\nlinks: []\n"
    preview, applied = await preview_apply(
        "cml_import_lab", {"topology_yaml": yaml_text, "title": "mcp-test-imp"}
    )
    assert preview["preview"]["node_definitions"] == {"iol-xe": 1}
    assert applied["result"]["id"] == "new"
    req = route.calls.last.request
    assert req.url.params["title"] == "mcp-test-imp" and req.content.decode() == yaml_text
    bad = yaml_text.replace("iol-xe", "made-up")
    preview, _ = await preview_apply("cml_import_lab", {"topology_yaml": bad, "title": "mcp-test-imp"})
    assert preview["status"] == "blocked" and "made-up" in preview["blockers"][0]


async def test_build_lab_preview_shows_wiring(lab_api: respx.MockRouter) -> None:
    route = lab_api.post("/import").mock(
        return_value=httpx.Response(200, json={"id": "built", "warnings": []})
    )
    args = {
        "title": "mcp-test-built",
        "nodes": [{"label": "r1", "definition": "iol-xe"}, {"label": "r2", "definition": "iol-xe"}],
        "links": ["r1 r2"],
    }
    preview, applied = await preview_apply("cml_build_lab", args)
    assert preview["preview"]["links"] == ["r1:Ethernet0/0<->r2:Ethernet0/0"]
    assert applied["result"]["id"] == "built"
    assert "node_definition: iol-xe" in route.calls.last.request.content.decode()


async def test_build_lab_blocked_on_bad_spec(lab_api: respx.MockRouter) -> None:
    args = {"title": "mcp-test-b", "nodes": [{"label": "r1", "definition": "nope"}], "links": []}
    preview, _ = await preview_apply("cml_build_lab", args)
    assert preview["status"] == "blocked" and "unknown node definition" in preview["blockers"][0]


async def test_start_lab_waits_for_convergence(lab_api: respx.MockRouter) -> None:
    start = lab_api.put(f"/labs/{LID}/start").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_start_lab", {"lab": LID})
    assert "0 of 2 nodes to start" in preview["action"]
    assert start.called and applied["result"]["converged"] is True


async def test_start_lab_requires_exact_title(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool("cml_start_lab", {"lab": "probe"}, raise_on_error=False)
    assert res.is_error and "No lab named 'probe'" in res.content[0].text


async def test_stop_lab_polls_state(lab_api: respx.MockRouter) -> None:
    lab_api.put(f"/labs/{LID}/stop").mock(return_value=httpx.Response(204))
    lab_api.get(f"/labs/{LID}/state").mock(return_value=httpx.Response(200, json="STOPPED"))
    _, applied = await preview_apply("cml_stop_lab", {"lab": LID})
    assert applied["result"] == {"state": "STOPPED"}


async def test_set_node_config_blocked_while_booted(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "configuration": "hostname x"}
    )
    assert preview["status"] == "blocked" and "DEFINED_ON_CORE" in preview["blockers"][0]
    assert "-hostname r1" in preview["preview"]["diff"] and "+hostname x" in preview["preview"]["diff"]


async def test_set_node_config_applies_main_file(lab_api: respx.MockRouter) -> None:
    wiped = [dict(n, state="DEFINED_ON_CORE") for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=wiped))
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=R1))
    _, applied = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "configuration": "hostname x"}
    )
    assert applied["status"] == "applied"
    assert json.loads(patch.calls.last.request.content) == {
        "configuration": [{"name": "Main", "content": "hostname x"}]
    }


async def test_update_node_changes_only_what_differs(lab_api: respx.MockRouter) -> None:
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=httpx.Response(200, json=R2))
    preview, _ = await preview_apply(
        "cml_update_node", {"lab": LID, "node": "r2", "tags": ["core"], "x": 200}
    )
    assert preview["preview"]["changes"] == {"tags": {"from": [], "to": ["core"]}}
    assert json.loads(patch.calls.last.request.content) == {"tags": ["core"]}
    blocked, _ = await preview_apply("cml_update_node", {"lab": LID, "node": "r2", "ram": 2048})
    assert blocked["status"] == "blocked"


async def test_connect_nodes_picks_first_free_interfaces(lab_api: respx.MockRouter) -> None:
    route = lab_api.post(f"/labs/{LID}/links").mock(return_value=httpx.Response(200, json={"id": "newlink"}))
    preview, applied = await preview_apply("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"})
    assert preview["action"] == "Connect r1:Ethernet0/1 <-> r2:Ethernet0/1"
    body = json.loads(route.calls.last.request.content)
    ifaces = {i["id"]: i for i in fixture("interfaces.json")}
    assert ifaces[body["src_int"]]["label"] == "Ethernet0/1" and ifaces[body["src_int"]]["node"] == R1
    assert applied["result"]["id"] == "newlink"


async def test_connect_nodes_rejects_used_interface(lab_api: respx.MockRouter) -> None:
    args = {"lab": LID, "node_a": "r1", "node_b": "r2", "interface_a": "Ethernet0/0"}
    preview, _ = await preview_apply("cml_connect_nodes", args)
    assert preview["status"] == "blocked" and "already connected to r2:Ethernet0/0" in preview["blockers"][0]


async def test_connect_nodes_creates_interface_on_wiped_node(lab_api: respx.MockRouter) -> None:
    ifaces = [i for i in fixture("interfaces.json") if i["node"] != R2 or i["label"] == "Ethernet0/0"]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=ifaces))
    wiped = [dict(n, state="DEFINED_ON_CORE") for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=wiped))
    new_iface = lab_api.post(f"/labs/{LID}/interfaces").mock(
        return_value=httpx.Response(200, json={"id": "11111111-1111-4111-8111-111111111111"})
    )
    links = lab_api.post(f"/labs/{LID}/links").mock(return_value=httpx.Response(200, json={"id": "l2"}))
    preview, _ = await preview_apply("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"})
    assert preview["preview"]["b"] == "r2:(new interface)"
    assert json.loads(new_iface.calls.last.request.content) == {"node": R2}
    assert json.loads(links.calls.last.request.content)["dst_int"] == "11111111-1111-4111-8111-111111111111"


def _ftd_lab(lab_api: respx.MockRouter, state: str, iface_state: str) -> None:
    """r2 becomes an FTDv in `state`; its interfaces report `iface_state` (synthetic payloads)."""
    nodes = [dict(n, node_definition="ftdv", state=state) if n["id"] == R2 else n for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=nodes))
    ifaces = [dict(i, state=iface_state) if i["node"] == R2 else i for i in fixture("interfaces.json")]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=ifaces))
    lab_api.post(f"/labs/{LID}/links").mock(return_value=httpx.Response(200, json={"id": "l3"}))


async def test_connect_nodes_warns_on_booted_ftdv(lab_api: respx.MockRouter) -> None:
    _ftd_lab(lab_api, "BOOTED", "STOPPED")  # booted before, a free interface that never came up
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"}))
    assert preview["status"] == "preview"
    (warning,) = preview["side_effects"]
    assert warning.startswith("this link stays down until the node is wiped (cml_wipe_node; day-0 survives)")
    assert "'r2'" in warning


async def test_connect_nodes_no_warning_for_wiped_ftdv(lab_api: respx.MockRouter) -> None:
    _ftd_lab(lab_api, "DEFINED_ON_CORE", "DEFINED_ON_CORE")
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"}))
    assert preview["status"] == "preview" and "side_effects" not in preview


async def test_connect_nodes_no_warning_for_booted_iol(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(**RW))) as c:  # fixture: two BOOTED iol-xe routers
        preview = data(await c.call_tool("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"}))
    assert preview["status"] == "preview" and "side_effects" not in preview


FTD_LABELS = ["Management0/0", "donotuse1", "GigabitEthernet0/0", "GigabitEthernet0/1"]


def _ftd_ports(lab_api: respx.MockRouter, state: str, labels: list[str]) -> None:
    """r2 becomes an FTDv in `state` whose physical slots carry `labels` (synthetic, shaped like CML's
    FTDv list: Management0/0, the 'donotuse1' placeholder, then GigabitEthernet0/x). Slot 0 keeps the
    fixture's link to r1, so Management0/0 is taken."""
    nodes = [dict(n, node_definition="ftdv", state=state) if n["id"] == R2 else n for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=nodes))
    others = [i for i in fixture("interfaces.json") if i["node"] != R2]
    r2 = sorted(
        (i for i in fixture("interfaces.json") if i["node"] == R2 and i["type"] == "physical"),
        key=lambda i: i["slot"],
    )
    ftd = [dict(i, label=label, state=state) for i, label in zip(r2, labels, strict=False)]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=others + ftd))
    lab_api.post(f"/labs/{LID}/links").mock(return_value=httpx.Response(200, json={"id": "l4"}))


async def test_connect_nodes_skips_ftdv_donotuse(lab_api: respx.MockRouter) -> None:
    _ftd_ports(lab_api, "DEFINED_ON_CORE", FTD_LABELS)
    links = lab_api.post(f"/labs/{LID}/links").mock(return_value=httpx.Response(200, json={"id": "l4"}))
    preview, applied = await preview_apply("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"})
    assert preview["action"] == "Connect r1:Ethernet0/1 <-> r2:GigabitEthernet0/0"
    dst = json.loads(links.calls.last.request.content)["dst_int"]
    r2 = sorted(
        (i for i in fixture("interfaces.json") if i["node"] == R2 and i["type"] == "physical"),
        key=lambda i: i["slot"],
    )
    assert dst == r2[2]["id"] and applied["status"] == "applied"


async def test_connect_nodes_blocks_when_only_donotuse_free_on_booted_ftdv(lab_api: respx.MockRouter) -> None:
    _ftd_ports(lab_api, "BOOTED", FTD_LABELS[:2])
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"}))
    assert preview["status"] == "blocked"
    (blocker,) = preview["blockers"]
    assert "r2 has no free interface (only placeholder slots are free: donotuse1" in blocker
    assert "cml_wipe_node" in blocker


async def test_connect_nodes_adds_interface_when_only_donotuse_free_on_wiped_ftdv(
    lab_api: respx.MockRouter,
) -> None:
    _ftd_ports(lab_api, "DEFINED_ON_CORE", FTD_LABELS[:2])
    new_iface = lab_api.post(f"/labs/{LID}/interfaces").mock(
        return_value=httpx.Response(200, json={"id": "22222222-2222-4222-8222-222222222222"})
    )
    links = lab_api.post(f"/labs/{LID}/links").mock(return_value=httpx.Response(200, json={"id": "l5"}))
    preview, _ = await preview_apply("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"})
    assert preview["preview"]["b"] == "r2:(new interface)"
    assert json.loads(new_iface.calls.last.request.content) == {"node": R2}
    assert json.loads(links.calls.last.request.content)["dst_int"] == "22222222-2222-4222-8222-222222222222"


async def test_connect_nodes_blocks_named_donotuse(lab_api: respx.MockRouter) -> None:
    _ftd_ports(lab_api, "DEFINED_ON_CORE", FTD_LABELS)
    args = {"lab": LID, "node_a": "r1", "node_b": "r2", "interface_b": "donotuse1"}
    preview, _ = await preview_apply("cml_connect_nodes", args)
    assert preview["status"] == "blocked"
    assert "r2:donotuse1 is a placeholder slot that never carries traffic" in preview["blockers"][0]


def test_late_link_warning_rules() -> None:
    ftd = {"label": "fw", "node_definition": "ftdv", "state": "STOPPED"}
    assert late_link_warning(ftd, None)  # a new interface on a booted-before FTDv
    assert late_link_warning(ftd, {"state": "STOPPED"})
    assert late_link_warning(dict(ftd, state="BOOTED"), {"state": "DEFINED_ON_CORE"})
    assert late_link_warning(dict(ftd, state="BOOTED"), {"state": "STARTED"}) is None  # bound at boot
    assert late_link_warning(dict(ftd, state="DEFINED_ON_CORE"), None) is None
    assert late_link_warning({"label": "r", "node_definition": "iol-xe", "state": "BOOTED"}, None) is None


async def test_link_condition_set_and_clear(lab_api: respx.MockRouter) -> None:
    patch = lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=httpx.Response(200, json={"latency": 50, "enabled": True})
    )
    delete = lab_api.delete(f"/labs/{LID}/links/{LINK}/condition").mock(return_value=httpx.Response(204))
    _, applied = await preview_apply(
        "cml_set_link_condition", {"lab": LID, "link": "r1<->r2", "latency_ms": 50}
    )
    sent = json.loads(patch.calls.last.request.content)
    assert sent["latency"] == 50 and sent["enabled"] is True and sent["loss"] is None  # others reset
    assert applied["result"] == {"latency": 50, "enabled": True}
    await preview_apply("cml_set_link_condition", {"lab": LID, "link": "r1<->r2", "clear": True})
    assert delete.called
    blocked, _ = await preview_apply("cml_set_link_condition", {"lab": LID, "link": "r1<->r2"})
    assert blocked["status"] == "blocked"


async def test_capture_start_blocked_when_running(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply("cml_start_capture", {"lab": LID, "link": LINK})
    assert preview["status"] == "blocked" and "already running" in preview["blockers"][0]
    stop = lab_api.put(f"/labs/{LID}/links/{LINK}/capture/stop").mock(return_value=httpx.Response(204))
    await preview_apply("cml_stop_capture", {"lab": LID, "link": LINK})
    assert stop.called


async def test_confirm_token_refused_when_node_changed(lab_api: respx.MockRouter) -> None:
    lab_api.put(f"/labs/{LID}/nodes/{R1}/state/stop").mock(return_value=httpx.Response(204))
    args = {"lab": LID, "node": "r1", "state": "stop", "wait": False}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_set_node_state", args))
        stopped = [dict(n, state="STOPPED") if n["id"] == R1 else n for n in NODES]
        lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=stopped))
        res = await c.call_tool(
            "cml_set_node_state", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    assert res.is_error and "changed since the preview" in res.content[0].text


async def test_link_condition_preview_lists_reset_impairments(lab_api: respx.MockRouter) -> None:
    """Core 0.12.4 replace=True: omitted impairments are reset by the PATCH, so the preview lists them."""
    lab_api.get(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=httpx.Response(
            200, json={"latency": 100, "loss": 2.0, "enabled": True, "operational": {}}
        )
    )
    lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(return_value=httpx.Response(200, json={}))
    preview, _ = await preview_apply(
        "cml_set_link_condition", {"lab": LID, "link": "r1<->r2", "latency_ms": 50}
    )
    assert preview["preview"]["changes"] == {
        "latency": {"from": 100, "to": 50},
        "loss": {"from": 2.0, "to": None, "removed": True},
    }


def test_condition_changes_clear_and_unconditioned() -> None:
    from cml_mcp.scenarios import condition_changes

    cur = {"latency": 100, "enabled": True, "link_id": "x"}
    assert condition_changes(cur, {}) == {
        "latency": {"from": 100, "to": None, "removed": True},
        "enabled": {"from": True, "to": None, "removed": True},
    }
    assert condition_changes({}, {"latency": 5, "loss": None, "enabled": True}) == {
        "latency": {"from": None, "to": 5},
        "enabled": {"from": None, "to": True},
    }
