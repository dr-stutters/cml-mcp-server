"""C81 (core #157): every write names its back-out step.

The preview carries `undo: 'back-out: <tool>(<args>)'` (or a text), the applied result carries
`undo: {tool, args, back_out}` with the arguments filled in from the apply result (or `{back_out}` for a
text step). Payload shapes are the recorded fixtures of the 'mcp-test-probe' lab (conftest.lab_api).
"""

import warnings
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp._core.testing import UndoWarning, undo_problems
from cml_mcp.server import create_server
from cml_mcp.undo import condition_undo, replayable

from .conftest import LID, LINK, NODES, R1, R2, fixture, make_settings
from .test_write_tools import RW, RWD, preview_apply

R1_E00 = "a5719a70-f658-4dd3-98c7-2f4c5355b6e7"  # wired to r2:Ethernet0/0 (the probe lab's link)


def ok(data: Any) -> httpx.Response:
    return httpx.Response(200, json=data)


def wiped_nodes(api: respx.MockRouter) -> None:
    api.get(f"/labs/{LID}/nodes").mock(return_value=ok([dict(n, state="DEFINED_ON_CORE") for n in NODES]))


async def preview_only(name: str, args: dict[str, Any], **settings: Any) -> dict[str, Any]:
    async with Client(create_server(make_settings(**(settings or RW)))) as c:
        res = await c.call_tool(name, args)
    return dict(res.structured_content or {})


def assert_undo(preview: dict[str, Any], applied: dict[str, Any], tool: str, args: dict[str, Any]) -> None:
    assert preview["status"] == "preview", preview
    assert preview["undo"].startswith(f"back-out: {tool}(")
    assert applied["status"] == "applied", applied
    assert applied["undo"]["tool"] == tool
    assert applied["undo"]["args"] == args
    assert applied["undo"]["back_out"].startswith(f"{tool}(")


def assert_text_undo(preview: dict[str, Any], *words: str) -> str:
    assert preview["status"] == "preview", preview
    text = preview["undo"]
    assert text.startswith("back-out: ")
    for w in words:
        assert w in text, text
    return str(text)


# --- the contract: no cml write tool is left without a back-out step ------------------------------------


@pytest.mark.parametrize("kw", [RW, RWD])
async def test_no_write_tool_lacks_undo(api: respx.MockRouter, kw: dict[str, Any]) -> None:
    server = create_server(make_settings(**kw))
    # cml_api_call is the core's raw call: its reverse depends on the endpoint and method
    assert undo_problems(server, "cml", allow={"cml_api_call"}) == []
    from cml_mcp._core.testing import assert_tool_contract

    with warnings.catch_warnings():
        warnings.simplefilter("error", UndoWarning)
        await assert_tool_contract(server, "cml", undo_allow={"cml_api_call"})


# --- topology writes ------------------------------------------------------------------------------------


async def test_add_node_undo_deletes_the_new_node(lab_api: respx.MockRouter) -> None:
    lab_api.post(f"/labs/{LID}/nodes").mock(return_value=ok({"id": "n-new"}))
    preview, applied = await preview_apply(
        "cml_add_node", {"lab": LID, "definition": "iol-xe", "label": "r3"}
    )
    assert preview["undo"] == f'back-out: cml_delete_node(lab="{LID}", node=<from the result: id>)'
    assert_undo(preview, applied, "cml_delete_node", {"lab": LID, "node": "n-new"})


async def test_connect_nodes_undo_deletes_the_new_link(lab_api: respx.MockRouter) -> None:
    lab_api.post(f"/labs/{LID}/links").mock(return_value=ok({"id": "newlink"}))
    preview, applied = await preview_apply("cml_connect_nodes", {"lab": LID, "node_a": "r1", "node_b": "r2"})
    assert "link=<from the result: id>" in preview["undo"]
    assert_undo(preview, applied, "cml_delete_link", {"lab": LID, "link": "newlink"})


async def test_update_node_undo_restores_previous_values(lab_api: respx.MockRouter) -> None:
    lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=ok(R2))
    preview, applied = await preview_apply("cml_update_node", {"lab": LID, "node": "r2", "tags": ["core"]})
    assert_undo(preview, applied, "cml_update_node", {"lab": LID, "node": R2, "tags": []})


async def test_update_node_undo_never_repeats_a_password(lab_api: respx.MockRouter) -> None:
    lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=ok(R2))
    preview, applied = await preview_apply(
        "cml_update_node", {"lab": LID, "node": "r2", "login_password": "Fake-New-Pw9"}
    )
    text = assert_text_undo(preview, "cml_update_node", "login_password back to the old value (not shown)")
    assert "Fake-New-Pw9" not in text
    assert applied["undo"] == {"back_out": text.removeprefix("back-out: ")}


async def test_set_node_config_undo_restores_previous_day0(lab_api: respx.MockRouter) -> None:
    wiped_nodes(lab_api)
    lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=ok(R1))
    previous = fixture("node_configs.json")[0]["configuration"][0]["content"]
    preview, applied = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "configuration": "hostname x"}
    )
    assert_undo(preview, applied, "cml_set_node_config", {"lab": LID, "node": R1, "configuration": previous})


async def test_set_node_config_undo_with_secrets_is_a_text(lab_api: respx.MockRouter) -> None:
    secret = "hostname r1\nenable secret 9 $9$fakehash\n"
    nodes = [dict(n, state="DEFINED_ON_CORE") for n in fixture("node_configs.json")]
    nodes[0]["configuration"] = [{"name": "ios_config.txt", "content": secret}]
    lab_api.get(f"/labs/{LID}/nodes/{R1}").mock(return_value=ok(nodes[0]))
    wiped_nodes(lab_api)
    lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=ok(R1))
    preview, _ = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "configuration": "hostname x"}
    )
    text = assert_text_undo(preview, "cml_set_node_config", "holds secrets")
    assert "fakehash" not in text


async def test_node_state_undo_is_the_opposite_state(lab_api: respx.MockRouter) -> None:
    lab_api.put(f"/labs/{LID}/nodes/{R1}/state/stop").mock(return_value=httpx.Response(204))
    lab_api.get(f"/labs/{LID}/nodes/{R1}/state").mock(return_value=ok({"state": "STOPPED"}))
    preview, applied = await preview_apply("cml_set_node_state", {"lab": LID, "node": "r1", "state": "stop"})
    assert_undo(preview, applied, "cml_set_node_state", {"lab": LID, "node": R1, "state": "start"})


async def test_node_state_noop_has_nothing_to_back_out(lab_api: respx.MockRouter) -> None:
    preview = await preview_only("cml_set_node_state", {"lab": LID, "node": "r1", "state": "start"})
    assert_text_undo(preview, "nothing to back out", "BOOTED")


async def test_link_state_undo_is_the_opposite_state(lab_api: respx.MockRouter) -> None:
    lab_api.put(f"/labs/{LID}/links/{LINK}/state/stop").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply(
        "cml_set_link_state", {"lab": LID, "link": "r1<->r2", "state": "down"}
    )
    assert_undo(preview, applied, "cml_set_link_state", {"lab": LID, "link": LINK, "state": "up"})


async def test_link_condition_undo_clears_when_there_was_none(lab_api: respx.MockRouter) -> None:
    lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=ok({"latency": 50, "enabled": True})
    )
    preview, applied = await preview_apply(
        "cml_set_link_condition", {"lab": LID, "link": "r1<->r2", "latency_ms": 50}
    )
    assert_undo(preview, applied, "cml_clear_link_scenarios", {"lab": LID, "link": LINK})


async def test_link_condition_undo_restores_previous_values(lab_api: respx.MockRouter) -> None:
    before = fixture("link_condition.json") | {"latency": 20, "loss": 1.5, "enabled": True}
    lab_api.get(f"/labs/{LID}/links/{LINK}/condition").mock(return_value=ok(before))
    lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=ok({"latency": 200, "enabled": True})
    )
    preview, applied = await preview_apply(
        "cml_set_link_condition", {"lab": LID, "link": "r1<->r2", "latency_ms": 200}
    )
    assert_undo(
        preview,
        applied,
        "cml_set_link_condition",
        {"lab": LID, "link": LINK, "latency_ms": 20, "loss_pct": 1.5},
    )


def test_condition_undo_ignores_a_disabled_condition() -> None:
    undo = condition_undo(LID, LINK, {"latency": 20, "enabled": False})
    assert undo.tool == "cml_clear_link_scenarios"


async def test_start_capture_undo_stops_it(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/labs/{LID}/links/{LINK}/capture/status").mock(return_value=ok({}))
    lab_api.put(f"/labs/{LID}/links/{LINK}/capture/start").mock(return_value=ok({"starttime": "t"}))
    preview, applied = await preview_apply("cml_start_capture", {"lab": LID, "link": "r1<->r2"})
    assert_undo(preview, applied, "cml_stop_capture", {"lab": LID, "link": LINK})


async def test_interface_state_undo_is_the_opposite_state(lab_api: respx.MockRouter) -> None:
    lab_api.put(f"/labs/{LID}/interfaces/{R1_E00}/state/stop").mock(return_value=httpx.Response(204))
    iface = next(i for i in fixture("interfaces.json") if i["id"] == R1_E00)
    lab_api.get(f"/labs/{LID}/interfaces/{R1_E00}").mock(return_value=ok(iface | {"state": "STOPPED"}))
    args = {"lab": LID, "node": "r1", "interface": "Ethernet0/0", "state": "down"}
    preview, applied = await preview_apply("cml_set_interface_state", args)
    assert_undo(
        preview,
        applied,
        "cml_set_interface_state",
        {"lab": LID, "node": R1, "interface": R1_E00, "state": "up"},
    )


async def test_link_scenario_undo_restores_conditioning(lab_api: respx.MockRouter) -> None:
    lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=ok({"latency": 300, "enabled": True})
    )
    preview, applied = await preview_apply(
        "cml_apply_link_scenario", {"lab": LID, "link": "r1<->r2", "scenario": "wan-satellite"}
    )
    assert_undo(preview, applied, "cml_clear_link_scenarios", {"lab": LID, "link": LINK})


# --- lab writes -----------------------------------------------------------------------------------------


async def test_create_lab_undo_deletes_it(lab_api: respx.MockRouter) -> None:
    lab_api.post("/labs").mock(
        return_value=ok({"id": "abc", "lab_title": "mcp-test-x", "state": "DEFINED_ON_CORE"})
    )
    preview, applied = await preview_apply("cml_create_lab", {"title": "mcp-test-x"})
    assert preview["undo"] == "back-out: cml_delete_lab(lab=<from the result: id>)"
    assert_undo(preview, applied, "cml_delete_lab", {"lab": "abc"})


async def test_build_and_start_undo_deletes_with_force(lab_api: respx.MockRouter) -> None:
    lab_api.post("/import").mock(return_value=ok({"id": "built", "warnings": []}))
    lab_api.get("/nodes").mock(return_value=ok([]))  # licence use across labs
    lab_api.put("/labs/built/start").mock(return_value=httpx.Response(204))
    args = {
        "title": "mcp-test-built",
        "nodes": [{"label": "r1", "definition": "iol-xe"}],
        "start": True,
        "wait": False,
    }
    preview, applied = await preview_apply("cml_build_lab", args)
    assert_undo(preview, applied, "cml_delete_lab", {"lab": "built", "force": True})


async def test_start_lab_undo_stops_it(lab_api: respx.MockRouter) -> None:
    stopped = [dict(n, state="STOPPED") for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=ok(stopped))
    lab_api.get("/nodes").mock(return_value=ok([]))  # licence use across labs
    lab_api.put(f"/labs/{LID}/start").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_start_lab", {"lab": LID, "wait": False})
    assert_undo(preview, applied, "cml_stop_lab", {"lab": LID})


async def test_stop_lab_undo_starts_it(lab_api: respx.MockRouter) -> None:
    lab_api.put(f"/labs/{LID}/stop").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_stop_lab", {"lab": LID, "wait": False})
    assert_undo(preview, applied, "cml_start_lab", {"lab": LID})


async def test_extract_configs_is_not_reversible(lab_api: respx.MockRouter) -> None:
    preview = await preview_only("cml_extract_node_configs", {"lab": LID})
    assert_text_undo(preview, "not reversible", "cml_archive_lab")


# --- dangerous ------------------------------------------------------------------------------------------


async def test_delete_lab_says_not_reversible(lab_api: respx.MockRouter) -> None:
    states = iter(["STOPPED", "DEFINED_ON_CORE"])
    lab_api.get(f"/labs/{LID}/state").mock(side_effect=lambda r: ok(next(states)))
    lab_api.put(f"/labs/{LID}/stop").mock(return_value=httpx.Response(204))
    lab_api.put(f"/labs/{LID}/wipe").mock(return_value=httpx.Response(204))
    lab_api.delete(f"/labs/{LID}").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_delete_lab", {"lab": LID, "force": True}, **RWD)
    text = assert_text_undo(preview, "not reversible", "cml_archive_lab", "cml_import_lab")
    assert applied["undo"] == {"back_out": text.removeprefix("back-out: ")}


async def test_wipe_and_delete_node_say_not_reversible(lab_api: respx.MockRouter) -> None:
    preview = await preview_only("cml_wipe_node", {"lab": LID, "node": "r1", "force": True}, **RWD)
    assert_text_undo(preview, "not reversible", "cml_extract_node_configs", "cml_archive_lab")
    preview = await preview_only("cml_delete_node", {"lab": LID, "node": "r2", "force": True}, **RWD)
    assert_text_undo(preview, "not reversible", "cml_archive_lab", "cml_add_node")


async def test_delete_link_undo_reconnects_the_same_ends(lab_api: respx.MockRouter) -> None:
    lab_api.delete(f"/labs/{LID}/links/{LINK}").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_delete_link", {"lab": LID, "link": "r1<->r2"}, **RWD)
    assert_undo(
        preview,
        applied,
        "cml_connect_nodes",
        {
            "lab": LID,
            "node_a": R1,
            "node_b": R2,
            "interface_a": "Ethernet0/0",
            "interface_b": "Ethernet0/0",
        },
    )


# --- console --------------------------------------------------------------------------------------------


async def test_configure_node_back_out_text(lab_api: respx.MockRouter) -> None:
    preview = await preview_only(
        "cml_configure_node", {"lab": LID, "node": "r1", "lines": ["ip route 192.0.2.0 255.255.255.0 Null0"]}
    )
    assert_text_undo(preview, "'no <line>'", "cml_diff_node_config", "Not saved")
    preview = await preview_only(
        "cml_configure_node", {"lab": LID, "node": "r1", "lines": ["clear ip ospf process"], "mode": "exec"}
    )
    assert_text_undo(preview, "not reversible", "exec lines run once")


def test_replayable_spots_masked_values() -> None:
    assert replayable("cml_set_node_config", {"configuration": "hostname r1\n"})
    assert not replayable("cml_set_node_config", {"configuration": "enable secret 9 $9$x\n"})
    assert not replayable("cml_update_node", {"login_password": "x"})
