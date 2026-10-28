"""L52: one-sided interface up/down, interface MAC pinning, and `macs` in the build spec.

Payload shapes from the bundled CML OpenAPI spec:
PUT /labs/{lab_id}/interfaces/{interface_id}/state/start|stop (no body, no response body), and
PATCH /labs/{lab_id}/interfaces/{interface_id} with InterfaceUpdate {"mac_address": <MAC or null>}
returning InterfaceResponse. The spec says nothing about the node
state a MAC change needs; the live proof records whether CML refuses it on a running node.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp.build import BuildError, NodeSpec, build_topology
from cml_mcp.macs import mac_problem, normalise_mac
from cml_mcp.server import create_server

from .conftest import LID, NODES, R1, fixture, make_settings
from .test_write_tools import RW, data, preview_apply

IFACES = fixture("interfaces.json")
R1_E00 = "a5719a70-f658-4dd3-98c7-2f4c5355b6e7"  # wired to r2:Ethernet0/0
R1_E01 = "eab0a18c-1398-4aa6-a2f2-fc3f6ddfd9d9"  # free
DEFS = {d["id"]: d for d in fixture("simplified_node_definitions.json")}


def iface(iid: str, **changes: Any) -> dict[str, Any]:
    return next(i for i in IFACES if i["id"] == iid) | changes


def with_node_state(api: respx.MockRouter, state: str) -> None:
    nodes = [n | {"state": state} if n["id"] == R1 else n for n in NODES]
    api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=nodes))


async def test_tools_are_write_tier(lab_api: respx.MockRouter) -> None:
    async def names(**kw: Any) -> set[str]:
        async with Client(create_server(make_settings(**kw))) as c:
            return {t.name for t in await c.list_tools()}

    ro, rw = await names(), await names(**RW)
    for tool in ("cml_set_interface_state", "cml_update_interface"):
        assert tool not in ro and tool in rw


async def test_interface_down_is_one_sided(lab_api: respx.MockRouter) -> None:
    stop = lab_api.put(f"/labs/{LID}/interfaces/{R1_E00}/state/stop").mock(return_value=httpx.Response(204))
    lab_api.get(f"/labs/{LID}/interfaces/{R1_E00}").mock(
        return_value=httpx.Response(200, json=iface(R1_E00, state="STOPPED"))
    )
    args = {"lab": LID, "node": "r1", "interface": "ethernet0/0", "state": "down"}
    preview, applied = await preview_apply("cml_set_interface_state", args)
    assert preview["status"] == "preview"
    assert preview["action"] == "Bring interface r1:Ethernet0/0 down (currently STARTED)"
    assert preview["preview"]["peer"] == "r2:Ethernet0/0"
    assert any("peer r2:Ethernet0/0 stays up" in s for s in preview["side_effects"])
    assert stop.called and stop.calls.last.request.content == b""
    assert applied["result"] == {"interface": "r1:Ethernet0/0", "state": "STOPPED", "peer": "r2:Ethernet0/0"}


async def test_interface_up_by_id(lab_api: respx.MockRouter) -> None:
    stopped = [i | {"state": "STOPPED"} if i["id"] == R1_E00 else i for i in IFACES]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=stopped))
    start = lab_api.put(f"/labs/{LID}/interfaces/{R1_E00}/state/start").mock(return_value=httpx.Response(204))
    lab_api.get(f"/labs/{LID}/interfaces/{R1_E00}").mock(return_value=httpx.Response(200, json=iface(R1_E00)))
    _, applied = await preview_apply(
        "cml_set_interface_state", {"lab": LID, "node": R1, "interface": R1_E00, "state": "up"}
    )
    assert start.called and applied["result"]["state"] == "STARTED"


@pytest.mark.parametrize(
    ("node_state", "interface", "message"),
    [
        ("STOPPED", "Ethernet0/0", "only go up/down on a running node"),
        ("DEFINED_ON_CORE", "Ethernet0/0", "only go up/down on a running node"),
        ("BOOTED", "Loopback0", "is a loopback"),
    ],
)
async def test_interface_state_blockers(
    lab_api: respx.MockRouter, node_state: str, interface: str, message: str
) -> None:
    with_node_state(lab_api, node_state)
    preview, _ = await preview_apply(
        "cml_set_interface_state", {"lab": LID, "node": "r1", "interface": interface, "state": "down"}
    )
    assert preview["status"] == "blocked" and any(message in b for b in preview["blockers"])


async def test_unknown_interface_lists_names(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool(
            "cml_set_interface_state",
            {"lab": LID, "node": "r1", "interface": "Gi9", "state": "down"},
            raise_on_error=False,
        )
    assert res.is_error and "r1 has no interface 'Gi9'" in res.content[0].text
    assert "Ethernet0/0" in res.content[0].text


async def test_mac_pin_on_wiped_node(lab_api: respx.MockRouter) -> None:
    with_node_state(lab_api, "DEFINED_ON_CORE")
    patch = lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(
        return_value=httpx.Response(200, json=iface(R1_E01, mac_address="52:54:00:00:01:01"))
    )
    args = {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "5254.0000.0101"}
    preview, applied = await preview_apply("cml_update_interface", args)
    assert preview["status"] == "preview"
    assert preview["preview"]["old_mac"] == "aa:bb:cc:00:02:10"
    assert preview["preview"]["new_mac"] == "52:54:00:00:01:01"
    effects = " ".join(preview["side_effects"])
    assert "aa:bb:cc:00:02:10" in effects and "ISE endpoints" in effects and "DHCP" in effects
    assert "keeps its current MAC" not in effects  # wiped node: no running-node warning
    assert json.loads(patch.calls.last.request.content) == {"mac_address": "52:54:00:00:01:01"}
    assert applied["result"] == {
        "interface": "r1:Ethernet0/1",
        "old_mac": "aa:bb:cc:00:02:10",
        "mac_address": "52:54:00:00:01:01",
    }


async def test_mac_pin_on_running_node_warns_and_explains_refusal(lab_api: respx.MockRouter) -> None:
    lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(
        return_value=httpx.Response(400, json={"code": 400, "description": "Node must be wiped"})
    )
    args = {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "52:54:00:00:01:01"}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_update_interface", args))
        assert preview["status"] == "preview"
        assert any("Node is BOOTED" in s and "wiped" in s for s in preview["side_effects"])
        res = await c.call_tool(
            "cml_update_interface", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    assert res.is_error and "DEFINED_ON_CORE" in res.content[0].text


async def test_mac_auto_clears_pin(lab_api: respx.MockRouter) -> None:
    with_node_state(lab_api, "DEFINED_ON_CORE")
    pinned = [i | {"mac_address": "52:54:00:00:01:01"} if i["id"] == R1_E01 else i for i in IFACES]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=pinned))
    patch = lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(
        return_value=httpx.Response(200, json=iface(R1_E01))
    )
    _, applied = await preview_apply(
        "cml_update_interface", {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "auto"}
    )
    assert json.loads(patch.calls.last.request.content) == {"mac_address": None}
    assert applied["result"]["old_mac"] == "52:54:00:00:01:01"


@pytest.mark.parametrize(
    ("interface", "mac", "message"),
    [
        ("Ethernet0/1", "aa:bb:cc:00:09:09", "outside 52:54:00"),
        ("Ethernet0/1", "52:54:00:zz:00:00", "not a MAC address"),
        ("Ethernet0/1", "aa:bb:cc:00:03:00", "outside 52:54:00"),
        ("Loopback0", "52:54:00:00:01:01", "is a loopback"),
    ],
)
async def test_mac_blockers(lab_api: respx.MockRouter, interface: str, mac: str, message: str) -> None:
    preview, _ = await preview_apply(
        "cml_update_interface", {"lab": LID, "node": "r1", "interface": interface, "mac_address": mac}
    )
    assert preview["status"] == "blocked" and any(message in b for b in preview["blockers"])


async def test_mac_clash_in_lab_blocks(lab_api: respx.MockRouter) -> None:
    taken = [i | {"mac_address": "52:54:00:00:03:00"} if i["label"] == "Ethernet0/0" else i for i in IFACES]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=taken))
    preview, _ = await preview_apply(
        "cml_update_interface",
        {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "52:54:00:00:03:00"},
    )
    assert preview["status"] == "blocked" and "already used in this lab by" in preview["blockers"][0]


def test_normalise_mac_forms() -> None:
    for raw in ("52:54:00:AB:CD:EF", "52-54-00-ab-cd-ef", "5254.00ab.cdef", "525400abcdef"):
        assert normalise_mac(raw) == "52:54:00:ab:cd:ef"
    assert mac_problem("52:54:00:ab:cd:ef") is None
    with pytest.raises(ValueError):
        normalise_mac("52:54:00:ab:cd")


def test_build_pins_macs_and_emits_the_interface() -> None:
    nodes = [
        NodeSpec(label="r1", definition="iol-xe", macs={"Ethernet1/0": "52-54-00-00-10-00"}),
        NodeSpec(label="r2", definition="iol-xe"),
    ]
    topo, _ = build_topology("t", nodes, ["r1 r2"], DEFS)
    r1 = {i["label"]: i for i in topo["nodes"][0]["interfaces"]}
    # Ethernet1/0 is past the default four, but a pinned MAC makes it exist
    assert r1["Ethernet1/0"]["mac_address"] == "52:54:00:00:10:00"
    assert "mac_address" not in r1["Ethernet0/0"]
    assert all("mac_address" not in i for i in topo["nodes"][1]["interfaces"])


@pytest.mark.parametrize(
    ("macs", "message"),
    [
        ({"r1": {"Gi9": "52:54:00:00:00:01"}}, "not a physical interface"),
        ({"r1": {"Ethernet0/0": "aa:bb:cc:00:00:01"}}, "outside 52:54:00"),
        (
            {"r1": {"Ethernet0/0": "52:54:00:00:00:01"}, "r2": {"Ethernet0/1": "52:54:00:00:00:01"}},
            "also given",
        ),
    ],
)
def test_build_rejects_bad_macs(macs: dict[str, dict[str, str]], message: str) -> None:
    nodes = [NodeSpec(label=lab, definition="iol-xe", macs=macs.get(lab, {})) for lab in ("r1", "r2")]
    with pytest.raises(BuildError, match=message):
        build_topology("t", nodes, [], DEFS)
