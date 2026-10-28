"""L52: one-sided interface up/down, interface MAC pinning, and `macs` in the build spec.

Payload shapes from the bundled CML OpenAPI spec:
PUT /labs/{lab_id}/interfaces/{interface_id}/state/start|stop (no body, no response body), and
PATCH /labs/{lab_id}/interfaces/{interface_id} with InterfaceUpdate {"mac_address": <MAC or null>}
returning InterfaceResponse. Live (CML 2.10, #95): the PATCH on a BOOTED node returns
400 'Physical configuration of node is locked', and an IOL node's import fails with 'cannot set custom
MAC address'. node_definition_alpine.json is GET /node_definitions/alpine as live (libvirt_domain_driver:
kvm, trimmed); node_definition_iol_xe.json is the recorded iol-xe one (libvirt_domain_driver: iol).
"""

import json
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from cml_mcp.build import BuildError, NodeSpec, build_topology
from cml_mcp.macs import custom_mac_problem, mac_problem, normalise_mac
from cml_mcp.server import create_server

from .conftest import LID, NODES, R1, fixture, make_settings
from .test_write_tools import RW, preview_apply

IFACES = fixture("interfaces.json")
R1_E00 = "a5719a70-f658-4dd3-98c7-2f4c5355b6e7"  # wired to r2:Ethernet0/0
R1_E01 = "eab0a18c-1398-4aa6-a2f2-fc3f6ddfd9d9"  # free
DEFS = {d["id"]: d for d in fixture("simplified_node_definitions.json")}


def iface(iid: str, **changes: Any) -> dict[str, Any]:
    return next(i for i in IFACES if i["id"] == iid) | changes


def with_node_state(api: respx.MockRouter, state: str, definition: str = "alpine") -> None:
    """r1 in `state`; by default made a KVM (alpine) node so a MAC pin is allowed."""
    nodes = [n | {"state": state, "node_definition": definition} if n["id"] == R1 else n for n in NODES]
    api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=nodes))
    api.get("/node_definitions/alpine").mock(
        return_value=httpx.Response(200, json=fixture("node_definition_alpine.json"))
    )


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


async def test_mac_pin_on_running_node_is_blocked(lab_api: respx.MockRouter) -> None:
    with_node_state(lab_api, "BOOTED")
    # what CML answers live on a BOOTED node; the preview must stop before it is ever sent
    patch = lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(
        return_value=httpx.Response(
            400, json={"code": 400, "description": "Physical configuration of node is locked"}
        )
    )
    args = {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "52:54:00:00:01:01"}
    preview, applied = await preview_apply("cml_update_interface", args)
    assert preview["status"] == "blocked" and applied is None
    assert any(
        "r1 is BOOTED" in b and "DEFINED_ON_CORE" in b and "cml_wipe_node" in b for b in preview["blockers"]
    )
    assert not patch.called


@pytest.mark.parametrize("state", ["STOPPED", "STARTED"])
async def test_mac_pin_blocked_unless_wiped(lab_api: respx.MockRouter, state: str) -> None:
    with_node_state(lab_api, state)
    preview, _ = await preview_apply(
        "cml_update_interface",
        {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "52:54:00:00:01:01"},
    )
    assert preview["status"] == "blocked" and any(f"is {state}" in b for b in preview["blockers"])


async def test_mac_pin_on_iol_node_is_blocked(lab_api: respx.MockRouter) -> None:
    with_node_state(lab_api, "DEFINED_ON_CORE", definition="iol-xe")  # recorded iol-xe definition
    patch = lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(return_value=httpx.Response(200, json={}))
    preview, _ = await preview_apply(
        "cml_update_interface",
        {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "52:54:00:00:01:01"},
    )
    assert preview["status"] == "blocked" and not patch.called
    assert any("iol-xe cannot take a pinned MAC" in b and "iol driver" in b for b in preview["blockers"])


async def test_mac_pin_on_docker_node_is_allowed(lab_api: respx.MockRouter) -> None:
    # GET /node_definitions/net-tools as live (trimmed): Docker driver, and CML 2.10's simplified
    # definition reports custom_mac: true for it, so the pin is not blocked
    docker = "id: net-tools\nsim:\n  linux_native:\n    driver: server\n    libvirt_domain_driver: docker\n"
    with_node_state(lab_api, "DEFINED_ON_CORE", definition="net-tools")
    lab_api.get("/node_definitions/net-tools").mock(return_value=httpx.Response(200, json=docker))
    patch = lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(
        return_value=httpx.Response(200, json=iface(R1_E01, mac_address="52:54:00:00:01:01"))
    )
    preview, _ = await preview_apply(
        "cml_update_interface",
        {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "52:54:00:00:01:01"},
    )
    assert preview["status"] == "preview" and patch.called
    assert custom_mac_problem("net-tools", DEFS["net-tools"]) is None


async def test_mac_clear_on_iol_node_is_not_blocked_by_driver(lab_api: respx.MockRouter) -> None:
    with_node_state(lab_api, "DEFINED_ON_CORE", definition="iol-xe")
    pinned = [i | {"mac_address": "52:54:00:00:01:01"} if i["id"] == R1_E01 else i for i in IFACES]
    lab_api.get(f"/labs/{LID}/interfaces").mock(return_value=httpx.Response(200, json=pinned))
    patch = lab_api.patch(f"/labs/{LID}/interfaces/{R1_E01}").mock(
        return_value=httpx.Response(200, json=iface(R1_E01))
    )
    preview, _ = await preview_apply(
        "cml_update_interface", {"lab": LID, "node": "r1", "interface": "Ethernet0/1", "mac_address": "auto"}
    )
    assert preview["status"] == "preview" and patch.called  # clearing a pin needs no KVM driver


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
        NodeSpec(label="r1", definition="alpine", macs={"eth3": "52-54-00-00-10-00"}),
        NodeSpec(label="r2", definition="iol-xe"),
    ]
    topo, _ = build_topology("t", nodes, ["r1 r2"], DEFS)
    r1 = {i["label"]: i for i in topo["nodes"][0]["interfaces"]}
    # eth3 is past alpine's default one interface, but a pinned MAC makes it exist
    assert r1["eth3"]["mac_address"] == "52:54:00:00:10:00"
    assert "mac_address" not in r1["eth0"]
    assert all("mac_address" not in i for i in topo["nodes"][1]["interfaces"])


@pytest.mark.parametrize(
    ("macs", "message"),
    [
        ({"r1": {"Gi9": "52:54:00:00:00:01"}}, "not a physical interface"),
        ({"r1": {"eth0": "aa:bb:cc:00:00:01"}}, "outside 52:54:00"),
        (
            {"r1": {"eth0": "52:54:00:00:00:01"}, "r2": {"eth1": "52:54:00:00:00:01"}},
            "also given",
        ),
    ],
)
def test_build_rejects_bad_macs(macs: dict[str, dict[str, str]], message: str) -> None:
    nodes = [NodeSpec(label=lab, definition="alpine", macs=macs.get(lab, {})) for lab in ("r1", "r2")]
    with pytest.raises(BuildError, match=message):
        build_topology("t", nodes, [], DEFS)


@pytest.mark.parametrize("definition", ["iol-xe", "ioll2-xe", "unmanaged_switch"])
def test_build_rejects_macs_on_non_kvm_nodes(definition: str) -> None:
    # simplified definitions (what cml_build_lab reads) carry sim.custom_mac: false for these
    nodes = [NodeSpec(label="r1", definition=definition, macs={"Ethernet0/0": "52:54:00:96:00:01"})]
    with pytest.raises(BuildError, match=f"r1: macs given, but node definition {definition} cannot take"):
        build_topology("t", nodes, [], DEFS)


def test_build_rejects_macs_by_full_definition_driver() -> None:
    full = {"iol-xe": yaml.safe_load(fixture("node_definition_iol_xe.json"))}
    nodes = [NodeSpec(label="r1", definition="iol-xe", macs={"Ethernet0/0": "52:54:00:96:00:01"})]
    with pytest.raises(BuildError, match="iol driver"):
        build_topology("t", nodes, [], full)


def test_custom_mac_problem_kvm_and_unknown() -> None:
    assert custom_mac_problem("alpine", yaml.safe_load(fixture("node_definition_alpine.json"))) is None
    assert custom_mac_problem("alpine", DEFS["alpine"]) is None  # simplified: custom_mac true
    assert custom_mac_problem("x", None) is None and custom_mac_problem("x", {}) is None
