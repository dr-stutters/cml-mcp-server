"""L65 (cml #56): recipe cat-sdwan-secure, a superset of cat-sdwan-fabric on the same lab (mcp-cat-sdwan)."""

import json
import re

from cml_mcp.build import NodeSpec, build_topology
from cml_mcp.recipes import get_recipe, placeholders, recipe_licensed_nodes, recipe_names
from cml_mcp.tools.recipes_tools import recipe_detail
from cml_mcp.verify import contract_of

from .conftest import fixture

NEW_NODES = {
    "hub-ftd": "ftdv",
    "br1-ftd": "ftdv",
    "br1-lan": "unmanaged_switch",
    "alice": "alpine",
    "bob": "alpine",
}
EDGES = ("hub1", "br1", "br2")


def _nodes(name: str) -> dict[str, dict]:
    return {n["label"]: n for n in get_recipe(name)["build"]["nodes"]}


def test_secure_is_a_superset_of_the_fabric_on_the_same_lab() -> None:
    """Extending mcp-cat-sdwan in place: every fabric node, link and setting is kept; only additions."""
    fabric, secure = get_recipe("cat-sdwan-fabric"), get_recipe("cat-sdwan-secure")
    assert secure["build"]["title"] == fabric["build"]["title"] == "mcp-cat-sdwan"
    fn, sn = _nodes("cat-sdwan-fabric"), _nodes("cat-sdwan-secure")
    assert set(sn) - set(fn) == set(NEW_NODES)
    assert {k: sn[k]["definition"] for k in NEW_NODES} == NEW_NODES
    for label, node in fn.items():
        mine = sn[label]
        changed = {k for k in {*node, *mine} if node.get(k) != mine.get(k)}
        if label in EDGES:
            assert changed <= {"ram", "cpus", "config"}, (label, changed)
            # the edge day-0 only gains lines: every fabric line is still there, in order
            old, new = node["config"].splitlines(), mine["config"].splitlines()
            it = iter(new)
            assert all(line in it for line in old), label
        else:
            assert not changed, (label, changed)
    assert set(fabric["build"]["links"]) <= set(secure["build"]["links"])
    assert secure["build"]["links"][: len(fabric["build"]["links"])] == fabric["build"]["links"]
    # the fabric's verify contract is kept whole
    fv, sv = fabric["verify"], secure["verify"]
    assert set(fv["booted"]) <= set(sv["booted"]) and fv["targets"] == sv["targets"]
    assert all(p in sv["probes"] for p in fv["probes"])


def test_edges_get_utd_resources() -> None:
    sn = _nodes("cat-sdwan-secure")
    assert {e: (sn[e]["cpus"], sn[e]["ram"]) for e in EDGES} == {e: (4, 8192) for e in EDGES}
    assert sn["alice"]["ram"] == sn["bob"]["ram"] == 512


def test_edge_interfaces_and_routes() -> None:
    sn = _nodes("cat-sdwan-secure")
    hub1, br1 = sn["hub1"]["config"], sn["br1"]["config"]
    for iface, addr in (
        ("GigabitEthernet5", "198.18.129.16 255.255.192.0"),
        ("GigabitEthernet6", "10.61.110.1 255.255.255.0"),
        ("GigabitEthernet7", "10.61.111.1 255.255.255.0"),
    ):
        assert re.search(
            rf"interface {iface}\n(?:.*\n)*?\s+vrf forwarding 10\n\s+ip address {addr}\n", hub1
        ), iface
    assert re.search(
        r"interface GigabitEthernet5\n(?:.*\n)*?\s+vrf forwarding 10\n\s+ip address 10\.61\.210\.1 ", br1
    )
    assert "ip route vrf 10 10.61.220.0 255.255.255.0 10.61.210.2" in br1
    links = get_recipe("cat-sdwan-secure")["build"]["links"]
    for link in (
        "hub1:GigabitEthernet5 mgmt-sw",
        "hub1:GigabitEthernet6 hub-ftd:GigabitEthernet0/1",
        "hub1:GigabitEthernet7 hub-ftd:GigabitEthernet0/0",
        "hub-ftd:Management0/0 mgmt-sw",
        "br1:GigabitEthernet5 br1-ftd:GigabitEthernet0/0",
        "br1-ftd:GigabitEthernet0/1 br1-lan",
        "br1-ftd:Management0/0 mgmt-sw",
        "alice:eth0 br1-lan",
        "bob:eth0 br1-lan",
    ):
        assert link in links


def test_ftd_day0_registers_with_fmc_on_free_addresses() -> None:
    sn = _nodes("cat-sdwan-secure")
    expected = {
        "hub-ftd": ("mcp-w8-hub-ftd", "198.18.129.17"),
        "br1-ftd": ("mcp-w8-br1-ftd", "198.18.129.18"),
    }
    for label, (host, ip) in expected.items():
        day0 = json.loads(sn[label]["config"])
        assert (day0["Hostname"], day0["IPv4Addr"], day0["IPv4Mask"]) == (host, ip, "255.255.192.0")
        assert day0["FmcIp"] == "198.18.134.76" and day0["FmcRegKey"] == "${LAB_FTD_REG_KEY}"
        assert day0["AdminPassword"] == "${LAB_FTD_ADMIN_PASSWORD}" and day0["ManageLocally"] == "No"
    # no other recipe uses the new addresses (hub1 DC .16, FTD management .17/.18)
    new = {"198.18.129.16", "198.18.129.17", "198.18.129.18"}
    for name in recipe_names():
        if name != "cat-sdwan-secure":
            blob = json.dumps(get_recipe(name))
            assert not [ip for ip in new if re.search(re.escape(ip) + r"(?!\d)", blob)], name
    # and none of them collides with the fabric's management addresses .10-.15
    assert not new & {f"198.18.129.{i}" for i in range(10, 16)}


def test_secrets_are_references_only() -> None:
    r = get_recipe("cat-sdwan-secure")
    assert placeholders(r) == {
        "LAB_SDWAN_ADMIN_PASSWORD",
        "LAB_SDWAN_ADMIN_HASH",
        "LAB_SDWAN_ORG",
        "LAB_CA_PEM",
        "LAB_FTD_ADMIN_PASSWORD",
        "LAB_FTD_REG_KEY",
    }


def test_verify_contract_checks_every_new_node() -> None:
    r = get_recipe("cat-sdwan-secure")
    assert recipe_licensed_nodes(r) == recipe_licensed_nodes(get_recipe("cat-sdwan-fabric")) + 4 == 14
    contract = contract_of(r)
    licensed = [
        n["label"]
        for n in r["build"]["nodes"]
        if n["definition"] not in ("external_connector", "unmanaged_switch")
    ]
    assert sorted(contract.booted or []) == sorted(licensed)
    probed = {p.node for p in contract.probes if p.command}
    assert {"hub-ftd", "br1-ftd", "alice", "hub1", "br1", "br2"} <= probed
    tcp = {p.tcp for p in contract.probes if p.tcp}
    assert {"198.18.129.17:22", "198.18.129.18:22"} <= tcp
    assert contract.addresses == {"alice": ["10.61.220.10"], "bob": ["10.61.220.11"]}


def test_hand_off_names_the_gate_and_the_product_sides() -> None:
    side = recipe_detail("cat-sdwan-secure")["product_side"]
    assert {"cml_side", "manager_side", "fmc_side"} <= set(side)
    assert "cml_plan_licences('cat-sdwan-secure')" in side["cml_side"]
    assert "never wipe an edge" in side["cml_side"]
    assert "Global/mcp-test-leaf" in side["fmc_side"] and "${LAB_FTD_REG_KEY}" in side["fmc_side"]
    assert "configuration group" in side["manager_side"]


def test_secure_topology_builds() -> None:
    """The wiring is valid against the node definitions (new edge interfaces, switch ports, FTD slots)."""
    defs = {d["id"]: d for d in fixture("simplified_node_definitions.json")}
    b = get_recipe("cat-sdwan-secure")["build"]
    nodes = [NodeSpec.model_validate(n) for n in b["nodes"]]
    topo, links = build_topology(b["title"], nodes, b["links"], defs)
    assert len(links) == len(b["links"]) == 30
    hub1 = next(n for n in topo["nodes"] if n["label"] == "hub1")
    assert hub1["ram"] == 8192 and hub1["cpus"] == 4
    assert "GigabitEthernet7" in {i["label"] for i in hub1["interfaces"]}
