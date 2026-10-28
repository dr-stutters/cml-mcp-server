"""L75 (cml #79): recipe isp-bgp, a dual-ISP eBGP internet edge on FRR (default origination, a synthetic
table, withdraw/restore/flap actions) that other recipes extend."""

import copy
import os
import re
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
import yaml

import cml_mcp.recipes as recipes
from cml_mcp.build import NodeSpec, build_topology
from cml_mcp.console import ConsoleServer, ConsoleSession, Credentials
from cml_mcp.recipes import (
    get_recipe,
    placeholders,
    recipe_actions,
    recipe_licensed_nodes,
    substituted,
    use_recipe_dirs,
)
from cml_mcp.tools.recipes_tools import recipe_detail
from cml_mcp.verify import contract_of

from .conftest import LAB, fixture
from .test_console import FakeDevice, ios
from .test_write_tools import preview_apply

NAME = "isp-bgp"


@pytest.fixture(autouse=True)
def no_extra_dirs() -> Iterator[None]:
    yield
    use_recipe_dirs(None)


def _node(recipe: dict[str, Any], label: str) -> dict[str, Any]:
    return next(n for n in recipe["build"]["nodes"] if n["label"] == label)


def _probe(recipe: dict[str, Any], words: str) -> re.Pattern[str]:
    p = next(p for p in contract_of(recipe).probes if words in p.name)
    assert p.expect
    return re.compile(p.expect)


# --- shape --------------------------------------------------------------------------------------------------


def test_recipe_shape() -> None:
    r = get_recipe(NAME)
    defs = {n["label"]: n["definition"] for n in r["build"]["nodes"]}
    assert defs == {
        "internet": "nginx",
        "internet-sw": "unmanaged_switch",
        "isp1": "frr",
        "isp2": "frr",
        "ce": "iol-xe",
    }
    assert r["build"]["title"] == "mcp-cml-isp-bgp" and recipe_licensed_nodes(r) == 4
    assert set(r["build"]["links"]) == {
        "isp1:eth0 ce:Ethernet0/0",
        "isp2:eth0 ce:Ethernet0/1",
        "isp1:eth1 internet-sw",
        "isp2:eth1 internet-sw",
        "internet:eth0 internet-sw",
    }
    # nothing is bridged to the lab network: documentation addresses only
    assert "external_connector" not in defs.values()
    assert "198.18." not in yaml.safe_dump(r["build"])


def test_topology_builds_against_the_node_definitions() -> None:
    defs = {d["id"]: d for d in fixture("simplified_node_definitions.json")}
    b = get_recipe(NAME)["build"]
    topo, links = build_topology(
        b["title"], [NodeSpec.model_validate(n) for n in b["nodes"]], b["links"], defs
    )
    assert len(links) == 5
    isp1 = next(n for n in topo["nodes"] if n["label"] == "isp1")
    assert {c["name"] for c in isp1["configuration"]} == {"node.cfg", "boot.sh", "protocols"}
    internet = next(n for n in topo["nodes"] if n["label"] == "internet")
    assert [c["name"] for c in internet["configuration"]] == ["boot.sh"]


def test_isps_peer_ebgp_and_originate_a_conditional_default() -> None:
    r = get_recipe(NAME)
    for isp, asn, me, peer in (
        ("isp1", 64496, "192.0.2.1", "192.0.2.2"),
        ("isp2", 64497, "198.51.100.1", "198.51.100.2"),
    ):
        files = _node(r, isp)["files"]
        cfg = files["node.cfg"]
        assert f"router bgp {asn}" in cfg and f"ip address {me}/" in cfg
        assert f"neighbor {peer} remote-as 65001" in cfg
        assert f"neighbor {peer} default-originate route-map MCP-DEFAULT" in cfg
        assert "redistribute static route-map MCP-SCALE" in cfg and "redistribute sharp" in cfg
        # the sentinel gates the default and is never advertised itself
        assert "permit 203.0.113.254/32" in cfg and "route-map MCP-TO-CE deny 5" in cfg
        assert f"neighbor {peer} route-map MCP-TO-CE out" in cfg
        assert files["protocols"].split("\n")[1:3] == ["bgpd", "sharpd"]
        assert "SCALE=routes-1000" in files["boot.sh"]
    assert "set as-path prepend 64497 64497" in _node(r, "isp2")["files"]["node.cfg"]
    assert "prepend" not in _node(r, "isp1")["files"]["node.cfg"]
    ce = _node(r, "ce")["config"]
    assert "neighbor 192.0.2.1 remote-as 64496" in ce and "neighbor 198.51.100.1 remote-as 64497" in ce
    assert "neighbor 192.0.2.1 route-map MCP-FROM-ISP1 in" in ce and "local-preference 200" in ce
    # a customer edge is never transit between its ISPs
    assert "neighbor 192.0.2.1 prefix-list MCP-NO-TRANSIT out" in ce
    assert "neighbor 198.51.100.1 prefix-list MCP-NO-TRANSIT out" in ce
    host = _node(r, "internet")["files"]["boot.sh"]
    assert (
        "203.0.113.10/24" in host and "via 203.0.113.1" in host and "198.51.100.0/30 via 203.0.113.2" in host
    )
    assert host.rstrip().endswith("exit 0") and 'echo "READY"' in host


def test_secrets_are_references_only(fake_lab_secrets: dict[str, str]) -> None:
    raw = (recipes.RECIPE_DIR / f"{NAME}.yaml").read_text()
    assert placeholders(get_recipe(NAME)) == {"LAB_CLI_PASSWORD"}
    assert not [v for v in fake_lab_secrets.values() if v in raw]
    assert "mitchcloud" not in raw.lower()
    blob = str(recipe_detail(NAME))
    assert not [v for v in fake_lab_secrets.values() if v in blob]


# --- verify contract ----------------------------------------------------------------------------------------

FRR_SUMMARY = """IPv4 Unicast Summary:
BGP router identifier 192.0.2.1, local AS number 64496 VRF default vrf-id 0
BGP table version 1002
RIB entries 2003, using 376 KiB of memory
Peers 1, using 13 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
192.0.2.2       4      65001        12        19     1002    0    0 00:05:01            0     1001 ce

Total number of neighbors 1
"""

IOS_SUMMARY = """BGP router identifier 192.0.2.2, local AS number 65001
BGP table version is 1003, main routing table version 1003

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.1       4        64496      21      12     1003    0    0 00:05:02     1001
198.51.100.1    4        64497      20      12     1003    0    0 00:04:58     1001
"""


def test_contract_validates_and_checks_every_node() -> None:
    c = contract_of(get_recipe(NAME))
    assert set(c.booted or []) == {"isp1", "isp2", "internet", "ce"}
    assert c.nodes == ["ce"] and "203.0.113.10" in c.targets
    assert {p.node for p in c.probes} == {"isp1", "isp2", "ce"}
    assert all(p.command and p.command.startswith("show ") for p in c.probes)


def test_probe_regexes_match_established_sessions_with_the_table() -> None:
    r = get_recipe(NAME)
    assert _probe(r, "isp1 sends").search(FRR_SUMMARY)
    assert _probe(r, "ce receives 100+ prefixes from isp1").search(IOS_SUMMARY)
    assert _probe(r, "ce receives 100+ prefixes from isp2").search(IOS_SUMMARY)
    assert _probe(r, "isp1 eBGP").search(
        "BGP neighbor is 192.0.2.2, remote AS 65001\n  BGP state = Established, up"
    )
    route = (
        'Routing entry for 0.0.0.0/0, supernet\n  Known via "bgp 65001", distance 20\n'
        "  * 192.0.2.1, from 192.0.2.1"
    )
    assert _probe(r, "ce default route").search(route)


def test_probe_regexes_fail_when_a_session_is_down_or_empty() -> None:
    r = get_recipe(NAME)
    down = IOS_SUMMARY.replace("00:05:02     1001", "never        Active")
    assert not _probe(r, "ce receives 100+ prefixes from isp1").search(down)
    assert not _probe(r, "isp1 sends").search(FRR_SUMMARY.replace("     1001 ce", "        1 ce"))
    assert not _probe(r, "ce default route").search(
        route_via_isp2 := 'Known via "bgp 65001"\n * 198.51.100.1'
    )
    assert route_via_isp2


# --- substitutions (the table size and other addresses) -----------------------------------------------------


def test_routes_parameter_is_a_substitution() -> None:
    r = substituted(get_recipe(NAME), {"routes-1000": "routes-5000"})
    for isp in ("isp1", "isp2"):
        assert "SCALE=routes-5000" in _node(r, isp)["files"]["boot.sh"]
    assert "routes-1000" not in yaml.safe_dump(r)


def test_off_testnet_copy_keeps_probes_matching() -> None:
    """FMC refuses some documentation addresses on interfaces: a copy on other addresses still verifies."""
    sub = {"192.0.2.": "172.31.75.", "198.51.100.": "172.31.76."}
    r = substituted(get_recipe(NAME), sub)
    assert "ip address 172.31.75.1/30" in _node(r, "isp1")["files"]["node.cfg"]
    assert "neighbor 172.31.76.1 remote-as 64497" in _node(r, "ce")["config"]
    moved = IOS_SUMMARY.replace("192.0.2.", "172.31.75.").replace("198.51.100.", "172.31.76.")
    assert _probe(r, "ce receives 100+ prefixes from isp1").search(moved)
    assert _probe(r, "ce receives 100+ prefixes from isp2").search(moved)
    assert contract_of(r).addresses == {"ce": ["172.31.75.2", "172.31.76.2"]}


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
@pytest.mark.parametrize("routes", [1000, 3, 99999])
def test_isp_boot_script_installs_the_table_and_the_sentinel(tmp_path: Path, routes: int) -> None:
    """Run each ISP's boot.sh with a stand-in vtysh: N static blackholes (capped at 16384) in one
    configure-terminal call, then the sharpd sentinel that gates the default."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "vtysh.log"
    fake = bindir / "vtysh"
    fake.write_text(f'#!/bin/bash\nprintf "%s\\n" "$*" >> {log}\nexit 0\n')
    fake.chmod(0o755)
    r = substituted(get_recipe(NAME), {"routes-1000": f"routes-{routes}"})
    script = tmp_path / "boot.sh"
    script.write_text(
        _node(r, "isp1")["files"]["boot.sh"].replace("/tmp/mcp-isp-bgp.log", str(tmp_path / "o"))
    )
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    done = subprocess.run(["bash", str(script)], env=env, timeout=30, check=False)
    assert done.returncode == 0
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and "sharp install" not in (log.read_text() if log.exists() else ""):
        time.sleep(0.1)
    calls = log.read_text().splitlines()
    assert calls[0] == "-c show version"
    statics = re.findall(r"-c ip route (\S+) blackhole", calls[1])
    want = min(routes, 16384)
    assert calls[1].startswith("-c configure terminal") and len(statics) == want
    assert (
        statics[0] == "100.64.0.0/24"
        and statics[-1] == f"100.{64 + (want - 1) // 256}.{(want - 1) % 256}.0/24"
    )
    assert calls[2] == "-c sharp install routes 203.0.113.254 nexthop 203.0.113.10 1"


# --- actions ------------------------------------------------------------------------------------------------


def test_actions_withdraw_restore_and_flap_each_isp() -> None:
    a = recipe_actions(get_recipe(NAME))
    assert set(a) == {
        f"{verb}-{isp}"
        for verb in ("withdraw-default", "restore-default", "flap")
        for isp in ("isp1", "isp2")
    }
    assert a["withdraw-default-isp1"] == {
        "description": a["withdraw-default-isp1"]["description"],
        "node": "isp1",
        "command": "sharp remove routes 203.0.113.254 1",
        "expect": None,
        "timeout": 30.0,
    }
    assert a["restore-default-isp2"]["command"] == "sharp install routes 203.0.113.254 nexthop 203.0.113.10 1"
    assert a["flap-isp1"]["command"] == "clear bgp ipv4 unicast 192.0.2.2"
    assert a["flap-isp2"]["command"] == "clear bgp ipv4 unicast 198.51.100.2"
    # the boot script installs the same sentinel the restore actions reinstall
    boot = _node(get_recipe(NAME), "isp2")["files"]["boot.sh"]
    assert a["restore-default-isp2"]["command"] in boot


def _isp_on_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    """isp-bgp's actions on the captured test lab (its r1 standing in for isp1)."""
    r = copy.deepcopy(get_recipe(NAME))
    r["name"] = "isp-bgp-test"
    r["build"]["title"] = LAB["lab_title"]
    _node(r, "isp1")["label"] = "r1"
    r["actions"] = {k: {**v, "node": "r1"} for k, v in r["actions"].items() if v["node"] == "isp1"}
    real = recipes._load_all()
    monkeypatch.setattr(recipes, "_load_all", lambda: {**real, "isp-bgp-test": r})


def _console(monkeypatch: pytest.MonkeyPatch, sent: list[str]) -> None:
    base = ios()

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd.startswith(("sharp ", "clear bgp ")):
            sent.append(cmd)
            return f"{cmd}\r\nr1#"
        return base(text)

    class Opened:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(reply), self.creds, timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(creds))


@pytest.mark.parametrize(
    ("action", "command"),
    [
        ("withdraw-default-isp1", "sharp remove routes 203.0.113.254 1"),
        ("restore-default-isp1", "sharp install routes 203.0.113.254 nexthop 203.0.113.10 1"),
        ("flap-isp1", "clear bgp ipv4 unicast 192.0.2.2"),
    ],
)
async def test_action_renders_in_the_preview_and_runs_on_the_isp(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, action: str, command: str
) -> None:
    _isp_on_lab(monkeypatch)
    sent: list[str] = []
    _console(monkeypatch, sent)
    preview, done = await preview_apply("cml_run_recipe_action", {"recipe": "isp-bgp-test", "action": action})
    assert preview["status"] == "preview" and command in str(preview)
    assert done["status"] == "applied" and done["result"]["ok"] is True, done
    assert sent == [command]


# --- as an extends: base ------------------------------------------------------------------------------------


def _write(directory: Path, recipe: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{recipe['name']}.yaml").write_text(yaml.safe_dump(recipe, sort_keys=False))


def test_an_ftd_child_replaces_the_customer_edge(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "name": "isp-bgp-ftd",
            "extends": NAME,
            "summary": "isp-bgp with an FTDv as the customer edge",
            "build": {
                "title": "mcp-cml-isp-bgp-ftd",
                "remove_nodes": ["ce"],
                "nodes": [
                    {"label": "ftd", "definition": "ftdv", "config": "{}"},
                ],
                "links": ["ftd:GigabitEthernet0/0 isp1:eth0", "ftd:GigabitEthernet0/1 isp2:eth0"],
            },
        },
    )
    use_recipe_dirs(str(tmp_path))
    r = get_recipe("isp-bgp-ftd")
    assert r["extends"] == NAME and r["build"]["title"] == "mcp-cml-isp-bgp-ftd"
    labels = [n["label"] for n in r["build"]["nodes"]]
    assert "ce" not in labels and {"isp1", "isp2", "internet", "ftd"} <= set(labels)
    assert set(r["build"]["links"]) == {
        "isp1:eth1 internet-sw",
        "isp2:eth1 internet-sw",
        "internet:eth0 internet-sw",
        "ftd:GigabitEthernet0/0 isp1:eth0",
        "ftd:GigabitEthernet0/1 isp2:eth0",
    }
    c = contract_of(r)
    assert {p.node for p in c.probes} == {"isp1", "isp2"} and "ce" not in (c.booted or [])
    assert set(recipe_actions(r)) == set(recipe_actions(get_recipe(NAME)))  # actions run on the ISPs
    defs = {d["id"]: d for d in fixture("simplified_node_definitions.json")}
    b = r["build"]
    build_topology(b["title"], [NodeSpec.model_validate(n) for n in b["nodes"]], b["links"], defs)


def test_a_cat8000v_child_swaps_the_edge_in_place(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "name": "isp-bgp-c8k",
            "extends": NAME,
            "build": {
                "nodes": [{"label": "ce", "definition": "cat8000v", "config": "hostname ce\n"}],
                "links": ["ce:GigabitEthernet2 isp1:eth0", "ce:GigabitEthernet3 isp2:eth0"],
            },
        },
    )
    use_recipe_dirs(str(tmp_path))
    r = get_recipe("isp-bgp-c8k")
    assert _node(r, "ce")["definition"] == "cat8000v"
    links = r["build"]["links"]
    assert "ce:GigabitEthernet2 isp1:eth0" in links and "isp1:eth0 ce:Ethernet0/0" not in links
    assert len(links) == 5
    assert {p.node for p in contract_of(r).probes} == {"isp1", "isp2", "ce"}


def test_listed_with_its_lab_and_hand_off() -> None:
    detail = recipe_detail(NAME)
    side = detail["product_side"]
    assert "fmc_configure_bgp" in side["fmc_side"] and "remove_nodes: [ce]" in side["fmc_side"]
    assert "cat8000v" in side["cml_side"]
    readme = (recipes.RECIPE_DIR / "README.md").read_text()
    assert "| `isp-bgp` | `mcp-cml-isp-bgp` |" in readme
