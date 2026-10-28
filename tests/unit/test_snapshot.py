"""L69: cml_snapshot / cml_compare_snapshot on the core snapshot contract."""

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.console import ConsoleServer, ConsoleSession, Credentials
from cml_mcp.server import create_server
from cml_mcp.tools.snapshot import (
    bgp_neighbours,
    config_hash,
    eigrp_neighbours,
    node_commands,
    ospf_neighbours,
    uptime_seconds,
)

from .conftest import LID, R1, R2, fixture, make_settings
from .test_console import FakeDevice, ios

OSPF_HEAD = "Neighbor ID     Pri   State           Dead Time   Address         Interface"
OSPF_OUT = f"""{OSPF_HEAD}
192.0.2.2         1   FULL/DR         00:00:33    198.51.100.2    Ethernet0/0
192.0.2.3         0   FULL/  -        00:00:35    198.51.100.6    Ethernet0/1
192.0.2.4         1   INIT/DROTHER    00:00:31    198.51.100.10   Ethernet0/2"""
NXOS_OSPF = """ OSPF Process ID 1 VRF default
 Total number of neighbors: 1
 Neighbor ID     Pri State            Up Time  Address         Interface
 192.0.2.9         1 FULL/BDR         00:01:02 198.51.100.14   Eth1/1"""
BGP_OUT = """BGP router identifier 192.0.2.1, local AS number 65001
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
198.51.100.2    4        65002      10      12        5    0    0 00:05:01        3
198.51.100.6    4        65003       0       0        1    0    0 never    Idle
203.0.113.1     4        65004       0       0        1    0    0 00:00:10 Idle (Admin)"""
EIGRP_OUT = """EIGRP-IPv4 Neighbors for AS(100)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
0   198.51.100.2            Et0/0                    13 00:01:23    1   100  0  3
1   198.51.100.6            Et0/1                    11 1d02h       2   100  0  7"""


def test_ospf_parser_drops_the_role() -> None:
    rows = ospf_neighbours(OSPF_OUT.replace("\n", "\r\n"))
    assert [(r["id"], r["state"], r["interface"]) for r in rows] == [
        ("192.0.2.2", "FULL", "Ethernet0/0"),
        ("192.0.2.3", "FULL", "Ethernet0/1"),
        ("192.0.2.4", "INIT", "Ethernet0/2"),
    ]
    assert ospf_neighbours(NXOS_OSPF) == [
        {"id": "192.0.2.9", "state": "FULL", "address": "198.51.100.14", "interface": "Eth1/1"}
    ]
    assert ospf_neighbours(OSPF_HEAD) == []


def test_bgp_and_eigrp_parsers() -> None:
    assert bgp_neighbours(BGP_OUT) == [
        {"peer": "198.51.100.2", "asn": "65002", "state": "Established"},
        {"peer": "198.51.100.6", "asn": "65003", "state": "Idle"},
        {"peer": "203.0.113.1", "asn": "65004", "state": "Idle (Admin)"},
    ]
    assert bgp_neighbours("% BGP not active") == []
    assert eigrp_neighbours(EIGRP_OUT) == [
        {"address": "198.51.100.2", "interface": "Et0/0"},
        {"address": "198.51.100.6", "interface": "Et0/1"},
    ]


def test_uptime_parser() -> None:
    assert uptime_seconds("r1 uptime is 1 day, 2 hours, 3 minutes") == 86400 + 7200 + 180
    assert uptime_seconds("r1 uptime is 1 week, 2 days, 0 minutes") == 9 * 86400
    assert uptime_seconds("Kernel uptime is 0 day(s), 1 hour(s), 5 minute(s), 3 second(s)") == 3600 + 300 + 3
    assert uptime_seconds(" 10:01:02 up 3 days,  2:05,  0 users,  load average: 0.00") == 3 * 86400 + 125 * 60
    assert uptime_seconds(" 10:01:02 up 5 min,  load average: 0.00") == 300
    assert uptime_seconds("% Invalid input") is None


def test_config_hash_ignores_noise_and_masks() -> None:
    a = "Building configuration...\nCurrent configuration : 1200 bytes\n!\n"
    a += "! Last configuration change at 10:00\n"
    a += "hostname r1\nusername admin secret 9 $9$abc\nntp clock-period 17179\ninterface Ethernet0/0\nend"
    b = a.replace("1200 bytes", "1210 bytes").replace("10:00", "11:00").replace("17179", "17180")
    b = b.replace("$9$abc", "$9$xyz")  # a masked secret is not visible to the hash
    assert config_hash(a) == config_hash(b) is not None
    assert config_hash(a) != config_hash(a.replace("Ethernet0/0", "Ethernet0/1"))
    assert config_hash("% Invalid input") is None


def test_node_commands_by_os() -> None:
    ios_cmds = node_commands(Credentials(os="iosxe"))
    assert "show running-config" in ios_cmds and "show ip ospf neighbor" in ios_cmds
    assert node_commands(Credentials(os="linux")) == ["ip -4 -o addr", "uptime"]
    assert "show running-config" not in node_commands(Credentials(os="ftd"))
    assert "show ip ospf neighbors" in node_commands(Credentials(os="nxos"))


# --- the tools on a synthetic two-router lab ------------------------------------------------------

STATE: dict[str, Any] = {}
ADDR = {"r1": ("198.51.100.1", "192.0.2.1"), "r2": ("198.51.100.2", "192.0.2.2")}
PEER = {"r1": "r2", "r2": "r1"}


def _reply(host: str, state: dict[str, Any]) -> Callable[[str], str]:
    base = ios()

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        peer = PEER[host]
        if cmd == "show ip interface brief":
            e0, lo = ADDR[host]
            out = (
                "Interface              IP-Address      OK? Method Status                Protocol\r\n"
                f"Ethernet0/0            {e0}    YES TFTP   up                    up\r\n"
                "Ethernet0/1            unassigned      YES unset  administratively down down\r\n"
                f"Loopback0              {lo}       YES TFTP   up                    up"
            )
        elif cmd == "show version | include uptime":
            out = f"{host} uptime is 2 hours, 5 minutes"
        elif cmd == "show running-config":
            n = state["reads"] = state.get("reads", 0) + 1
            out = (
                f"Building configuration...\r\n\r\nCurrent configuration : {1200 + n} bytes\r\n!\r\n"
                f"! Last configuration change at 10:0{n}\r\nhostname {host}\r\n"
                f"ntp clock-period {17000 + n}\r\ninterface Ethernet0/0\r\n ip address {ADDR[host][0]} "
                f"255.255.255.252\r\nrouter ospf 1\r\n{state.get('extra', '')}end"
            )
        elif cmd == "show ip ospf neighbor":
            out = OSPF_HEAD
            if state["ospf"]:
                row = f"{ADDR[peer][1]}         1   FULL/DR         00:00:33    {ADDR[peer][0]}"
                out += f"\r\n{row}    Ethernet0/0"
        elif cmd == "show ip bgp summary":
            out = "% BGP not active"
        elif cmd == "show ip eigrp neighbors":
            out = "EIGRP-IPv4 Neighbors for AS(100)"
        elif cmd.startswith("ping "):
            state.setdefault("pings", []).append((host, cmd))
            out = "Success rate is 100 percent (3/3)" if state["ping"] else "Success rate is 0 percent (0/3)"
        else:
            return base(text).replace("r1", host)
        return f"{cmd}\r\n{out}\r\n{host}#"

    return reply


@pytest.fixture
def lab(lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"ospf": True, "ping": True}
    hosts = {R1: "r1", R2: "r2"}

    class Opened:
        def __init__(self, node: str, creds: Credentials) -> None:
            self.node, self.creds = node, creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(_reply(hosts[self.node], state)), self.creds, timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(node, creds))
    state["api"] = lab_api
    return state


def _link_down(api: respx.MockRouter) -> None:
    element = fixture("element_state.json")
    element["links"] = {k: "STOPPED" for k in element["links"]}
    api.get(f"/labs/{LID}/lab_element_state").mock(return_value=httpx.Response(200, json=element))


async def test_unchanged_lab_compares_clean(lab: dict[str, Any]) -> None:
    server = create_server(make_settings())
    before = await call_tool(server, "cml_snapshot", {"lab": LID})
    assert before["prefix"] == "cml" and before["scope"] == {"lab": "mcp-test-probe", "probes": "auto"}
    secs = before["sections"]
    assert set(secs) == {"lab", "nodes", "links", "addresses", "configs", "neighbours", "reachability"}
    assert (
        secs["nodes"]["items"]["r1"]["state"] == "BOOTED" and "booted_at_min" in secs["nodes"]["items"]["r1"]
    )
    assert secs["links"]["items"]["r1:Ethernet0/0<->r2:Ethernet0/0"]["ok"] is True
    assert secs["addresses"]["items"]["r2:Loopback0"]["state"] == "192.0.2.2"
    assert set(secs["neighbours"]["items"]) == {
        "r1|ospf|192.0.2.2|Ethernet0/0",
        "r2|ospf|192.0.2.1|Ethernet0/0",
    }
    assert set(secs["reachability"]["items"]) == {"r1->192.0.2.2", "r2->192.0.2.1"}  # nobody pings itself
    assert "sha" in secs["configs"]["items"]["r1"]
    # no `after`: a fresh snapshot of the same scope (its running configs differ only in noise lines)
    out = await call_tool(server, "cml_compare_snapshot", {"before": before})
    assert out["counts"] == {"major": 0, "minor": 0, "info": 0}, out
    assert out["verdict"].startswith("No change")


async def test_link_down_names_link_neighbours_and_pairs(lab: dict[str, Any]) -> None:
    server = create_server(make_settings())
    before = await call_tool(server, "cml_snapshot", {"lab": LID})
    _link_down(lab["api"])
    lab["ospf"] = False
    lab["ping"] = False
    after = await call_tool(server, "cml_snapshot", {"lab": LID})
    out = await call_tool(server, "cml_compare_snapshot", {"before": before, "after": after})
    found = {(c["severity"], c["section"], c["item"]) for c in out["changes"]}
    assert found == {
        ("major", "links", "r1:Ethernet0/0<->r2:Ethernet0/0"),
        ("major", "neighbours", "r1|ospf|192.0.2.2|Ethernet0/0"),
        ("major", "neighbours", "r2|ospf|192.0.2.1|Ethernet0/0"),
        ("major", "reachability", "r1->192.0.2.2"),
        ("major", "reachability", "r2->192.0.2.1"),
    }, out
    link = next(c for c in out["changes"] if c["section"] == "links")
    assert "STARTED -> STOPPED" in link["what"]
    # and back: the recovery is info only
    lab["api"].get(f"/labs/{LID}/lab_element_state").mock(
        return_value=httpx.Response(200, json=fixture("element_state.json"))
    )
    lab["ospf"] = lab["ping"] = True
    again = await call_tool(server, "cml_compare_snapshot", {"before": before})
    assert again["counts"] == {"major": 0, "minor": 0, "info": 0}


async def test_config_change_is_minor(lab: dict[str, Any]) -> None:
    server = create_server(make_settings())
    before = await call_tool(server, "cml_snapshot", {"lab": LID, "probes": "none"})
    assert "reachability" not in before["sections"] and before["scope"]["probes"] == "none"
    lab["extra"] = "ip route 0.0.0.0 0.0.0.0 198.51.100.2\r\n"
    out = await call_tool(server, "cml_compare_snapshot", {"before": before})
    assert out["counts"]["major"] == 0 and out["counts"]["minor"] == 2
    assert {c["item"] for c in out["changes"]} == {"r1", "r2"}
    assert not lab.get("pings")


async def test_explicit_matrix_and_nodes(lab: dict[str, Any]) -> None:
    server = create_server(make_settings())
    blob = await call_tool(
        server, "cml_snapshot", {"lab": LID, "probes": "matrix", "nodes": ["r1"], "targets": ["203.0.113.9"]}
    )
    assert blob["scope"]["nodes"] == "r1" and blob["scope"]["targets"] == "203.0.113.9"
    assert list(blob["sections"]["reachability"]["items"]) == ["r1->203.0.113.9"]
    assert "r2" not in blob["sections"]["configs"]["items"]
    assert lab["pings"] == [("r1", "ping 203.0.113.9 repeat 3 timeout 2")]


async def test_recipe_probe_without_a_recipe_is_unreadable(lab: dict[str, Any]) -> None:
    blob = await call_tool(create_server(make_settings()), "cml_snapshot", {"lab": LID, "probes": "recipe"})
    assert "not built from a recipe" in blob["sections"]["recipe"]["error"]


async def test_console_failure_marks_sections_unreadable(
    lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    class Broken:
        async def __aenter__(self) -> ConsoleSession:
            raise OSError("console refused")

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Broken())
    blob = await call_tool(create_server(make_settings()), "cml_snapshot", {"lab": LID, "probes": "none"})
    assert "console refused" in blob["sections"]["neighbours"]["error"]
    assert blob["sections"]["links"]["items"]  # the REST sections still read


async def test_bad_input(lab: dict[str, Any]) -> None:
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool(
            "cml_snapshot", {"lab": LID, "targets": ["1.1.1.1; reload"]}, raise_on_error=False
        )
        assert res.is_error and "Not an IP address" in res.content[0].text
        res = await c.call_tool("cml_snapshot", {"lab": LID, "nodes": ["r9"]}, raise_on_error=False)
        assert res.is_error and "r9" in res.content[0].text
        other = {"snapshot": 1, "prefix": "fmc", "sections": {}}
        res = await c.call_tool("cml_compare_snapshot", {"before": other}, raise_on_error=False)
        assert res.is_error and "not 'cml'" in res.content[0].text
