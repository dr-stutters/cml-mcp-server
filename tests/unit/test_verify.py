"""L3: recipe verify contracts, the result model, probes."""

import asyncio
from typing import Any

import httpx
import pytest
import respx
from stutters_mcp_core.testing import call_tool

from cml_mcp.console import ConsoleServer, ConsoleSession, Credentials
from cml_mcp.recipes import get_recipe, recipe_names
from cml_mcp.server import create_server
from cml_mcp.verify import (
    contract_of,
    snmp_get_sysname_request,
    snmp_sysname_from_response,
    tcp_probe,
)

from .conftest import LAB, NODES, make_settings
from .test_console import FakeDevice, ios


@pytest.mark.parametrize("name", recipe_names())
def test_every_recipe_contract_parses(name: str) -> None:
    import re

    c = contract_of(get_recipe(name))
    assert c.targets and c.nodes
    labels = {n["label"] for n in get_recipe(name)["build"]["nodes"]}
    assert set(c.nodes) <= labels and set(c.addresses) <= labels
    for p in c.probes:
        assert p.node is None or p.node in labels
        assert bool(p.command) + bool(p.tcp) + bool(p.snmp) == 1, p.name
        for rx in (p.expect, p.reject):
            if rx:
                re.compile(rx)


def test_bad_contract_is_reported() -> None:
    with pytest.raises(ValueError, match="invalid verify contract"):
        contract_of({"name": "x", "verify": {"probes": [{"tcp": "a:1"}]}})  # probe without a name


def test_snmp_request_shape() -> None:
    req = snmp_get_sysname_request("mcp-ro")
    assert req[0] == 0x30 and b"mcp-ro" in req


async def test_tcp_probe_open_and_closed() -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        assert (await tcp_probe(f"127.0.0.1:{port}"))[0] is True
    assert (await tcp_probe("127.0.0.1:1", timeout=1))[0] is False
    assert (await tcp_probe("not a target"))[0] is False


def _ftd_console(monkeypatch: pytest.MonkeyPatch, managers: str) -> None:
    base = ios()

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show managers":
            return f"{cmd}\r\n{managers}\r\nr1#"
        if cmd.startswith("ping"):
            return f"{cmd}\r\nSuccess rate is 100 percent (3/3)\r\nr1#"
        if cmd == "show ip interface brief":
            return f"{cmd}\r\nGigabitEthernet1  198.18.128.151  YES manual up up\r\nr1#"
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


def _fake_recipe(monkeypatch: pytest.MonkeyPatch, tcp_port: int) -> None:
    import cml_mcp.recipes as recipes

    recipe: dict[str, Any] = {
        "name": "fake",
        "build": {"title": LAB["lab_title"], "nodes": [{"label": "r1", "definition": "iol-xe"}]},
        "verify": {
            "nodes": ["r1"],
            "targets": ["198.18.134.76"],
            "addresses": {"r1": ["198.18.128.151"]},
            "probes": [
                {"name": "manager", "node": "r1", "command": "show managers", "expect": r"198\.18\.134\.76"},
                {"name": "ssh", "tcp": f"127.0.0.1:{tcp_port}"},
            ],
        },
    }
    real = recipes._load_all()
    monkeypatch.setattr(recipes, "_load_all", lambda: {**real, "fake": recipe})


async def test_verify_tool_pass_and_fail(lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    _fake_recipe(monkeypatch, port)
    _ftd_console(monkeypatch, "Host: 198.18.134.76\r\nRegistration: Completed")
    async with server:
        data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake"})
    assert data["passed"] is True, data
    kinds = {c["kind"] for c in data["checks"]}
    assert kinds == {"state", "ping", "address", "console", "tcp"}
    _ftd_console(monkeypatch, "No managers configured.")
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake"})
    failed = {c["check"] for c in data["checks"] if not c["ok"]}
    assert data["passed"] is False and failed == {"manager", "ssh"}


async def test_verify_missing_lab(api: respx.MockRouter) -> None:
    api.get("/labs").mock(return_value=httpx.Response(200, json=[]))
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "ise-access"})
    assert data["passed"] is False and "build it first" in str(data["checks"])


def test_nodes_fixture_is_booted() -> None:
    assert all(n["state"] == "BOOTED" for n in NODES)


@pytest.mark.parametrize(
    "probe",
    [
        {"name": "none"},
        {"name": "two", "tcp": "a:22", "snmp": {"host": "a", "community": "c"}},
        {"name": "nonode", "command": "show version"},
        {"name": "write", "node": "r1", "command": "reload"},
        {"name": "conf", "node": "r1", "command": "configure terminal"},
        {"name": "port", "tcp": "a:99999"},
        {"name": "regex", "node": "r1", "command": "show version", "expect": "("},
    ],
)
def test_probe_validation(probe: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="invalid verify contract"):
        contract_of({"name": "x", "verify": {"probes": [probe]}})


def test_probe_allows_test_aaa() -> None:
    c = contract_of(
        {
            "verify": {
                "probes": [{"name": "t", "node": "sw1", "command": "test aaa group radius u p new-code"}]
            }
        }
    )
    assert c.probes[0].command


def _resp(rid: int = 0x4D43, err: int = 0, value: bytes = b"\x04\x06mcp-r1") -> bytes:
    from cml_mcp.verify import SYSNAME_OID, _tlv

    vb = _tlv(0x30, _tlv(0x30, _tlv(0x06, SYSNAME_OID) + value))
    pdu = _tlv(0xA2, _tlv(0x02, rid.to_bytes(2, "big")) + _tlv(0x02, bytes([err])) + b"\x02\x01\x00" + vb)
    return _tlv(0x30, b"\x02\x01\x01" + _tlv(0x04, b"mcp-ro") + pdu)


def test_snmp_parser_rejects_bad_replies() -> None:
    assert snmp_sysname_from_response(_resp()) == "mcp-r1"
    assert snmp_sysname_from_response(_resp(rid=1)) is None  # not our request
    assert snmp_sysname_from_response(_resp(err=2)) is None  # noSuchName
    assert snmp_sysname_from_response(_resp(value=b"\x80\x00")) is None  # noSuchObject
    assert snmp_sysname_from_response(_resp()[:-3]) is None  # truncated
    assert snmp_sysname_from_response(b"\x30\x84\xff\xff\xff\xff") is None  # silly length


async def test_snmp_probe_against_loopback_responder() -> None:
    from cml_mcp.verify import SnmpProbe, snmp_probe

    loop = asyncio.get_running_loop()

    class Responder(asyncio.DatagramProtocol):
        def connection_made(self, transport: Any) -> None:
            self.t = transport

        def datagram_received(self, data: bytes, addr: Any) -> None:
            self.t.sendto(_resp(), addr)

    transport, _ = await loop.create_datagram_endpoint(Responder, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        ok, detail = await snmp_probe(SnmpProbe(host="127.0.0.1", community="mcp-ro", port=port), timeout=2)
    finally:
        transport.close()
    assert ok and "mcp-r1" in detail and "mcp-ro" not in detail
    ok, _ = await snmp_probe(SnmpProbe(host="127.0.0.1", community="x", port=port), timeout=1)
    assert ok is False  # nothing listens any more


async def test_console_failure_fails_every_planned_check(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from stutters_mcp_core import Unreachable

    class Broken:
        async def __aenter__(self) -> ConsoleSession:
            raise Unreachable("console server down")

        async def __aexit__(self, *exc: object) -> None:
            return None

    _fake_recipe(monkeypatch, 1)
    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Broken())
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake"})
    failed = {c["check"] for c in data["checks"] if not c["ok"]}
    assert {"r1 console", "r1 -> 198.18.134.76", "manager", "r1 has 198.18.128.151", "ssh"} <= failed
