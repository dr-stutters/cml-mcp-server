"""Phase 2: build spec extensions, licences, FTD/NX-OS console handling, address discovery, pings."""

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp._core import AuthError, InvalidRequest, UpstreamError, UpstreamTimeout
from cml_mcp._core.testing import call_tool
from cml_mcp.build import BuildError, NodeCredentials, NodeSpec, build_topology
from cml_mcp.console import ConsoleSession, Credentials, auto_answer
from cml_mcp.console import testbed_credentials as parse_testbed
from cml_mcp.licence import licence_blocker
from cml_mcp.netops import address_commands, parse_addresses, ping_command, ping_result
from cml_mcp.server import create_server

from .conftest import LID, R1, fixture, make_settings
from .test_console import FakeDevice, ios

DEFS = {d["id"]: d for d in fixture("simplified_node_definitions.json")}
FTDV = {
    "id": "ftdv",
    "device": {
        "interfaces": {
            "physical": ["Management0/0", "donotuse1", "GigabitEthernet0/0", "GigabitEthernet0/1"],
            "default_count": 4,
        }
    },
    "image_definitions": ["ftdv-10-0-0"],
}
DEFS["ftdv"] = FTDV
CONNECTORS = [
    {"label": "NAT", "device_name": "virbr0", "tags": ["NAT"], "operational": {"forwarding": "NAT"}},
    {
        "label": "System Bridge",
        "device_name": "bridge0",
        "tags": ["System Bridge"],
        "snooped": True,
        "operational": {"forwarding": "BRIDGE", "interface": "ens192"},
    },
]


# --- build spec -------------------------------------------------------------------------------


def test_build_files_credentials_parameters_and_position() -> None:
    nodes = [
        NodeSpec(
            label="sw",
            definition="iol-xe",
            config="hostname sw",
            files={"extra.txt": "x"},
            credentials=NodeCredentials(username="netadmin", password="pw"),
            parameters={"smbios.serial": "ABC"},
            x=10,
            y=-20,
        )
    ]
    topo, _ = build_topology("t", nodes, [], DEFS)
    node = topo["nodes"][0]
    assert node["configuration"] == [
        {"name": "Main", "content": "hostname sw"},
        {"name": "extra.txt", "content": "x"},
    ]
    assert node["pyats"] == {"username": "netadmin", "password": "pw"}
    assert node["parameters"] == {"smbios.serial": "ABC"}
    assert (node["x"], node["y"]) == (10, -20)


def test_auto_allocation_skips_donotuse() -> None:
    nodes = [NodeSpec(label="ftd", definition="ftdv"), NodeSpec(label="sw", definition="unmanaged_switch")]
    _, wiring = build_topology("t", nodes, ["ftd sw", "ftd sw"], DEFS)
    assert wiring[0].startswith("ftd:Management0/0") and wiring[1].startswith("ftd:GigabitEthernet0/0")


def test_external_connector_checked() -> None:
    notes: list[str] = []
    ok = [NodeSpec(label="ext", definition="external_connector", config="System Bridge\n")]
    topo, _ = build_topology("t", ok, [], DEFS, connectors=CONNECTORS, notes=notes)
    assert topo["nodes"][0]["configuration"] == [{"name": "Main", "content": "System Bridge"}]
    build_topology("t", [NodeSpec(label="e", definition="external_connector")], [], DEFS,
                   connectors=CONNECTORS, notes=notes)  # fmt: skip
    assert "default ('NAT')" in notes[0]
    bad = [NodeSpec(label="ext", definition="external_connector", config="bridge9")]
    with pytest.raises(BuildError, match="does not exist"):
        build_topology("t", bad, [], DEFS, connectors=CONNECTORS)


def test_licence_blocker() -> None:
    usage = {"running_licensed_nodes": 4, "by_lab": {"a": 4}, "limit": 5, "free": 1}
    assert licence_blocker(usage, 1) is None
    assert "only 1 of 5" in str(licence_blocker(usage, 2))
    assert licence_blocker({"running_licensed_nodes": 9, "by_lab": {}}, 3) is None  # limit unknown


# --- console: FTD, NX-OS, questions -------------------------------------------------------------


def ftd() -> Callable[[str], str]:
    state = {"in": False}

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "":
            return "\r\n> " if state["in"] else "\r\nmcp-ftd1 login: "
        if cmd == "admin":
            return "admin\r\nPassword: "
        if cmd == "pw":
            state["in"] = True
            return "\r\nCopyright...\r\n> "
        if cmd == "enable":
            return "enable\r\nSyntax error: Illegal command line\r\n> "
        if cmd == "configure manager delete":
            return f"{cmd}\r\nDo you want to continue[yes/no]:"
        if cmd == "yes":
            return "yes\r\nManager successfully deleted.\r\n> "
        if cmd == "ping system 1.1.1.1":
            return f"{cmd}\r\n64 bytes from 1.1.1.1: icmp_seq=1\r\n"
        if cmd == "show interface bogus":
            return f"{cmd}\r\nSyntax error: Illegal command line\r\n> show interface bogus"
        if cmd == "\x15":
            return "\r\x1b[K> "
        if cmd == "\x03":
            return "^C\r\n1 packets transmitted, 1 received, 0% packet loss\r\n> "
        return f"{cmd}\r\noutput\r\n> "

    return reply


async def test_ftd_login_skips_enable_and_answers_questions() -> None:
    dev = FakeDevice(ftd())
    s = ConsoleSession(dev, Credentials("admin", "pw", os="fxos"), timeout=2)
    assert await s.wake() == ">"
    assert "enable\r" not in dev.written
    with pytest.raises(InvalidRequest, match="asked"):
        await s.run("configure manager delete")
    dev.queue.put_nowait("\r\n> ")
    out = await s.run("configure manager delete", answer_questions=True)
    assert "successfully deleted" in out and "yes\r" in dev.written


async def test_ftd_refilled_command_after_syntax_error_is_cleared() -> None:
    dev = FakeDevice(ftd())
    s = ConsoleSession(dev, Credentials("admin", "pw", os="fxos"), timeout=2)
    await s.wake()
    out = await s.run("show interface bogus")
    assert "Syntax error: Illegal command line" in out and "\x15" in dev.written
    assert dev.written[dev.written.index("\x15") + 1] == "\r"  # fresh prompt, line already cleared
    assert "show interface bogus" not in out.splitlines()[-1]
    assert "output" in await s.run("show version")  # the session is usable afterwards


async def test_refill_detection_ignores_ordinary_output() -> None:
    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show log":
            return f"{cmd}\r\nSyntax error: Illegal command line\r\n> show other\r\nmore\r\n> "
        return ftd()(text)

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials("admin", "pw", os="fxos"), timeout=2)
    await s.wake()
    out = await s.run("show log")  # the '> show other' line isn't the command we sent
    assert "more" in out and "\x15" not in dev.written
    ios_dev = FakeDevice(ftd())  # non-FTD sessions never look for refills
    s2 = ConsoleSession(ios_dev, Credentials("admin", "pw", os="ios"), timeout=1)
    s2.prompt = ">"
    s2.at_prompt = True
    with pytest.raises(UpstreamError):
        await s2.run("show interface bogus")
    assert "\x15" not in ios_dev.written


async def test_interrupt_after_sends_ctrl_c() -> None:
    dev = FakeDevice(ftd())
    s = ConsoleSession(dev, Credentials("admin", "pw", os="fxos"), timeout=2)
    await s.wake()
    out = await s.run("ping system 1.1.1.1", interrupt_after=0.5)
    assert "\x03" in dev.written and ping_result(out)["ok"]


async def test_timeout_interrupts_runaway_command() -> None:
    dev = FakeDevice(ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    dev.reply = lambda t: "" if t == "\x03" else "still going"
    with pytest.raises(UpstreamTimeout):
        await s.run("ping 1.1.1.1", timeout=1)
    assert dev.written[-1] == "\x03"


async def test_forced_password_change_is_reported() -> None:
    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        return {"": "\r\nlogin: ", "admin": "admin\r\nPassword: "}.get(cmd, "\r\nEnter new password: ")

    s = ConsoleSession(FakeDevice(reply), Credentials("admin", "pw", os="fxos"), timeout=2)
    with pytest.raises(AuthError, match="demands a new password"):
        await s.wake()


async def test_nxos_poap_is_skipped() -> None:
    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "":
            return "\r\nAbort Power On Auto Provisioning [yes - continue with normal setup, skip - bypass]:"
        return "\r\nswitch# " if cmd == "skip" else "\r\nswitch# "

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials(os="nxos"), timeout=2)
    assert await s.wake() == "switch#"
    assert "skip\r" in dev.written


@pytest.mark.parametrize(
    ("question", "answer"),
    [("Proceed with reload? [confirm]", ""), ("Do you want to continue[yes/no]:", "yes"),
     ("Overwrite? (y/n)", "y"), ("Destination filename [startup-config]?", "")],
)  # fmt: skip
def test_auto_answer(question: str, answer: str) -> None:
    assert auto_answer(question) == answer


def test_testbed_os() -> None:
    creds = parse_testbed("devices:\n  ftd1:\n    os: fxos\n    credentials: {default: {username: admin}}\n")
    assert creds["ftd1"].os == "fxos"


# --- addresses and pings ---------------------------------------------------------------------

IOS_BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       198.18.128.152  YES TFTP   up                    up
GigabitEthernet2       10.255.12.1     YES TFTP   up                    up
GigabitEthernet3       unassigned      YES unset  administratively down down
Loopback0              10.255.255.1    YES TFTP   up                    up"""
NXOS_BRIEF = """IP Interface Status for VRF "management"(2)
Interface            IP Address      Interface Status
mgmt0                192.168.0.5     protocol-up/link-up/admin-up"""
FTD_NETWORK = """===============[ System Information ]===============
IPv4 Default route
  Gateway                 : 198.18.128.1
======================[ eth0 ]======================
----------------------[ IPv4 ]----------------------
Address                   : 198.18.128.151
Netmask                   : 255.255.192.0"""
LINUX = (
    "1: lo    inet 127.0.0.1/8 scope host lo\n"
    "2: eth0    inet 10.10.10.100/24 brd 10.10.10.255 scope global eth0"
)


def test_parse_addresses() -> None:
    assert [r["ipv4"] for r in parse_addresses("show ip interface brief", IOS_BRIEF)] == [
        "198.18.128.152",
        "10.255.12.1",
        "10.255.255.1",
    ]
    assert parse_addresses("show ip interface brief vrf all", NXOS_BRIEF) == [
        {"interface": "mgmt0", "ipv4": "192.168.0.5"}
    ]
    assert parse_addresses("show network", FTD_NETWORK) == [{"interface": "eth0", "ipv4": "198.18.128.151"}]
    assert parse_addresses("ip -4 -o addr", LINUX) == [{"interface": "eth0", "ipv4": "10.10.10.100/24"}]
    assert address_commands("fxos") == ["show network", "show interface ip brief"]
    assert address_commands("weird") == []


def test_ping_commands_and_results() -> None:
    assert ping_command("iosxe", "1.1.1.1", 3) == ("ping 1.1.1.1 repeat 3 timeout 2", None)
    assert (
        ping_command("iosxe", "1.1.1.1", 3, "Mgmt-vrf")[0] == "ping vrf Mgmt-vrf 1.1.1.1 repeat 3 timeout 2"
    )
    assert ping_command("nxos", "1.1.1.1", 2, "management")[0] == "ping 1.1.1.1 count 2 vrf management"
    assert ping_command("linux", "1.1.1.1", 2)[0] == "ping -c 2 -W 2 1.1.1.1"
    assert ping_command("fxos", "1.1.1.1", 3, "management") == ("ping system 1.1.1.1", 4.5)
    assert ping_result("Success rate is 80 percent (4/5), round-trip")["success_percent"] == 80
    assert ping_result("3 packets transmitted, 0 received, 100% packet loss")["ok"] is False
    assert ping_result("garbage")["ok"] is False


# --- tools ----------------------------------------------------------------------------------


@pytest.fixture
def fake_ios_console(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from cml_mcp.console import ConsoleServer

    commands: list[str] = []

    def reply_factory() -> Callable[[str], str]:
        base = ios()

        def reply(text: str) -> str:
            cmd = text.rstrip("\r")
            commands.append(cmd)
            if cmd.startswith("ping "):
                return f"{cmd}\r\nSuccess rate is 100 percent (3/3), round-trip min/avg/max = 1/1/1 ms\r\nr1#"
            if cmd == "show ip interface brief":
                return f"{cmd}\r\n{IOS_BRIEF}\r\nr1#"
            return base(text)

        return reply

    class Opened:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(reply_factory()), self.creds, timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(creds))
    return commands


async def test_check_reachability_tool(lab_api: respx.MockRouter, fake_ios_console: list[str]) -> None:
    data = await call_tool(
        create_server(make_settings()),
        "cml_check_reachability",
        {"lab": LID, "nodes": ["r1"], "targets": ["198.18.128.1", "198.18.134.35"], "count": 3},
    )
    assert data["all_ok"] is True and len(data["results"]) == 2
    assert "ping 198.18.134.35 repeat 3 timeout 2" in fake_ios_console


async def test_check_reachability_rejects_bad_target(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool(
            "cml_check_reachability", {"lab": LID, "nodes": ["r1"], "targets": ["1.1.1.1; reload"]},
            raise_on_error=False,
        )  # fmt: skip
    assert res.is_error and "Not an IP address" in res.content[0].text


async def test_layer3_addresses_from_cli(lab_api: respx.MockRouter, fake_ios_console: list[str]) -> None:
    data = await call_tool(
        create_server(make_settings()), "cml_get_layer3_addresses", {"lab": LID, "source": "both"}
    )
    assert {"node": "r1", "interface": "GigabitEthernet1", "ipv4": "198.18.128.152"} in data["cli"]
    assert "addresses" in data


async def test_list_external_connectors(api: respx.MockRouter) -> None:
    api.get("/system/external_connectors").mock(return_value=httpx.Response(200, json=CONNECTORS))
    data = await call_tool(
        create_server(make_settings()), "cml_list_external_connectors", {"response_format": "json"}
    )
    rows = {r["label"]: r for r in data["results"]}
    assert rows["System Bridge"]["forwarding"] == "BRIDGE" and rows["NAT"]["device_name"] == "virbr0"


async def test_console_log_grep_and_ansi(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/labs/{LID}/nodes/{R1}/consoles/0/log").mock(
        return_value=httpx.Response(200, json="|1|boot ok\n|2|\x1b[1;32mOK\x1b[0m done\n|3|login: ")
    )
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool("cml_get_node_console_log", {"lab": LID, "node": "r1", "grep": "ok"})
    assert res.content[0].text == "boot ok\nOK done"


async def test_configure_node_exec_mode(lab_api: respx.MockRouter, fake_ios_console: list[str]) -> None:
    args: dict[str, Any] = {"lab": LID, "node": "r1", "lines": ["clear counters"], "mode": "exec"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_configure_node", args)).structured_content
        applied = (
            await c.call_tool("cml_configure_node", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied["result"]["applied"] == 1
    assert "configure terminal" not in fake_ios_console and "clear counters" in fake_ios_console


def _licence_api(api: respx.MockRouter, running: int) -> None:
    nodes = [
        {"id": f"n{i}", "lab_id": "L1", "state": "BOOTED", "node_definition": "iol-xe"}
        for i in range(running)
    ] + [{"id": "e", "lab_id": "L1", "state": "BOOTED", "node_definition": "external_connector"}]
    api.get("/nodes").mock(return_value=httpx.Response(200, json=nodes))
    api.get("/labs").mock(return_value=httpx.Response(200, json=[{"id": "L1", "lab_title": "busy"}]))
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/system/external_connectors").mock(return_value=httpx.Response(200, json=CONNECTORS))


async def test_build_lab_preview_blocks_on_licences(api: respx.MockRouter) -> None:
    _licence_api(api, 4)
    settings = make_settings(mcp_enable_writes=True, node_license_limit=5)
    data = await call_tool(
        create_server(settings),
        "cml_build_lab",
        {
            "title": "x",
            "start": True,
            "nodes": [
                {"label": "ext", "definition": "external_connector", "config": "System Bridge"},
                {"label": "r1", "definition": "iol-xe"},
                {"label": "r2", "definition": "iol-xe"},
            ],
            "links": ["r1 ext", "r1 r2"],
        },
    )
    assert data["preview"]["licensed_nodes"] == 2
    assert any("only 1 of 5" in b and "'busy' (4)" in b for b in data["blockers"]), data


async def test_build_lab_start_licence_error_is_explained(api: respx.MockRouter) -> None:
    _licence_api(api, 5)
    api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new-lab"}))
    api.put("/labs/new-lab/start").mock(
        return_value=httpx.Response(400, json={"code": 400, "description": "5 of 5 node licenses are in use"})
    )
    args: dict[str, Any] = {
        "title": "x",
        "start": True,
        "nodes": [{"label": "r1", "definition": "iol-xe"}],
    }
    async with Client(create_server(make_settings(mcp_enable_writes=True, node_license_limit=50))) as c:
        preview = (await c.call_tool("cml_build_lab", args)).structured_content
        res = await c.call_tool(
            "cml_build_lab", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    assert res.is_error
    text = res.content[0].text
    assert "was created (new-lab) but not started" in text and "'busy' (5)" in text


def test_licence_error_passthrough() -> None:
    import asyncio

    from cml_mcp.client import CmlApp
    from cml_mcp.licence import explain_licence_error

    err = UpstreamError("something else")
    app = CmlApp(make_settings())
    assert asyncio.run(explain_licence_error(app, err, "x")) is err


async def test_unanswered_question_is_cancelled() -> None:
    dev = FakeDevice(ftd())
    s = ConsoleSession(dev, Credentials("admin", "pw", os="fxos"), timeout=2)
    await s.wake()
    with pytest.raises(InvalidRequest, match="cancelled"):
        await s.run("configure manager delete")
    assert dev.written[-1] == "\x03" and "yes\r" not in dev.written


async def test_question_like_output_is_not_a_question() -> None:
    import asyncio

    dev: FakeDevice

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show banner":
            loop = asyncio.get_running_loop()
            loop.call_later(0.2, dev.queue.put_nowait, "? more text\r\nr1#")
            return "show banner\r\nAuthorized users only (y/n)"
        return "\r\nr1#"

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials(), timeout=3)
    await s.wake()
    out = await s.run("show banner")
    assert "more text" in out


async def test_batch_continues_after_a_command_timeout(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cml_mcp.console import ConsoleServer

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "ping 9.9.9.9 repeat 3 timeout 2":
            return f"{cmd}\r\nsilence"
        if cmd.startswith("ping "):
            return f"{cmd}\r\nSuccess rate is 100 percent (3/3)\r\nr1#"
        return "\r\nr1#" if cmd in ("", "\x03") else f"{cmd}\r\nr1#"

    class Opened:
        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(reply), Credentials(), timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened())
    data = await call_tool(
        create_server(make_settings()),
        "cml_check_reachability",
        {"lab": LID, "nodes": ["r1"], "targets": ["9.9.9.9", "1.1.1.1"], "count": 3},
    )
    by_target = {r["target"]: r for r in data["results"]}
    assert "error" in by_target["9.9.9.9"] and by_target["1.1.1.1"]["ok"] is True


def test_ftd_rejects_other_vrfs_and_targets_must_be_whole() -> None:
    from cml_mcp.tools.network import TARGET

    with pytest.raises(InvalidRequest):
        ping_command("fxos", "1.1.1.1", 3, "inside")
    assert TARGET.fullmatch("1.1.1.1") and not TARGET.fullmatch("1.1.1.1\n")
