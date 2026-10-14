import asyncio
from collections.abc import Callable

import pytest

from cml_mcp.console import ConsoleSession, Credentials, clean, read_only_problem
from cml_mcp.console import testbed_credentials as parse_testbed


class FakeDevice:
    """A scripted console: reply(written_text) -> output to emit."""

    def __init__(self, reply: Callable[[str], str], banner: str = "") -> None:
        self.reply = reply
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        if banner:
            self.queue.put_nowait(banner)
        self.written: list[str] = []
        self.stdin = self
        self.stdout = self

    def write(self, text: str) -> None:
        self.written.append(text)
        out = self.reply(text)
        if out:
            self.queue.put_nowait(out)

    async def read(self, n: int) -> str:
        return await self.queue.get()


def ios(enable_password: str = "cisco") -> Callable[[str], str]:
    state = {"mode": "user"}

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if state["mode"] == "enable-pw":
            state["mode"] = "priv" if cmd == enable_password else "user"
            return "\r\nr1#" if state["mode"] == "priv" else "\r\n% Bad secrets\r\nr1>"
        if cmd == "":
            return "\r\nr1#" if state["mode"] == "priv" else "\r\nr1>"
        if cmd == "enable":
            state["mode"] = "enable-pw"
            return "enable\r\nPassword: "
        if cmd == "configure terminal":
            state["mode"] = "config"
            return "configure terminal\r\nEnter configuration commands\r\nr1(config)#"
        if state["mode"] == "config":
            if cmd == "end":
                state["mode"] = "priv"
                return "end\r\nr1#"
            if cmd.startswith("bogus"):
                return f"{cmd}\r\n   ^\r\n% Invalid input detected at '^' marker.\r\n\r\nr1(config)#"
            return f"{cmd}\r\nr1(config)#"
        if cmd == "terminal length 0":
            return "terminal length 0\r\nr1#"
        if cmd == "show long":
            return "show long\r\nline1\r\n --More-- "
        if text == " ":
            return "\x08\x08\x08\x08\x08\x08\x08\x08\x08line2\r\nr1#"
        return f"{cmd}\r\noutput of {cmd}\r\n\r\nr1#"

    return reply


async def test_wake_enables_and_runs() -> None:
    dev = FakeDevice(ios())
    s = ConsoleSession(dev, Credentials("cisco", "cisco", "cisco"), timeout=2)
    assert await s.wake() == "r1#"
    assert "enable\r" in dev.written
    assert await s.run("show clock") == "output of show clock"
    assert await s.run("show long") == "line1\nline2"


async def test_wake_logs_in() -> None:
    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        return {"": "\r\nlogin: ", "cisco": "cisco\r\nPassword: "}.get(cmd, "\r\nhost:~$ ")

    s = ConsoleSession(FakeDevice(reply), Credentials("cisco", "pw"), timeout=2)
    assert await s.wake() == "host:~$"


async def test_wake_without_credentials_fails_cleanly() -> None:
    from stutters_mcp_core import AuthError

    s = ConsoleSession(FakeDevice(lambda t: "\r\nUsername: "), Credentials(), timeout=2)
    with pytest.raises(AuthError, match="pyATS username"):
        await s.wake()


async def test_run_ignores_late_syslog_prompt() -> None:
    dev = FakeDevice(ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    dev.queue.put_nowait("\r\n*%LINK-3-UPDOWN: Interface Loopback7, changed state to up\r\nr1#")
    assert await s.run("show x") == "output of show x"


async def test_run_times_out() -> None:
    from stutters_mcp_core import UpstreamTimeout

    dev = FakeDevice(ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    dev.reply = lambda t: "no prompt ever"
    with pytest.raises(UpstreamTimeout, match="No CLI prompt"):
        await s.run("show x", timeout=1)


@pytest.mark.parametrize(
    "command",
    [
        "show ip int brief",
        "sh run",
        "ping 10.0.0.1",
        "traceroute 1.1.1.1",
        "ip addr",
        "ifconfig",
        "dir flash:",
    ],
)
def test_read_only_allowed(command: str) -> None:
    assert read_only_problem(command) is None


@pytest.mark.parametrize(
    "command",
    [
        "reload",
        "conf t",
        "copy run start",
        "show run | redirect flash:x",
        "show run > x",
        "ip link set eth0 down;",
        "rm -rf /",
        "write erase",
        "show clock\nreload",
        "",
        "ip route add 1.0.0.0/8 via 1.1.1.1 && reboot",
    ],
)
def test_read_only_refused(command: str) -> None:
    assert read_only_problem(command) is not None


def test_testbed_credentials() -> None:
    text = """devices:
  r1:
    credentials:
      default: {username: admin, password: pw}
      enable: {password: en}
  h1: {}
"""
    creds = parse_testbed(text)
    assert creds["r1"] == Credentials("admin", "pw", "en")
    assert creds["h1"] == Credentials()


def test_clean_strips_escapes_and_carriage_returns() -> None:
    assert clean("a\r\r\nb\x1b[Jc\x08") == "a\nbc"


class _Opened:
    def __init__(self, creds: Credentials) -> None:
        self.creds = creds

    async def __aenter__(self) -> ConsoleSession:
        s = ConsoleSession(FakeDevice(ios()), self.creds, timeout=2)
        await s.wake()
        return s

    async def __aexit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def fake_console(monkeypatch: pytest.MonkeyPatch) -> list[Credentials]:
    from cml_mcp.console import ConsoleServer

    seen: list[Credentials] = []

    def fake_open(
        self: ConsoleServer, lab_id: str, node_id: str, creds: Credentials, line: int = 0
    ) -> _Opened:
        seen.append(creds)
        return _Opened(creds)

    monkeypatch.setattr(ConsoleServer, "open", fake_open)
    return seen


async def test_run_commands_tool(lab_api: object, fake_console: list[Credentials]) -> None:
    from stutters_mcp_core.testing import call_tool

    from cml_mcp.server import create_server

    from .conftest import LID, make_settings

    data = await call_tool(
        create_server(make_settings()),
        "cml_run_commands",
        {"lab": LID, "nodes": ["r1", "r2"], "commands": ["show clock"]},
    )
    assert [r.get("outputs", [{}])[0].get("output") for r in data["results"]] == [
        "output of show clock"
    ] * 2, data
    assert fake_console[0].username == "cisco"  # from the lab's pyATS testbed


async def test_configure_node_reports_rejected_lines(
    lab_api: object, fake_console: list[Credentials]
) -> None:
    from fastmcp import Client

    from cml_mcp.server import create_server

    from .conftest import LID, make_settings

    args = {"lab": LID, "node": "r1", "lines": ["hostname r1", "bogus line"], "save": False}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_configure_node", args)).structured_content
        assert preview["preview"]["lines"] == ["hostname r1", "bogus line"]
        applied = (
            await c.call_tool("cml_configure_node", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied["result"]["applied"] == 1
    assert applied["result"]["rejected"][0]["line"] == "bogus line"


@pytest.mark.parametrize(
    "command",
    [
        "hostname evil",
        "ifconfig eth0 down",
        "route add default gw 1.1.1.1",
        "arp -s 1.1.1.1 aa:bb",
        "ip addr add 1.1.1.1/32 dev lo",
        "ip link set eth0 down",
        "ip -4 addr flush dev eth0",
        "ip a | sh",
        "uname | xargs reboot",
        "show run | redirect x",
        "show clock\rreload",
        "ping",
        "dirty",
        "show tech-support",
        "echo $HOME",
        "ip neigh del 1.1.1.1 dev eth0",
    ],
)
def test_allow_list_bypasses_refused(command: str) -> None:
    assert read_only_problem(command) is not None


def test_show_filters_allowed_and_secrets_masked() -> None:
    from cml_mcp.console import mask_secrets

    assert read_only_problem("show running-config | include hostname") is None
    assert read_only_problem("ip -br addr") is None
    assert read_only_problem("route -n") is None
    text = "username cisco privilege 15 secret 9 $9$abc\nsnmp-server community public RO\nhostname r1"
    masked = mask_secrets(text)
    assert "$9$abc" not in masked and "public" not in masked and "hostname r1" in masked


async def test_errors_redact_passwords() -> None:
    from stutters_mcp_core import UpstreamTimeout

    s = ConsoleSession(
        FakeDevice(lambda t: "", banner="Password: hunter2 echoed"), Credentials("u", "hunter2"), 1
    )
    with pytest.raises(UpstreamTimeout) as e:
        await s.read_until(lambda t: False, 1)
    assert "hunter2" not in str(e.value)
