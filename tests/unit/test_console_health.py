"""L41: console health (silent / flooded / login-looping), flood-tolerant reads, the SSH transport and
'unprovable' verify checks. Everything runs on scripted fake consoles and a fake asyncssh connection."""

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
import respx

from cml_mcp._core import AuthError, InvalidRequest
from cml_mcp._core.testing import call_tool
from cml_mcp.console import (
    ConsoleFlooded,
    ConsoleServer,
    ConsoleSession,
    ConsoleSilent,
    Credentials,
    LoginLoop,
    settle,
    strip_syslog,
)
from cml_mcp.server import create_server

from .conftest import LID, make_settings
from .test_console import FakeDevice, ios

SYSLOG = [
    "*Oct 28 10:00:00.123: %DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client",
    "000123: *Oct 28 10:00:01: %SESSION_MGR-5-FAIL: Authorization failed for client (0050.5600.0001)",
    "*00:01:23: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down",
    "2026 Oct 28 10:00:02 sw1 %ETHPORT-5-IF_UP: Interface Ethernet1/1 is up",
]
NOISE = "\r\n" + "\r\n".join(SYSLOG) + "\r\n"


# --- syslog stripping ---------------------------------------------------------------------------


def test_strip_syslog_removes_messages_keeps_output() -> None:
    text = "show clock\n" + "\n".join(SYSLOG) + "\n*10:00:03.000 UTC Wed Oct 28 2026\nr1#"
    out, n = strip_syslog(text)
    assert n == 4
    assert out == "show clock\n*10:00:03.000 UTC Wed Oct 28 2026\nr1#"


def test_strip_syslog_keeps_a_prompt_and_joins_a_split_echo() -> None:
    assert strip_syslog("r1#*Oct 28 10:00:00.123: %LINK-3-UPDOWN: Interface up\n")[0] == "r1#"
    joined, n = strip_syslog("r1#sh*Oct 28 10:00:00.123: %SYS-5-CONFIG_I: Configured\now clock\nout")
    assert n == 1 and joined == "r1#show clock\nout"
    # '% Invalid input' is IOS output, never syslog
    assert strip_syslog("% Invalid input detected at '^' marker.")[1] == 0


def test_settle_only_drops_trailing_syslog() -> None:
    text = "out\n" + SYSLOG[0] + "\nmore\nr1#\n" + SYSLOG[2] + "\n"
    assert settle(text) == "out\n" + SYSLOG[0] + "\nmore\nr1#"
    assert settle("plain\nr1#") == "plain\nr1#"


# --- scripted consoles --------------------------------------------------------------------------


def flooded_ios() -> Callable[[str], str]:
    """IOS behind a syslog flood: every reply is followed by a burst of AAA syslog, and the echo of a
    typed command is split by a message."""
    base = ios()

    def reply(text: str) -> str:
        out = base(text)
        cmd = text.rstrip("\r")
        if cmd.startswith("show "):
            out = out.replace(cmd, cmd[:2] + "\r\n" + SYSLOG[0] + "\r\n" + cmd[2:], 1)
        return out + NOISE

    return reply


async def test_silent_console_raises_console_silent() -> None:
    dev = FakeDevice(lambda t: "")
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=1)
    with pytest.raises(ConsoleSilent, match="silent"):
        await s.wake()
    assert dev.written == ["\r", "\r"]  # two RETURNs, nothing else typed


async def test_flooded_console_reaches_prompt_and_runs() -> None:
    dev = FakeDevice(flooded_ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    assert await s.wake() == "r1#"
    assert s.flooded and s.syslog_seen >= 3
    assert any("flooded with syslog" in n for n in s.notes)
    # the marker RETURN: the prompt had to come back once more before it counted
    assert dev.written[:2] == ["\r", "\r"]
    out = await s.run("show clock")
    assert out == "output of show clock"
    # nothing that changes the configuration was ever sent
    assert not any("logging" in w or "configure" in w for w in dev.written)


async def test_trailing_syslog_does_not_hide_the_prompt_on_a_normal_console() -> None:
    base = ios()
    dev = FakeDevice(lambda t: base(t) + ("\r\n" + SYSLOG[2] + "\r\n" if t.startswith("show") else ""))
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    assert not s.flooded
    assert await s.run("show clock") == "output of show clock"


async def test_only_syslog_raises_console_flooded() -> None:
    dev = FakeDevice(lambda t: NOISE)
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=1)
    with pytest.raises(ConsoleFlooded, match="only syslog"):
        await s.wake()


async def test_login_loop_raises_login_loop() -> None:
    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        return "\r\nPassword: " if cmd == "cisco" else "\r\n% Login invalid\r\n\r\nUsername: "

    s = ConsoleSession(FakeDevice(reply), Credentials("cisco", "wrong"), timeout=2)
    with pytest.raises(LoginLoop, match="login looping"):
        await s.wake()


async def test_no_answer_after_the_login_is_a_timeout_not_silent() -> None:
    """A console that answered (Username:, Password:) and then goes quiet (slow AAA) is not silent."""
    from cml_mcp._core import UpstreamTimeout

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "":
            return "\r\nUsername: "
        return "\r\nPassword: " if cmd == "cisco" else ""

    s = ConsoleSession(FakeDevice(reply), Credentials("cisco", "pw"), timeout=1)
    with pytest.raises(UpstreamTimeout) as err:
        await s.wake()
    assert not isinstance(err.value, (ConsoleSilent, ConsoleFlooded))


# --- tools on fake consoles ---------------------------------------------------------------------


class Opened:
    def __init__(self, device: FakeDevice | None, creds: Credentials, error: Exception | None = None) -> None:
        self.device, self.creds, self.error = device, creds, error

    async def __aenter__(self) -> ConsoleSession:
        if self.error is not None:
            raise self.error
        assert self.device is not None
        s = ConsoleSession(self.device, self.creds, timeout=2)
        await s.wake()
        return s

    async def __aexit__(self, *exc: object) -> None:
        return None


def patch_consoles(monkeypatch: pytest.MonkeyPatch, per_node: dict[str, Any]) -> list[str]:
    """ConsoleServer.open returns per_node[node id] (a reply function or an exception); ssh() returns
    an IOS session and records the host."""
    from .conftest import R1, R2

    ids = {"r1": R1, "r2": R2}
    table = {ids[k]: v for k, v in per_node.items()}
    hosts: list[str] = []

    def fake_open(
        self: ConsoleServer, lab: str, node: str, creds: Credentials, line: int = 0, **kw: Any
    ) -> Opened:
        what = table[node]
        if isinstance(what, Exception):
            return Opened(None, creds, what)
        return Opened(FakeDevice(what()), creds)

    def fake_ssh(self: ConsoleServer, host: str, creds: Credentials, **kw: Any) -> Opened:
        hosts.append(host)
        return Opened(FakeDevice(ios()), creds)

    monkeypatch.setattr(ConsoleServer, "open", fake_open)
    monkeypatch.setattr(ConsoleServer, "ssh", fake_ssh)
    return hosts


async def test_console_health_tool(lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_consoles(
        monkeypatch, {"r1": flooded_ios, "r2": ConsoleSilent("The console sent nothing: it is silent.")}
    )
    data = await call_tool(create_server(make_settings()), "cml_console_health", {"lab": LID})
    rows = {r["node"]: r for r in data["nodes"]}
    assert rows["r1"]["state"] == "flooded" and rows["r1"]["prompt"] == "r1#"
    assert rows["r2"]["state"] == "silent" and "transport='ssh'" in rows["r2"]["hint"]
    assert data["summary"] == {"flooded": 1, "silent": 1} and data["usable"] == ["r1"]


async def test_console_health_login_states(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_consoles(monkeypatch, {"r1": LoginLoop("login looping"), "r2": AuthError("no credentials")})
    data = await call_tool(
        create_server(make_settings()), "cml_console_health", {"lab": LID, "nodes": ["r1", "r2"]}
    )
    states = {r["node"]: r["state"] for r in data["nodes"]}
    assert states == {"r1": "login-looping", "r2": "no-credentials"}


async def test_run_commands_auto_falls_back_to_ssh(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = patch_consoles(monkeypatch, {"r1": ConsoleSilent("silent"), "r2": ios})
    data = await call_tool(
        create_server(make_settings()),
        "cml_run_commands",
        {"lab": LID, "nodes": ["r1", "r2"], "commands": ["show clock"]},
    )
    rows = {r["node"]: r for r in data["results"]}
    assert rows["r1"]["transport"] == "ssh" and rows["r1"]["outputs"][0]["output"] == "output of show clock"
    assert "silent; used SSH to 10.0.12.1" in rows["r1"]["notes"][0]  # its only day-0 address
    assert rows["r2"]["transport"] == "console"
    assert hosts == ["10.0.12.1"]


async def test_run_commands_console_only_reports_the_state(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = patch_consoles(monkeypatch, {"r1": ConsoleSilent("silent")})
    data = await call_tool(
        create_server(make_settings()),
        "cml_run_commands",
        {"lab": LID, "nodes": ["r1"], "commands": ["show clock"], "transport": "console"},
    )
    assert data["results"][0]["console"] == "silent" and hosts == []


async def test_ssh_host_must_be_the_nodes_own_address(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_consoles(monkeypatch, {"r1": ios})
    server = create_server(make_settings())
    args = {"lab": LID, "nodes": ["r1"], "commands": ["show clock"], "transport": "ssh"}
    with pytest.raises(Exception, match="not one of r1's own addresses"):
        await call_tool(server, "cml_run_commands", {**args, "ssh_host": "203.0.113.9"})
    data = await call_tool(server, "cml_run_commands", {**args, "ssh_host": {"r1": "1.1.1.1"}})
    assert data["results"][0]["transport"] == "ssh"


async def test_configure_node_preview_names_the_ssh_fallback(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastmcp import Client

    hosts = patch_consoles(monkeypatch, {"r1": ConsoleSilent("silent")})
    args = {"lab": LID, "node": "r1", "lines": ["ntp server 192.0.2.1"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_configure_node", args)).structured_content
        assert preview["preview"]["transport"] == "auto" and preview["preview"]["ssh_host"] == "10.0.12.1"
        applied = (
            await c.call_tool("cml_configure_node", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied["result"]["applied"] == 1 and applied["result"]["transport"] == "ssh"
    assert hosts == ["10.0.12.1"]


async def test_configure_node_refuses_a_foreign_ssh_host(lab_api: respx.MockRouter) -> None:
    from fastmcp import Client

    args = {"lab": LID, "node": "r1", "lines": ["ntp server 192.0.2.1"], "ssh_host": "198.51.100.7"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_configure_node", args)).structured_content
    assert preview["status"] == "blocked" and "not one of r1's own addresses" in preview["blockers"][0]


def test_ssh_host_map() -> None:
    from cml_mcp.netops import ssh_host_map

    nodes = [{"id": "n1", "label": "r1"}, {"id": "n2", "label": "r2"}]
    assert ssh_host_map({"n2": "192.0.2.2"}, nodes, ["r1", "r2"]) == {"r2": "192.0.2.2"}
    with pytest.raises(InvalidRequest, match="exactly one node"):
        ssh_host_map("192.0.2.1", nodes, ["r1", "r2"])
    with pytest.raises(InvalidRequest, match="not one of the nodes"):
        ssh_host_map({"r9": "192.0.2.9"}, nodes, ["r1", "r2"])


# --- the SSH session itself (fake asyncssh) -----------------------------------------------------


async def test_ssh_console_logs_in_with_pinned_known_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncssh

    seen: dict[str, Any] = {}
    device = FakeDevice(ios())
    device.close = lambda: None  # type: ignore[attr-defined]

    class Conn:
        async def create_process(self, **kw: object) -> FakeDevice:
            return device

        def close(self) -> None:
            seen["closed"] = True

        async def wait_closed(self) -> None: ...

    async def connect(host: str, **kw: Any) -> Conn:
        seen.update(host=host, **kw)
        return Conn()

    monkeypatch.setattr(asyncssh, "connect", connect)
    srv = ConsoleServer("https://cml.test", "u", "p", known_hosts="/pinned/known_hosts")
    async with srv.ssh("192.0.2.10", Credentials("cisco", "pw", "cisco")) as session:
        assert session.prompt == "r1#"
        assert await session.run("show clock") == "output of show clock"
    assert seen["host"] == "192.0.2.10" and seen["known_hosts"] == "/pinned/known_hosts"
    assert seen["username"] == "cisco" and seen["client_keys"] is None and seen["closed"]
    assert "\x1d" not in device.written  # no console-server escape on a direct session


async def test_ssh_console_needs_credentials() -> None:
    srv = ConsoleServer("https://cml.test", "u", "p")
    with pytest.raises(AuthError, match="pyATS username and password"):
        async with srv.ssh("192.0.2.10", Credentials()):
            pass


# --- cml_verify_recipe ----------------------------------------------------------------------------


async def test_verify_marks_silent_console_checks_unprovable(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_verify import _fake_recipe

    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    _fake_recipe(monkeypatch, port)
    patch_consoles(monkeypatch, {"r1": ConsoleSilent("The console sent nothing: it is silent.")})
    # no SSH fallback: r1 has no management address in this run
    import cml_mcp.netops as netops

    async def no_address(*a: object) -> None:
        return None

    monkeypatch.setattr(netops, "management_address", no_address)
    async with server:
        data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake"})
    unproven = {c["check"] for c in data["checks"] if c.get("unprovable")}
    assert {"r1 console", "r1 -> 198.18.134.76", "manager", "r1 has 198.18.128.151"} == unproven
    assert all(c["unprovable"] == "console silent" for c in data["checks"] if c.get("unprovable"))
    assert data["passed"] is False and data["verdict"] == "unprovable"
    assert data["unprovable"]["nodes"] == {"r1": "silent"}
    assert "4 unprovable (console silent), 0 failed" in data["summary"]
