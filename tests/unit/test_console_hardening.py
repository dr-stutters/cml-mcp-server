"""L4: per-node console lock with a busy error, logout on close, re-login after a lost session."""

import asyncio
from collections.abc import Callable

import pytest
import respx

from cml_mcp._core.testing import call_tool
from cml_mcp.console import ConsoleBusy, ConsoleServer, ConsoleSession, Credentials, OpenConsole, SessionLost
from cml_mcp.convergence import slow_forwarding_hint
from cml_mcp.server import create_server

from .conftest import LID, make_settings
from .test_console import FakeDevice, ios


def server(lock_wait: float) -> ConsoleServer:
    return ConsoleServer("https://cml.test", "u", "p", lock_wait=lock_wait)


async def test_claim_serialises_and_reports_busy() -> None:
    srv = server(lock_wait=0.2)
    order: list[str] = []

    async def holder() -> None:
        async with srv.claim("n1", "r1", "cml_configure_node"):
            order.append("a-in")
            await asyncio.sleep(0.5)
            order.append("a-out")

    task = asyncio.create_task(holder())
    await asyncio.sleep(0.05)
    with pytest.raises(ConsoleBusy, match=r"console of 'r1' is busy \(cml_configure_node"):
        async with srv.claim("n1", "r1", "cml_run_commands"):
            pass
    # another node is independent
    async with srv.claim("n2", "r2", "x"):
        order.append("other-node")
    await task
    # released afterwards
    async with srv.claim("n1", "r1", "x"):
        order.append("b")
    assert order == ["a-in", "other-node", "a-out", "b"]


async def test_claim_waits_within_lock_wait() -> None:
    srv = server(lock_wait=5)
    seen: list[str] = []

    async def use(name: str) -> None:
        async with srv.claim("n1", "r1", name):
            seen.append(f"{name}-in")
            await asyncio.sleep(0.1)
            seen.append(f"{name}-out")

    await asyncio.gather(use("a"), use("b"))
    assert seen in (["a-in", "a-out", "b-in", "b-out"], ["b-in", "b-out", "a-in", "a-out"])


async def test_logout_leaves_config_mode_and_exits() -> None:
    dev = FakeDevice(ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    await s.run("configure terminal")
    assert "(config" in s.last_prompt
    await s.logout()
    assert dev.written[-2:] == ["end\r", "exit\r"] and s.prompt == ""
    await s.logout()  # idempotent
    assert dev.written[-1] == "exit\r"


async def test_open_console_exit_logs_out() -> None:
    dev = FakeDevice(ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    oc = OpenConsole(server(1), "/l/n/0", Credentials())
    oc.session = s
    await oc.__aexit__(None, None, None)
    assert "exit\r" in dev.written


def rebooting_ios() -> Callable[[str], str]:
    base = ios()
    state = {"rebooted": False}

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show version" and not state["rebooted"]:
            state["rebooted"] = True
            return "show version\r\n\r\n*** System restarted ***\r\n\r\nPress RETURN to get started!"
        return base(text)

    return reply


async def test_relogin_after_session_lost() -> None:
    dev = FakeDevice(rebooting_ios())
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    with pytest.raises(SessionLost, match="logged in again"):
        await s.run("show version")
    assert s.prompt == "r1#"  # usable again
    assert dev.written.count("show version\r") == 1  # never re-sent
    assert await s.run("show clock") == "output of show clock"


async def test_output_mentioning_login_is_not_a_logout() -> None:
    base = ios()
    dev: FakeDevice

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show banner":
            # a chunk boundary that looks like a login prompt, then the rest of the output
            asyncio.get_running_loop().call_later(0.2, dev.queue.put_nowait, " ^C hello ^C\r\nr1#")
            return "show banner\r\nbanner login:"
        return base(text)

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    assert "banner login: ^C hello ^C" in await s.run("show banner")


async def test_concurrent_run_commands_do_not_interleave(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = {"n": 0, "max": 0}

    class Opened:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            active["n"] += 1
            active["max"] = max(active["max"], active["n"])
            s = ConsoleSession(FakeDevice(ios()), self.creds, timeout=2)
            await s.wake()
            await asyncio.sleep(0.2)
            return s

        async def __aexit__(self, *exc: object) -> None:
            active["n"] -= 1

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(creds))
    srv = create_server(make_settings())
    args = {"lab": LID, "nodes": ["r1"], "commands": ["show clock"]}
    a, b = await asyncio.gather(
        call_tool(srv, "cml_run_commands", args), call_tool(srv, "cml_run_commands", args)
    )
    assert active["max"] == 1
    for data in (a, b):
        assert "output of show clock" in str(data)


async def test_busy_error_is_reported_per_node(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Slow:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(ios()), self.creds, timeout=2)
            await s.wake()
            await asyncio.sleep(0.6)
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Slow(creds))
    srv = create_server(make_settings(console_lock_wait=0.1))
    args = {"lab": LID, "nodes": ["r1"], "commands": ["show clock"]}
    a, b = await asyncio.gather(
        call_tool(srv, "cml_run_commands", args), call_tool(srv, "cml_run_commands", args)
    )
    texts = str(a) + str(b)
    assert "is busy (cml_run_commands" in texts and "output of show clock" in texts


def test_slow_forwarding_hint() -> None:
    nodes = [
        {"label": "sw1", "state": "BOOTED", "node_definition": "cat9000v-uadp"},
        {"label": "r1", "state": "BOOTED", "node_definition": "iol-xe"},
    ]
    assert "sw1" in (slow_forwarding_hint(nodes) or "") and "r1" not in (slow_forwarding_hint(nodes) or "")
    assert slow_forwarding_hint(nodes[1:]) is None


async def test_logout_never_answers_a_pending_question() -> None:
    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "reload":
            return "reload\r\nProceed with reload? [confirm]"
        if cmd == "\x03":
            return ""  # the device ignores Ctrl-C: the prompt never comes back
        return ios()(text)

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=2)
    await s.wake()
    dev.write("reload\r")  # a question left pending (e.g. after an error path)
    s.at_prompt = False
    await s.logout()
    assert "exit\r" not in dev.written and "\x03" in dev.written


async def test_slow_output_ending_in_login_is_not_a_logout() -> None:
    base = ios()
    dev: FakeDevice

    def reply(text: str) -> str:
        if text.rstrip("\r") == "show run | include login":
            asyncio.get_running_loop().call_later(1.2, dev.queue.put_nowait, "\r\nlogin block-for 60\r\nr1#")
            return "show run | include login\r\nUsername:"
        return base(text)

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials(enable="cisco"), timeout=4)
    await s.wake()
    out = await s.run("show run | include login")
    assert "login block-for 60" in out and dev.written.count("\r") == 1  # no wake RETURN


async def test_relogin_with_username_prompt_logs_in_once() -> None:
    state = {"lost": False, "logins": 0}
    base = ios()

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show version" and not state["lost"]:
            state["lost"] = True
            return "show version\r\n\r\nUser Access Verification\r\n\r\nUsername: "
        if cmd == "" and state["lost"] and not state["logins"]:
            return "\r\nUsername: "
        if cmd == "admin":
            state["logins"] += 1
            return "admin\r\nPassword: "
        if cmd == "pw":
            return "\r\nr1#"
        return base(text)

    dev = FakeDevice(reply)
    s = ConsoleSession(dev, Credentials("admin", "pw", "cisco"), timeout=4)
    await s.wake()
    with pytest.raises(SessionLost, match="logged in again"):
        await s.run("show version")
    assert state["logins"] == 1 and s.prompt == "r1#"


async def test_cancelled_exit_still_closes_the_connection() -> None:
    closed: list[str] = []

    class Proc:
        stdin = None

        def close(self) -> None:
            closed.append("proc")

    oc = OpenConsole(server(1), "/l/n/0", Credentials())
    s = ConsoleSession(FakeDevice(ios()), Credentials(enable="cisco"), timeout=2)
    await s.wake()
    oc.session, oc.proc = s, Proc()
    await oc.__aexit__(asyncio.CancelledError, asyncio.CancelledError(), None)
    assert closed == ["proc"]


async def test_cancelled_waiter_leaves_lock_usable() -> None:
    srv = server(lock_wait=5)
    release = asyncio.Event()

    async def holder() -> None:
        async with srv.claim("n1", "r1", "a"):
            await release.wait()

    h = asyncio.create_task(holder())
    await asyncio.sleep(0)
    waiter = asyncio.create_task(srv.claim("n1", "r1", "b").__aenter__())
    await asyncio.sleep(0.05)
    waiter.cancel()
    release.set()
    await h
    async with srv.claim("n1", "r1", "c"):
        pass
