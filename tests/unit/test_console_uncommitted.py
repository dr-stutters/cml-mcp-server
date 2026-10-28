"""#68: IOS XE 'Uncommitted changes found, commit them? [yes/no/CANCEL]' (controller-mode C8000V,
config-transaction) is answered 'no' and reported, instead of stalling the console tools."""

from collections.abc import Callable

import pytest

from cml_mcp.console import UNCOMMITTED, ConsoleSession, Credentials

from .test_console import FakeDevice

QUESTION = "Uncommitted changes found, commit them? [yes/no/CANCEL] "


def controller_mode(state: dict[str, object]) -> Callable[[str], str]:
    """A C8000V in controller mode: 'config-transaction' holds a candidate config until 'commit';
    'end' with uncommitted changes asks QUESTION."""

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        mode = state["mode"]
        if mode == "question":
            if cmd == "no":
                state["mode"], state["pending"] = "priv", False
                state.setdefault("answers", []).append("no")  # type: ignore[union-attr]
                return "no\r\nr1#"
            if cmd == "yes":
                state["mode"], state["committed"] = "priv", True
                state.setdefault("answers", []).append("yes")  # type: ignore[union-attr]
                return "yes\r\nCommit complete.\r\nr1#"
            return f"{cmd}\r\n{QUESTION}"  # RETURN or anything else: asked again
        if mode == "config":
            if cmd == "end":
                if state.get("pending"):
                    state["mode"] = "question"
                    return f"end\r\n{QUESTION}"
                state["mode"] = "priv"
                return "end\r\nr1#"
            if cmd == "commit":
                state["pending"], state["committed"] = False, True
                return "commit\r\nCommit complete.\r\nr1(config)#"
            state["pending"] = True
            return f"{cmd}\r\nr1(config)#"
        if cmd == "config-transaction":
            state["mode"] = "config"
            return "config-transaction\r\nadmin connected from 127.0.0.1 using console on r1\r\nr1(config)#"
        if cmd == "":
            return "\r\nr1#"
        if cmd == "terminal length 0":
            return "terminal length 0\r\nr1#"
        if cmd == "exit":
            return "exit\r\n\r\nr1 con0 is now available\r\n\r\nPress RETURN to get started."
        return f"{cmd}\r\noutput of {cmd}\r\n\r\nr1#"

    return reply


def test_pattern_matches_ios_xe_question() -> None:
    assert UNCOMMITTED.search("end\n" + QUESTION)
    assert UNCOMMITTED.search("Uncommitted changes found, commit them? [yes/no/CANCEL]:")
    assert not UNCOMMITTED.search("Uncommitted changes found, commit them? [yes/no/CANCEL] was asked\nr1#")


async def test_wake_answers_no_to_a_left_over_question() -> None:
    state: dict[str, object] = {"mode": "question", "pending": True}
    dev = FakeDevice(controller_mode(state), banner=QUESTION)
    s = ConsoleSession(dev, Credentials("admin", "pw"), timeout=2)
    assert await s.wake() == "r1#"
    assert state["answers"] == ["no"] and not state.get("committed")
    assert "yes\r" not in dev.written
    assert len(s.notes) == 1 and "discarded" in s.notes[0]


async def test_run_answers_no_even_with_answer_questions() -> None:
    state: dict[str, object] = {"mode": "priv"}
    dev = FakeDevice(controller_mode(state))
    s = ConsoleSession(dev, Credentials("admin", "pw"), timeout=2)
    await s.wake()
    await s.run("config-transaction")
    await s.run("hostname r9")
    out = await s.run("end", answer_questions=True)
    assert state["answers"] == ["no"] and not state.get("committed")
    assert s.last_prompt == "r1#" and s.at_prompt
    assert "Uncommitted" not in out and "no" not in out.split("\n")
    assert len(s.notes) == 1 and "'end'" in s.notes[0] and "commit" in s.notes[0]
    # the session stays usable
    assert await s.run("show clock") == "output of show clock"


async def test_explicit_commit_never_asks() -> None:
    state: dict[str, object] = {"mode": "priv"}
    dev = FakeDevice(controller_mode(state))
    s = ConsoleSession(dev, Credentials("admin", "pw"), timeout=2)
    await s.wake()
    for line in ("config-transaction", "hostname r9", "commit", "end"):
        await s.run(line)
    assert state.get("committed") and not s.notes and "answers" not in state


async def test_logout_from_config_transaction_discards() -> None:
    state: dict[str, object] = {"mode": "priv"}
    dev = FakeDevice(controller_mode(state))
    s = ConsoleSession(dev, Credentials("admin", "pw"), timeout=2)
    await s.wake()
    await s.run("config-transaction")
    await s.run("hostname r9")
    await s.logout()
    assert dev.written[-3:] == ["end\r", "no\r", "exit\r"]
    assert state["answers"] == ["no"] and not state.get("committed")


async def test_question_that_never_clears_is_an_error() -> None:
    from cml_mcp._core import InvalidRequest

    dev = FakeDevice(lambda t: "\r\nr1#" if t == "\r" else f"{t.rstrip()}\r\n{QUESTION}")
    s = ConsoleSession(dev, Credentials(), timeout=2)
    await s.wake()
    with pytest.raises(InvalidRequest, match="kept asking"):
        await s.run("end")


# --- through the tools -----------------------------------------------------------------------


@pytest.fixture
def controller_console(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    from cml_mcp.console import ConsoleServer

    state: dict[str, object] = {}

    class Opened:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(
                FakeDevice(controller_mode(state), banner=state.get("banner", "")), self.creds, 2
            )  # type: ignore[arg-type]
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    def fake_open(
        self: ConsoleServer, lab_id: str, node_id: str, creds: Credentials, line: int = 0
    ) -> Opened:
        return Opened(creds)

    monkeypatch.setattr(ConsoleServer, "open", fake_open)
    return state


async def test_run_commands_reports_discarded_changes(
    lab_api: object, controller_console: dict[str, object]
) -> None:
    from cml_mcp._core.testing import call_tool
    from cml_mcp.server import create_server

    from .conftest import LID, make_settings

    controller_console.update({"mode": "question", "pending": True, "banner": QUESTION})
    data = await call_tool(
        create_server(make_settings()),
        "cml_run_commands",
        {"lab": LID, "nodes": ["r1"], "commands": ["show clock"]},
    )
    res = data["results"][0]
    assert res["outputs"][0]["output"] == "output of show clock", data
    assert "discarded" in res["notes"][0]
    assert controller_console["answers"] == ["no"] and not controller_console.get("committed")


async def test_configure_node_exec_reports_discarded_changes(
    lab_api: object, controller_console: dict[str, object]
) -> None:
    from fastmcp import Client

    from cml_mcp.server import create_server

    from .conftest import LID, make_settings

    controller_console.update({"mode": "priv"})
    args = {
        "lab": LID,
        "node": "r1",
        "lines": ["config-transaction", "hostname r9", "end"],
        "mode": "exec",
        "answer_questions": True,
    }
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_configure_node", args)).structured_content
        applied = (
            await c.call_tool("cml_configure_node", {**args, "confirm": preview["confirm"]})
        ).structured_content
    result = applied["result"]
    assert result["applied"] == 3 and "rejected" not in result, result
    assert "'end'" in result["notes"][0] and "commit" in result["notes"][0]
    assert controller_console["answers"] == ["no"] and not controller_console.get("committed")
