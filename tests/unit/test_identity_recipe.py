"""L34: the ise-fmc-identity recipe, ise_session verify probes and recipe actions."""

from typing import Any

import httpx
import pytest
import respx

from cml_mcp._core.testing import call_tool
from cml_mcp.console import ConsoleServer, ConsoleSession, Credentials
from cml_mcp.recipes import get_recipe, recipe_actions, recipe_names
from cml_mcp.server import create_server
from cml_mcp.verify import IseSessionProbe, Probe, active_sessions, contract_of, ise_session_probe

from .conftest import LAB, make_settings
from .test_console import FakeDevice, ios
from .test_write_tools import preview_apply

ISE = "https://ise.example.test"
ACTIVE = """<?xml version="1.0" encoding="UTF-8"?>
<activeList noOfActiveSession="3">
<activeSession><user_name>mcp-alice</user_name><calling_station_id>52:54:00:AA:BB:CC</calling_station_id>
<nas_ip_address>198.18.128.194</nas_ip_address><framed_ip_address>10.10.34.100</framed_ip_address></activeSession>
<activeSession><user_name>mcp-bob</user_name><calling_station_id>52:54:00:11:22:33</calling_station_id>
<nas_ip_address>198.18.128.154</nas_ip_address><framed_ip_address>10.10.10.5</framed_ip_address></activeSession>
<activeSession><user_name>52-54-00-61-3D-9E</user_name><nas_ip_address>198.18.128.194</nas_ip_address></activeSession>
</activeList>"""


def probe(**kw: Any) -> IseSessionProbe:
    base: dict[str, Any] = {
        "url": ISE,
        "username": "u",
        "password": "fake-ise-pw",
        "user": "^mcp-(alice|bob)$",
    }
    return IseSessionProbe(**{**base, **kw})


def test_recipe_shape() -> None:
    r = get_recipe("ise-fmc-identity")
    labels = {n["label"]: n["definition"] for n in r["build"]["nodes"]}
    assert labels["sw1"] == "cat9000v-uadp" and labels["ftd"] == "ftdv" and labels["client"] == "ubuntu"
    links = set(r["build"]["links"])
    assert "sw1:GigabitEthernet1/0/3 ftd:GigabitEthernet0/1" in links  # client VLAN gateway = FTD inside
    assert "ftd:GigabitEthernet0/0 outside-host:ens2" in links
    client = next(n for n in r["build"]["nodes"] if n["label"] == "client")["config"]
    assert "${LAB_AD_TEST_USER_PASSWORD}" in client and 'identity="mcp-alice"' in client
    assert 'identity="mcp-bob"' in client and "BEGIN CERTIFICATE" in client  # validates ISE via mitchcloud-CA
    sw1 = next(n for n in r["build"]["nodes"] if n["label"] == "sw1")["config"]
    assert "default-router 10.10.34.1" in sw1 and "device-tracking attach-policy" in sw1
    kinds = {k for p in contract_of(r).probes for k in ("command", "tcp", "ise_session") if getattr(p, k)}
    assert kinds == {"command", "tcp", "ise_session"}


def test_actions_switch_users() -> None:
    a = recipe_actions(get_recipe("ise-fmc-identity"))
    assert set(a) == {"login-alice", "login-bob", "logoff"}
    assert a["login-bob"]["node"] == "client" and "mcp-bob" in a["login-bob"]["expect"]


@pytest.mark.parametrize("name", recipe_names())
def test_every_recipe_actions_parse(name: str) -> None:
    recipe_actions(get_recipe(name))


@pytest.mark.parametrize(
    "action",
    [
        {"node": "client"},
        {"node": "nope", "command": "x"},
        {"node": "client", "command": "a\nb"},
        {"node": "client", "command": "x", "timeout": 9999},
    ],
)
def test_bad_actions_rejected(action: dict[str, Any]) -> None:
    r = {"name": "x", "build": {"nodes": [{"label": "client"}]}, "actions": {"a": action}}
    with pytest.raises(ValueError):
        recipe_actions(r)


def test_mcp_check_prefix_allowed_but_not_shell() -> None:
    assert Probe(name="x", node="c", command="mcp-check tcp 172.31.34.10 23").command
    with pytest.raises(ValueError, match="control or shell"):
        Probe(name="x", node="c", command="mcp-check tcp 1.2.3.4 23; reboot")
    with pytest.raises(ValueError, match="not a read-only"):
        Probe(name="x", node="c", command="mcp-checker tcp")


@pytest.mark.parametrize("url", ["http://ise", "https://ise/admin", "https://u:p@ise", "ise.example"])
def test_ise_probe_url_validation(url: str) -> None:
    with pytest.raises(ValueError):
        probe(url=url)


def test_active_sessions_parser() -> None:
    rows = active_sessions(ACTIVE)
    assert len(rows) == 3 and rows[0]["framed_ip_address"] == "10.10.34.100"


@respx.mock(assert_all_called=False)
async def test_ise_session_probe_outcomes(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.get(f"{ISE}/admin/API/mnt/Session/ActiveList")
    route.mock(return_value=httpx.Response(200, text=ACTIVE))
    ok, detail = await ise_session_probe(probe(nas_ip="198.18.128.194", framed_ip=r"^10\.10\.34\."))
    assert ok and detail["sessions"][0]["user_name"] == "mcp-alice"
    assert route.calls.last.request.headers["authorization"].startswith("Basic ")
    ok, detail = await ise_session_probe(probe(nas_ip="198.18.128.194", framed_ip=r"^10\.99\."))
    assert not ok and "framed IP" in detail["problem"]
    ok, detail = await ise_session_probe(probe(nas_ip="198.18.128.1"))
    assert not ok and detail["active_sessions"] == 3 and "fake-ise-pw" not in str(detail)
    route.mock(return_value=httpx.Response(401))
    ok, detail = await ise_session_probe(probe())
    assert not ok and "refused" in detail
    route.mock(return_value=httpx.Response(200, text="<html>login</nothtml>"))
    ok, detail = await ise_session_probe(probe())
    assert not ok and "not its session XML" in detail


def _fake_action_recipe(monkeypatch: pytest.MonkeyPatch) -> None:
    import cml_mcp.recipes as recipes

    recipe: dict[str, Any] = {
        "name": "fakeact",
        "build": {"title": LAB["lab_title"], "nodes": [{"label": "r1", "definition": "iol-xe"}]},
        "verify": {"nodes": ["r1"], "targets": ["198.18.128.1"]},
        "actions": {
            "login-bob": {
                "description": "log in as bob",
                "node": "r1",
                "command": "sudo /usr/local/sbin/mcp-dot1x-login bob",
                "expect": "user=mcp-bob port=Authorized",
                "timeout": 30,
            }
        },
    }
    real = recipes._load_all()
    monkeypatch.setattr(recipes, "_load_all", lambda: {**real, "fakeact": recipe})


def _console(monkeypatch: pytest.MonkeyPatch, sent: list[str], answer: str) -> None:
    base = ios()

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd.startswith("sudo "):
            sent.append(cmd)
            return f"{cmd}\r\n{answer}\r\nr1#"
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


async def test_run_recipe_action_preview_then_apply(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_action_recipe(monkeypatch)
    sent: list[str] = []
    _console(monkeypatch, sent, "user=mcp-bob port=Authorized eap=SUCCESS ip=10.10.34.100/24")
    args = {"recipe": "fakeact", "action": "login-bob"}
    preview, done = await preview_apply("cml_run_recipe_action", args)
    assert preview["status"] == "preview" and "mcp-dot1x-login bob" in str(preview)
    assert done["status"] == "applied" and done["result"]["ok"] is True, done
    assert sent == ["sudo /usr/local/sbin/mcp-dot1x-login bob"]


async def test_run_recipe_action_reports_mismatch_and_unknown(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_action_recipe(monkeypatch)
    sent: list[str] = []
    _console(monkeypatch, sent, "user=mcp-bob port=Unauthorized eap=FAILURE ip=none")
    _, done = await preview_apply("cml_run_recipe_action", {"recipe": "fakeact", "action": "login-bob"})
    assert done["result"]["ok"] is False and "Unauthorized" in done["result"]["output"]
    server = create_server(make_settings(mcp_enable_writes=True))
    with pytest.raises(Exception, match="no action 'rm-rf'"):
        await call_tool(server, "cml_run_recipe_action", {"recipe": "fakeact", "action": "rm-rf"})


def test_validation_errors_never_echo_resolved_secrets() -> None:
    with pytest.raises(ValueError) as e:
        contract_of(
            {
                "verify": {
                    "probes": [
                        {
                            "name": "x",
                            "ise_session": {
                                "url": "http://bad",
                                "username": "u",
                                "password": "fake-ise-pw",
                                "user": "a",
                            },
                        },
                        {"name": "y", "snmp": {"host": "h", "community": "fake-ro-c", "port": "x"}},
                    ]
                }
            }
        )
    assert "fake-ise-pw" not in str(e.value) and "fake-ro-c" not in str(e.value)
    assert "fake-ise-pw" not in repr(probe())


def test_probe_prefix_rejects_pipes() -> None:
    with pytest.raises(ValueError, match="no '\\|'"):
        Probe(name="x", node="c", command="mcp-check tcp 1.2.3.4 23 | tee x")


@respx.mock(assert_all_called=False)
async def test_ise_session_probe_refuses_doctype(respx_mock: respx.MockRouter) -> None:
    body = '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY b "c">]><activeList>&b;</activeList>'
    respx_mock.get(f"{ISE}/admin/API/mnt/Session/ActiveList").mock(
        return_value=httpx.Response(200, text=body)
    )
    ok, detail = await ise_session_probe(probe())
    assert not ok and "DOCTYPE" in detail


def test_actions_reject_secret_references() -> None:
    r = {
        "name": "x",
        "build": {"nodes": [{"label": "c"}]},
        "actions": {"a": {"node": "c", "command": "echo ${LAB_CLI_PASSWORD}"}},
    }
    with pytest.raises(ValueError, match="LAB_"):
        recipe_actions(r)


async def test_notes_rename_cannot_redirect_ise_probe(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of L34: a notes substitution that renames a probe must not lift the redirect guard."""
    import cml_mcp.recipes as recipes
    from cml_mcp.recipes import recipe_marker

    from .test_verify import _labs_with_notes

    recipe: dict[str, Any] = {
        "name": "fakeise",
        "build": {"title": LAB["lab_title"], "nodes": [{"label": "r1", "definition": "iol-xe"}]},
        "verify": {
            "booted": [],
            "probes": [
                {
                    "name": "ISE live",
                    "ise_session": {
                        "url": "https://ise.example.test",
                        "username": "u",
                        "password": "fake-ise-pw",
                        "user": "a",
                    },
                },
                {"name": "ssh", "tcp": "127.0.0.1:1"},
            ],
        },
    }
    real = recipes._load_all()
    monkeypatch.setattr(recipes, "_load_all", lambda: {**real, "fakeise": recipe})
    _labs_with_notes(
        monkeypatch,
        recipe_marker(
            "fakeise", {"ise.example.test": "evil.example.test", "ISE": "XSE", "127.0.0.1": "10.9.9.9"}
        ),
    )
    sent: list[str] = []

    async def spy(p: Any, timeout: float = 1.0) -> tuple[bool, str]:  # noqa: ASYNC109
        sent.append(getattr(p, "url", str(p)))
        return True, "ok"

    monkeypatch.setattr("cml_mcp.verify.ise_session_probe", spy)
    monkeypatch.setattr("cml_mcp.verify.tcp_probe", spy)
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fakeise"})
    assert not sent, sent
    assert set(data["skipped"]["checks"]) == {"XSE live", "ssh"}


async def test_run_recipe_action_refuses_unrelated_lab(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    import cml_mcp.recipes as recipes

    _fake_action_recipe(monkeypatch)
    real = recipes._load_all()
    moved = {**real["fakeact"], "build": {**real["fakeact"]["build"], "title": "some-other-title"}}
    monkeypatch.setattr(recipes, "_load_all", lambda: {**real, "fakeact": moved})
    preview, _ = await preview_apply(
        "cml_run_recipe_action", {"recipe": "fakeact", "action": "login-bob", "lab": LAB["lab_title"]}
    )
    assert "no record of being built" in str(preview)
