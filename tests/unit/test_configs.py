"""L6: node configuration diffs (normalisation, masking, the tools)."""

from collections.abc import Callable

import pytest
import respx
from stutters_mcp_core.testing import call_tool

from cml_mcp.console import ConsoleServer, ConsoleSession, Credentials
from cml_mcp.diff import diff_configs, normalise_config
from cml_mcp.server import create_server

from .conftest import LID, make_settings
from .test_console import FakeDevice, ios

RUNNING_R1 = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:00:00 UTC Thu Oct 15 2026
!
hostname r1
!
username netadmin privilege 15 secret 9 $9$abcdefgh$XYZ
snmp-server community fake-ro RO
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
interface Loopback7
 description added by catc
interface Ethernet0/0
 ip address 10.0.12.1 255.255.255.0
 no shutdown
!
end"""


def test_normalise_masks_and_drops_noise() -> None:
    lines = normalise_config(RUNNING_R1)
    assert lines[0] == "hostname r1"
    assert "username netadmin privilege 15 secret ********" in lines  # type digit dropped too
    assert "snmp-server community ******** RO" in lines
    assert not any("Last configuration" in ln or ln == "!" or ln == "end" for ln in lines)
    assert "$9$" not in "\n".join(lines)


def test_diff_configs_counts_and_masks() -> None:
    day0 = "hostname r1\nusername netadmin privilege 15 secret Fake-Cli-Pw9\nend\n"
    running = "hostname r1\nusername netadmin privilege 15 secret 9 $9$x$y\nlogging host 10.1.1.1\n"
    d = diff_configs(day0, running, a_name="day0", b_name="running")
    assert d["lines_added"] == 1 and d["lines_removed"] == 0
    assert "+logging host 10.1.1.1" in d["diff"] and "Fake-Cli-Pw9" not in d["diff"]
    assert diff_configs(day0, day0, a_name="a", b_name="b")["identical"] is True
    ignored = diff_configs(day0, running, a_name="a", b_name="b", ignore=[r"^logging host"])
    assert ignored["identical"] is True


def test_diff_configs_caps_lines() -> None:
    big = "\n".join(f"interface Loopback{i}" for i in range(500))
    d = diff_configs("hostname x", big, a_name="a", b_name="b", max_lines=20)
    assert d["lines_added"] == 500 and "more diff lines" in d["diff"]


def running_ios(config: str, startup: str = "hostname r1\nend") -> Callable[[str], str]:
    base = ios()

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if cmd == "show running-config":
            return cmd + "\r\n" + config.replace("\n", "\r\n") + "\r\nr1#"
        if cmd == "show startup-config":
            return cmd + "\r\n" + startup.replace("\n", "\r\n") + "\r\nr1#"
        return base(text)

    return reply


@pytest.fixture
def config_console(monkeypatch: pytest.MonkeyPatch) -> None:
    class Opened:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(running_ios(RUNNING_R1)), self.creds, timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(creds))


async def test_diff_node_config_against_day0(lab_api: respx.MockRouter, config_console: None) -> None:
    data = await call_tool(create_server(make_settings()), "cml_diff_node_config", {"lab": LID, "node": "r1"})
    assert data["node"] == "r1" and data["identical"] is False
    assert "+interface Loopback7" in data["diff"] and "+ description added by catc" in data["diff"]
    assert "$9$" not in data["diff"]


async def test_diff_node_config_baseline_roundtrip(lab_api: respx.MockRouter, config_console: None) -> None:
    srv = create_server(make_settings())
    first = await call_tool(srv, "cml_diff_node_config", {"lab": LID, "node": "r1", "include_running": True})
    baseline = first["running_config"]
    assert "$9$" not in baseline
    same = await call_tool(
        srv, "cml_diff_node_config", {"lab": LID, "node": "r1", "against": "text", "baseline_text": baseline}
    )
    assert same["identical"] is True
    saved = await call_tool(srv, "cml_diff_node_config", {"lab": LID, "node": "r1", "against": "saved"})
    assert saved["lines_added"] > 0 and "startup-config" in saved["diff"]
    other = await call_tool(
        srv, "cml_diff_node_config", {"lab": LID, "node": "r1", "against": "node", "other_node": "r2"}
    )
    assert other["identical"] is True  # the fake console gives both nodes the same config


async def test_diff_node_config_argument_checks(lab_api: respx.MockRouter, config_console: None) -> None:
    from fastmcp import Client

    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool(
            "cml_diff_node_config", {"lab": LID, "node": "r1", "against": "node"}, raise_on_error=False
        )
    assert res.is_error and "other_node" in res.content[0].text  # type: ignore[union-attr]


async def test_diff_lab_running_configs(lab_api: respx.MockRouter, config_console: None) -> None:
    from pathlib import Path

    text = (Path(__file__).parent.parent / "fixtures" / "lab_export.yaml").read_text()
    data = await call_tool(
        create_server(make_settings()),
        "cml_diff_lab",
        {"lab": LID, "baseline_yaml": text, "running_configs": True},
    )
    assert "-interface Loopback7" in data["nodes"]["changed"]["r1"]["config_diff"]  # lab is side a
    assert "running_config_unavailable" not in data


SECRET_CASES = [
    ("snmp-server community public RO", "public"),
    ("ip ospf message-digest-key 1 md5 7 0822455D", "0822455D"),
    ("ntp authentication-key 1 md5 NTPKEY 7", "NTPKEY"),
    (" pre-shared-key local 7 ABCDEF", "ABCDEF"),
    (" pre-shared-key remote 0 abc123", "abc123"),
    (" pre-shared-key address 1.1.1.1 key XKEY", "XKEY"),
    ("crypto isakmp key IKEKEY address 0.0.0.0", "IKEKEY"),
    ("snmp-server user u g v3 auth sha AUTHPASS priv aes 128 PRIVPASS", "AUTHPASS"),
    ("snmp-server user u g v3 auth sha AUTHPASS priv aes 128 PRIVPASS", "PRIVPASS"),
    ("snmp-server host 10.1.1.1 version 2c TRAPCOMM", "TRAPCOMM"),
    ("snmp-server host 10.1.1.1 traps TRAPC2", "TRAPC2"),
    ("snmp-server host 10.1.1.1 community HCOMM", "HCOMM"),
    (" wpa-psk ascii 7 WPAKEY", "WPAKEY"),
    ("username netadmin privilege 15 secret 9 $9$abc$def", "$9$abc$def"),
    ("tacacs-server host 1.1.1.1 key 7 TACKEY", "TACKEY"),
    (" key fake-radius-key", "fake-radius-key"),
    (" client 198.18.134.35 server-key fake-radius-key", "fake-radius-key"),
    ("  key-string 7 0822455D0A16", "0822455D0A16"),
    ("username admin password XYZPW encrypted privilege 15", "XYZPW"),
    (" ikev1 pre-shared-key ASAKEY", "ASAKEY"),
    (" neighbor 1.1.1.1 password BGPPW", "BGPPW"),
    (" password 7 LINEPW", "LINEPW"),
]


@pytest.mark.parametrize(("line", "secret"), SECRET_CASES)
def test_secret_forms_are_masked(line: str, secret: str) -> None:
    from cml_mcp.console import mask_secrets

    assert secret not in mask_secrets(line)
    assert secret not in "\n".join(normalise_config(line))


def test_masking_never_crosses_lines() -> None:
    from cml_mcp.console import mask_secrets

    text = "key chain K\n key 1\nsnmp-server community public RO\ncrypto key generate rsa modulus 2048"
    out = mask_secrets(text).split("\n")
    assert out[0] == "key chain K" and out[2] == "snmp-server community ******** RO"
    assert out[3] == "crypto key generate rsa modulus 2048"


def test_banner_body_is_kept() -> None:
    a = "banner motd ^C\nHello\n!\nend\n^C\nhostname r1"
    b = "banner motd ^C\nHello\n^C\nhostname r1"
    assert diff_configs(a, b, a_name="a", b_name="b")["identical"] is False


def test_bad_ignore_regex() -> None:
    from stutters_mcp_core import InvalidRequest

    with pytest.raises(InvalidRequest, match="bad regular expression"):
        diff_configs("a", "b", a_name="a", b_name="b", ignore=["("])


async def test_running_and_diff_never_carry_secrets(lab_api: respx.MockRouter, config_console: None) -> None:
    data = await call_tool(
        create_server(make_settings()),
        "cml_diff_node_config",
        {"lab": LID, "node": "r1", "include_running": True},
    )
    blob = data["running_config"] + data["diff"]
    assert "$9$" not in blob and "fake-ro" not in blob
