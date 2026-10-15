"""L6: node configuration diffs (normalisation, masking, the tools)."""

from collections.abc import Callable
from pathlib import Path

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


# --- L27: section-aware changes ------------------------------------------------------------------

CONFIGS = Path(__file__).resolve().parents[1] / "fixtures" / "configs"


def _pair(name: str) -> tuple[str, str]:
    return (CONFIGS / f"{name}_day0.txt").read_text(), (CONFIGS / f"{name}_running.txt").read_text()


def test_changes_since_boot_iol_shows_only_real_changes() -> None:
    """Live mcp-cml-ospf r1 after 4 config lines: the unified diff said +38/-4."""
    from cml_mcp.diff import config_changes

    day0, running = _pair("iol")
    assert diff_configs(day0, running, a_name="a", b_name="b")["lines_added"] > 30
    r = config_changes(day0, running, a_name="day0", b_name="running")
    assert (r["lines_added"], r["lines_removed"]) == (4, 0) and r["defaults_hidden"] > 20
    for line in ("+ description to-r3", "+ ip ospf cost 50", "+snmp-server community ******** RO"):
        assert line in r["diff"]
    assert "version" not in r["diff"] and "line vty" not in r["diff"]


def test_changes_cat9kv_unchanged_switch_is_nearly_identical() -> None:
    """Live mcp-cml2-ise sw1 straight after boot: the unified diff had 208 added lines."""
    from cml_mcp.diff import config_changes

    r = config_changes(*_pair("cat9kv"), a_name="day0", b_name="running")
    assert r["lines_added"] + r["lines_removed"] <= 2, r.get("diff")


def test_changes_keep_real_changes_to_defaults() -> None:
    from cml_mcp.diff import config_changes

    day0 = "hostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    running = (
        "version 17.18\nhostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\n shutdown\n"
        "interface Ethernet0/1\n no ip address\n shutdown\nip http server\nspanning-tree mode mst\n"
    )
    r = config_changes(day0, running, a_name="a", b_name="b")
    assert "+ shutdown" in r["diff"] and "- no shutdown" in r["diff"]  # a shut interface is a change
    assert "+spanning-tree mode mst" in r["diff"]  # a non-default value isn't hidden
    assert "Ethernet0/1" not in r["diff"] and "ip http server" not in r["diff"] and "version" not in r["diff"]
    # turning a default off shows up as its own 'no ...' line
    r = config_changes("ip http server\n", "no ip http server\n", a_name="a", b_name="b")
    assert "+no ip http server" in r["diff"]
    assert config_changes(day0, day0, a_name="a", b_name="b")["identical"] is True


def _changes(day0: str, running: str) -> dict:  # type: ignore[type-arg]
    from cml_mcp.diff import config_changes

    return config_changes(day0, running, a_name="day0", b_name="running")


def test_changes_acl_order_is_a_change() -> None:
    day0 = "ip access-list extended X\n deny tcp any any eq 23\n permit ip any any\n"
    running = "ip access-list extended X\n permit ip any any\n deny tcp any any eq 23\n"
    assert not _changes(day0, running)["identical"]
    numbered = _changes(
        "access-list 100 deny ip any host 1.1.1.1\naccess-list 100 permit ip any any\n",
        "access-list 100 permit ip any any\naccess-list 100 deny ip any host 1.1.1.1\n",
    )
    assert not numbered["identical"] and " access-list 100" in numbered["diff"]


def test_changes_keep_nesting() -> None:
    day0 = "router bgp 1\n address-family ipv4\n  neighbor 1.1.1.1 activate\n address-family ipv6\n"
    running = "router bgp 1\n address-family ipv4\n address-family ipv6\n  neighbor 1.1.1.1 activate\n"
    r = _changes(day0, running)
    assert "+ address-family ipv6 > neighbor 1.1.1.1 activate" in r["diff"]
    assert "- address-family ipv4 > neighbor 1.1.1.1 activate" in r["diff"]


def test_changes_vty_ranges_compare_per_line() -> None:
    day0 = "line vty 0 15\n access-class 10 in\n"
    running = "line vty 0 4\n access-class 10 in\nline vty 5 15\n"
    r = _changes(day0, running)
    assert " line vty 5 15" in r["diff"] and "- access-class 10 in" in r["diff"], r
    same = _changes(day0, "line vty 0 4\n access-class 10 in\nline vty 5 15\n access-class 10 in\n")
    assert same["identical"], same


def test_changes_default_sections_with_real_content_are_shown() -> None:
    r = _changes(
        "hostname a\n",
        "hostname a\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        "line vty 0 4\n transport input telnet\n password ********\n",
    )
    assert "+interface GigabitEthernet0/0" in r["diff"] and "transport input telnet" in r["diff"]
    assert "vlan 20" in _changes("hostname a\n", "vlan 20\n name X\n")["diff"]  # consumed is day-0 only
    lic = _changes("license boot level a\n", "license boot level b\n")
    assert "+license boot level b" in lic["diff"] and "-license boot level a" in lic["diff"]
    assert "+version 17.18" not in _changes("hostname a\n", "version 17.18\nhostname a\n").get("diff", "")


def test_changes_logical_interfaces_and_scoped_child_defaults() -> None:
    assert "+interface Loopback5" in _changes("hostname a\n", "hostname a\ninterface Loopback5\n")["diff"]
    r = _changes("router ospf 1\n no shutdown\n", "router ospf 1\n")
    assert "- no shutdown" in r["diff"]  # only interfaces drop 'no shutdown'
    r = _changes("interface E0/0\n no shutdown\n", "interface E0/0\n negotiation auto\n")
    assert r["identical"] and r["hidden"]


def test_changes_ignore_drops_whole_sections() -> None:
    day0 = "interface Gi0/0\n description a\ninterface Gi0/1\n description b\n"
    running = "interface Gi0/0\n description changed\ninterface Gi0/1\n description b\n"
    assert _changes(day0, running) and _changes_ignored(day0, running)["identical"]


def _changes_ignored(day0: str, running: str) -> dict:  # type: ignore[type-arg]
    from cml_mcp.diff import config_changes

    return config_changes(day0, running, a_name="a", b_name="b", ignore=[r"^interface Gi0/0$"])


def test_changes_without_day0_hide_nothing() -> None:
    from cml_mcp.diff import config_changes

    r = config_changes("hostname a\n", "hostname a\nversion 17.18\n", a_name="a", b_name="b", day0=None)
    assert "+version 17.18" in r["diff"]


def test_diff_topologies_semantic_sides() -> None:
    from cml_mcp.diff import diff_topologies

    def topo(cfg: str) -> dict:  # type: ignore[type-arg]
        return {
            "lab": {"title": "t"},
            "nodes": [{"id": "n", "label": "r1", "configuration": cfg}],
            "links": [],
        }

    running = "hostname r1\nversion 17.18\nvlan 20\n name X\n"
    stored = "hostname r1\n"
    # a = running lab, b = baseline YAML (stored): the default 'version' hides, the user's vlan doesn't
    d = diff_topologies(topo(running), topo(stored), semantic=True, day0="b")["nodes"]["changed"]["r1"]
    assert "-vlan 20" in d["config_diff"] and "version" not in d["config_diff"]
    # two running labs: nothing hidden, and swapping the sides mirrors the result
    ab = diff_topologies(topo(running), topo(stored), semantic=True)["nodes"]["changed"]["r1"]["config_diff"]
    ba = diff_topologies(topo(stored), topo(running), semantic=True)["nodes"]["changed"]["r1"]["config_diff"]
    assert "-vlan 20" in ab and "+vlan 20" in ba and "-version 17.18" in ab


def test_changes_aaa_server_order_matters() -> None:
    day0 = "aaa group server radius G\n server name a\n server name b\n"
    assert not _changes(day0, "aaa group server radius G\n server name b\n server name a\n")["identical"]
