"""L49: cml_configure_nodes (templated multi-node push) and cml_diff_lab's per-node section view."""

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.console import ConsoleServer, ConsoleSession, Credentials
from cml_mcp.server import create_server
from cml_mcp.templating import placeholders, render, vars_problems

from .conftest import LID, R1, R2, make_settings
from .test_configs import RUNNING_R1
from .test_console import FakeDevice, ios
from .test_write_tools import RW, preview_apply


@pytest.fixture
def consoles(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """A fake IOS console per node; returns {node id: commands written to it}."""
    seen: dict[str, list[str]] = {}

    def reply_for(node_id: str) -> Callable[[str], str]:
        base = ios()

        def reply(text: str) -> str:
            cmd = text.rstrip("\r")
            seen.setdefault(node_id, []).append(cmd)
            if cmd == "show running-config":
                return cmd + "\r\n" + RUNNING_R1.replace("\n", "\r\n") + "\r\nr1#"
            if cmd == "show startup-config":
                return cmd + "\r\n" + RUNNING_R1.replace("\n", "\r\n") + "\r\nr1#"
            if cmd == "write memory":
                return cmd + "\r\nBuilding configuration...\r\n[OK]\r\nr1#"
            return base(text)

        return reply

    class Opened:
        def __init__(self, node_id: str, creds: Credentials) -> None:
            self.node_id, self.creds = node_id, creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(reply_for(self.node_id)), self.creds, timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(node, creds))
    return seen


def config_lines(commands: list[str]) -> list[str]:
    """The lines sent between 'configure terminal' and 'end'."""
    start = commands.index("configure terminal")
    return commands[start + 1 : commands.index("end", start)]


# --- templating ---------------------------------------------------------------------------------


def test_render_fills_placeholders_and_keeps_escaped_braces() -> None:
    lines = ["hostname {label}-x", "ntp server {ntp}", "event manager applet A {{x}}"]
    out, missing = render(lines, {"label": "r1", "ntp": "192.0.2.1"})
    assert out == ["hostname r1-x", "ntp server 192.0.2.1", "event manager applet A {x}"]
    assert missing == []
    assert render(["ip address {addr} {mask}"], {"addr": "1"})[1] == ["mask"]
    assert placeholders(lines) == {"label", "ntp"}


@pytest.mark.parametrize(
    ("values", "problem"),
    [
        ({"x": "${LAB_CLI_PASSWORD}"}, "lab secret"),
        ({"LAB_CLI_PASSWORD": "x"}, "lab secret"),
        ({"x": "a\nb"}, "single line"),
        ({"1x": "a"}, "letters, digits"),
        ({"x": "a" * 600}, "longer than"),
    ],
)
def test_vars_problems(values: dict[str, Any], problem: str) -> None:
    assert any(problem in p for p in vars_problems("r1", values))


def test_plain_vars_are_fine() -> None:
    assert vars_problems("r1", {"tunnel_ip": "192.0.2.11", "area": 0}) == []


# --- the tool -----------------------------------------------------------------------------------


async def test_configure_nodes_one_preview_per_node_lines(
    lab_api: respx.MockRouter, consoles: dict[str, list[str]]
) -> None:
    args = {
        "lab": LID,
        "nodes": ["r1", "r2"],
        "lines": ["hostname {label}-edge", "interface Tunnel1", " ip address {tunnel_ip} 255.255.255.0"],
        "vars": {"r1": {"tunnel_ip": "192.0.2.11"}, "r2": {"tunnel_ip": "192.0.2.12"}},
        "save": True,
    }
    preview, applied = await preview_apply("cml_configure_nodes", args, **RW)
    assert preview["status"] == "preview" and preview["blast_radius"] == 2
    assert preview["preview"]["nodes"] == {
        "r1": ["hostname r1-edge", "interface Tunnel1", " ip address 192.0.2.11 255.255.255.0"],
        "r2": ["hostname r2-edge", "interface Tunnel1", " ip address 192.0.2.12 255.255.255.0"],
    }
    result = applied["result"]
    assert result["nodes_ok"] == 2 and "nodes_with_problems" not in result
    assert {r["node"]: r["saved"] for r in result["results"]} == {"r1": True, "r2": True}
    assert config_lines(consoles[R1])[0] == "hostname r1-edge"
    assert config_lines(consoles[R2])[2] == " ip address 192.0.2.12 255.255.255.0"
    assert "write memory" in consoles[R1] and "write memory" in consoles[R2]


async def test_configure_nodes_mgmt_ip_from_snooped_then_day0(
    lab_api: respx.MockRouter, consoles: dict[str, list[str]]
) -> None:
    snooped = {
        R1: {"name": "r1", "interfaces": {"aa:bb": {"label": "Ethernet0/3", "ip4": ["192.0.2.51"]}}},
        R2: {"name": "r2", "interfaces": {"aa:cc": {"label": "Ethernet0/3", "ip4": []}}},
    }
    lab_api.get(f"/labs/{LID}/layer3_addresses").mock(return_value=httpx.Response(200, json=snooped))
    args = {"lab": LID, "nodes": ["r1", "r2"], "lines": ["logging source-interface {mgmt_ip}"]}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = (await c.call_tool("cml_configure_nodes", args)).structured_content
    assert preview is not None
    nodes = preview["preview"]["nodes"]
    assert nodes["r1"] == ["logging source-interface 192.0.2.51"]  # snooped by CML
    assert nodes["r2"] == ["logging source-interface 10.0.12.2"]  # its only day-0 address
    # an explicit value wins over discovery
    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool("cml_configure_nodes", {**args, "vars": {"r1": {"mgmt_ip": "198.51.100.1"}}})
    assert res.structured_content is not None
    assert res.structured_content["preview"]["nodes"]["r1"] == ["logging source-interface 198.51.100.1"]


async def test_configure_nodes_blockers(lab_api: respx.MockRouter, consoles: dict[str, list[str]]) -> None:
    async def blockers(**kw: Any) -> list[str]:
        args = {"lab": LID, "nodes": ["r1", "r2"], "lines": ["hostname {label}"], **kw}
        preview, applied = await preview_apply("cml_configure_nodes", args, **RW)
        assert preview["status"] == "blocked" and applied is None, preview
        return list(preview["blockers"])

    # the deny-list applies to the rendered lines (a variable can't smuggle in 'reload')
    got = await blockers(lines=["{cmd}"], vars={"r1": {"cmd": "reload"}, "r2": {"cmd": "do write erase"}})
    assert any("deny-list" in b and "reload" in b and "do write erase" in b for b in got)
    got = await blockers(vars={"r1": {"pw": "${LAB_CLI_PASSWORD}"}})
    assert any("lab secret" in b for b in got)
    got = await blockers(lines=["username x secret ${LAB_CLI_PASSWORD}"])
    assert any("does not fill in lab secrets" in b for b in got)
    got = await blockers(lines=["ntp server {ntp}"], vars={"r1": {"ntp": "192.0.2.1"}})
    assert got == ["r2: no value for ['ntp']"]
    got = await blockers(vars={"r3": {"x": "1"}})
    assert any("'r3'" in b and "not one of the nodes" in b for b in got)
    got = await blockers(mode="exec", save=True)
    assert any("save only applies" in b for b in got)
    got = await blockers(vars={"r1": {"label": "other"}})
    assert any("built-in" in b for b in got)
    assert consoles == {}  # nothing was sent anywhere


async def test_configure_nodes_mgmt_ip_missing(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/labs/{LID}/nodes/{R1}").mock(
        return_value=httpx.Response(200, json={"id": R1, "label": "r1", "configuration": "hostname r1"})
    )
    args = {"lab": LID, "nodes": ["r1"], "lines": ["snmp-server source-interface {mgmt_ip}"]}
    preview, _ = await preview_apply("cml_configure_nodes", args, **RW)
    assert preview["status"] == "blocked"
    assert any("vars[node].mgmt_ip" in b for b in preview["blockers"])


async def test_configure_nodes_blast_radius_limit(lab_api: respx.MockRouter) -> None:
    args = {"lab": LID, "nodes": ["r1", "r2"], "lines": ["hostname {label}"]}
    preview, _ = await preview_apply(
        "cml_configure_nodes", args, **RW, mcp_blast_radius_overrides="cml_configure_nodes=1"
    )
    assert preview["status"] == "blocked" and preview["blast_radius"] == 2


async def test_configure_nodes_one_failure_does_not_stop_the_others(
    lab_api: respx.MockRouter, consoles: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    opened = ConsoleServer.open

    def flaky(self: ConsoleServer, lab: str, node: str, creds: Credentials, line: int = 0) -> Any:
        if node == R2:
            raise ConnectionError("console server refused the connection")
        return opened(self, lab, node, creds, line)

    monkeypatch.setattr(ConsoleServer, "open", flaky)
    args = {"lab": LID, "nodes": ["r1", "r2"], "lines": ["bogus {label}", "ntp server 192.0.2.1"]}
    _, applied = await preview_apply("cml_configure_nodes", args, **RW)
    rows = {r["node"]: r for r in applied["result"]["results"]}
    assert rows["r1"]["applied"] == 1 and rows["r1"]["rejected"][0]["line"] == "bogus r1"
    assert "refused" in rows["r2"]["error"]
    assert applied["result"]["nodes_with_problems"] == ["r1", "r2"]


async def test_configure_nodes_rejects_duplicates(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool(
            "cml_configure_nodes",
            {"lab": LID, "nodes": ["r1", R1], "lines": ["hostname x"]},
            raise_on_error=False,
        )
    assert res.is_error and "only once" in res.content[0].text  # type: ignore[union-attr]


# --- cml_diff_lab: lab-wide drift by node and section ------------------------------------------


async def test_diff_lab_against_day0_sections(
    lab_api: respx.MockRouter, consoles: dict[str, list[str]]
) -> None:
    data = await call_tool(
        create_server(make_settings()), "cml_diff_lab", {"lab": LID, "against": "day0", "view": "sections"}
    )
    assert data["against"] == "day0" and data["identical"] is False
    r1 = data["changed"]["r1"]
    sections = {s["section"]: s for s in r1["sections"]}
    assert sections["interface Loopback7"]["change"] == "added"
    assert sections["interface Loopback7"]["lines"] == ["description added by catc"]
    assert "$9$" not in str(data)  # secrets masked
    assert set(data["changed"]) == {"r1", "r2"}  # r2's day-0 differs from the fake running config


async def test_diff_lab_nodes_filter_and_full_view(
    lab_api: respx.MockRouter, consoles: dict[str, list[str]]
) -> None:
    data = await call_tool(
        create_server(make_settings()), "cml_diff_lab", {"lab": LID, "against": "day0", "nodes": ["r1"]}
    )
    assert list(data["changed"]) == ["r1"] and "+interface Loopback7" in data["changed"]["r1"]["diff"]
    assert R2 not in consoles  # only the named node's console was read


async def test_diff_lab_against_saved(lab_api: respx.MockRouter, consoles: dict[str, list[str]]) -> None:
    data = await call_tool(create_server(make_settings()), "cml_diff_lab", {"lab": LID, "against": "saved"})
    assert data["identical"] is True and data["unchanged"] == ["r1", "r2"]


async def test_diff_lab_sections_view_with_baseline(
    lab_api: respx.MockRouter, consoles: dict[str, list[str]]
) -> None:
    from pathlib import Path

    text = (Path(__file__).parent.parent / "fixtures" / "lab_export.yaml").read_text()
    data = await call_tool(
        create_server(make_settings()),
        "cml_diff_lab",
        {"lab": LID, "baseline_yaml": text, "running_configs": True, "view": "sections", "nodes": ["r1"]},
    )
    changed = data["nodes"]["changed"]
    assert list(changed) == ["r1"]
    loop7 = {"section": "interface Loopback7", "change": "removed", "lines": ["description added by catc"]}
    assert loop7 in changed["r1"]["config_sections"]
    assert not (data.get("links") or {}).get("only_in_a")  # the r1<->r2 link is outside the filter


async def test_diff_lab_against_excludes_other_targets(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool(
            "cml_diff_lab", {"lab": LID, "against": "day0", "other_lab": LID}, raise_on_error=False
        )
    assert res.is_error and "exactly one" in res.content[0].text  # type: ignore[union-attr]
