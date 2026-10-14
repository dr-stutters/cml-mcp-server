"""Phase 2 features end to end on a throwaway 'mcp-test-live-p2' lab (always deleted afterwards):
external connector (NAT) + credentials in cml_build_lab, console_pattern waits, CLI address
discovery, the reachability matrix, exec-mode config with an answered question, login updates."""

from collections.abc import Iterator

import pytest
from fastmcp import Client
from stutters_mcp_core.testing import call_tool

from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import rw
from .labkit import confirm_call, delete_lab, find_lab

pytestmark = pytest.mark.live
TITLE = "mcp-test-live-p2"
R1 = """hostname r1
username netadmin privilege 15 secret Lab-pw-123
enable secret Lab-pw-123
interface Ethernet0/0
 ip address dhcp
 no shutdown
interface Ethernet0/1
 ip address 10.77.0.1 255.255.255.0
 no shutdown
line con 0
 login local
 exec-timeout 0 0
end
"""
H1 = """hostname h1
USERNAME=cisco
PASSWORD=cisco
ip link set eth0 up
ip address add 10.77.0.10/24 dev eth0
"""


@pytest.fixture
def cleanup(settings: Settings) -> Iterator[None]:
    if lab_id := find_lab(settings, TITLE):
        delete_lab(settings, lab_id)
    yield
    if lab_id := find_lab(settings, TITLE):
        delete_lab(settings, lab_id)


async def test_phase2_flow(settings: Settings, cleanup: None) -> None:
    s = rw(settings)
    async with Client(create_server(s)) as c:
        connectors = await call_tool(
            create_server(s), "cml_list_external_connectors", {"response_format": "json"}
        )
        assert any(r["label"] == "NAT" for r in connectors["results"])
        # an unknown connector is a preview blocker
        bad = await c.call_tool(
            "cml_build_lab",
            {"title": TITLE, "nodes": [{"label": "e", "definition": "external_connector", "config": "nope"}]},
        )
        assert any("does not exist" in b for b in bad.structured_content["blockers"])

        built = await confirm_call(
            c,
            "cml_build_lab",
            {
                "title": TITLE,
                "nodes": [
                    {"label": "ext", "definition": "external_connector", "config": "NAT"},
                    {
                        "label": "r1",
                        "definition": "iol-xe",
                        "config": R1,
                        "credentials": {"username": "netadmin", "password": "Lab-pw-123"},
                    },
                    {"label": "h1", "definition": "alpine", "config": H1},
                ],
                "links": ["r1:Ethernet0/0 ext", "r1:Ethernet0/1 h1"],
                "start": True,
                "wait": False,
            },
        )
        assert built["started"] is True
        waited = await call_tool(
            create_server(s),
            "cml_wait_for_converged",
            {"lab": TITLE, "node": "r1", "console_pattern": r"%SYS-5-RESTART", "timeout": 300},
        )
        assert "RESTART" in waited["console_match"]
        await call_tool(create_server(s), "cml_wait_for_converged", {"lab": TITLE, "timeout": 300})

        # login comes from the build credentials (console asks for a username)
        reach = await call_tool(
            create_server(s),
            "cml_check_reachability",
            {"lab": TITLE, "nodes": ["r1"], "targets": ["10.77.0.10"]},
        )
        assert reach["all_ok"], reach
        addrs = await call_tool(create_server(s), "cml_get_layer3_addresses", {"lab": TITLE, "source": "cli"})
        found = {(r.get("node"), r.get("ipv4")) for r in addrs["cli"]}
        assert ("r1", "10.77.0.1") in found and ("h1", "10.77.0.10/24") in found, addrs

        # exec mode + an answered question ('clear counters' asks [confirm])
        res = await confirm_call(
            c,
            "cml_configure_node",
            {
                "lab": TITLE,
                "node": "r1",
                "lines": ["clear counters"],
                "mode": "exec",
                "answer_questions": True,
            },
        )
        assert res["applied"] == 1
        unanswered = await c.call_tool(
            "cml_configure_node",
            {"lab": TITLE, "node": "r1", "lines": ["clear counters"], "mode": "exec"},
        )
        token = unanswered.structured_content["confirm"]
        failed = await c.call_tool(
            "cml_configure_node",
            {"lab": TITLE, "node": "r1", "lines": ["clear counters"], "mode": "exec", "confirm": token},
            raise_on_error=False,
        )
        assert failed.is_error and "asked" in failed.content[0].text

        # login update (consoles stay logged in once opened, so only the stored login is checked)
        preview = await c.call_tool(
            "cml_update_node", {"lab": TITLE, "node": "r1", "login_password": "x-Pw-2"}
        )
        assert preview.structured_content["preview"]["changes"]["login_password"]["to"] == "(changed)"
        assert "x-Pw-2" not in preview.content[0].text
        res = await confirm_call(
            c, "cml_update_node", {"lab": TITLE, "node": "r1", "login_password": "x-Pw-2"}
        )
        assert res["changed"] == ["login_password"]

        log = await c.call_tool("cml_get_node_console_log", {"lab": TITLE, "node": "r1", "grep": "RESTART"})
        assert "RESTART" in log.content[0].text and "\x1b" not in log.content[0].text
