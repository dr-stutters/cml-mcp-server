"""L16: replica planning (platform mapping, budget) and the cml_replicate_site prompt."""

import httpx
import pytest
import respx
from stutters_mcp_core.testing import assert_prompt_contract, call_tool, load_tool_manifests

from cml_mcp.replica import map_platform, plan_replica
from cml_mcp.server import create_server

from .conftest import fixture, make_settings


@pytest.mark.parametrize(
    ("platform", "light", "faithful", "kind"),
    [
        ("C9300-48U", "ioll2-xe", "cat9000v-uadp", "switch"),
        ("Cisco Catalyst 9500-24Y4C", "ioll2-xe", "cat9000v-uadp", "switch"),
        ("C8300-1N1S-6T", "iol-xe", "cat8000v", "router"),
        ("ISR4451-X/K9", "iol-xe", "cat8000v", "router"),
        ("N9K-C93180YC-EX", "nxosv9000", "nxosv9000", "switch"),
        ("Cisco Secure Firewall Threat Defense for VMware", "ftdv", "ftdv", "firewall"),
        ("ASA5516", "asav", "asav", "firewall"),
        ("C9800-CL-K9", "cat9800", "cat9800", "wlc"),
        ("C9120AXI-B", None, None, "ap"),
        ("Meraki MX67", None, None, "other"),
        ("SNS-3695", None, "ise", "aaa"),
        ("C9KV-UADP-8P", "ioll2-xe", "cat9000v-uadp", "switch"),
        ("Cisco Firepower Management Center for VMware", None, "fmcv", "manager"),
        ("Cisco Secure Firewall Management Center 2600", None, "fmcv", "manager"),
        ("ASR920-24SZ-M", "iol-xe", "cat8000v", "router"),
        ("ASR-903", "iol-xe", "cat8000v", "router"),
        ("ASR9006", "xrd", "iosxrv9000", "router"),
        ("Cisco 8201", "xrd", "iosxrv9000", "router"),
        ("ISR4331/K9", "iol-xe", "cat8000v", "router"),
        ("Cisco Identity Services Engine", None, "ise", "aaa"),
        ("CISCO2911/K9", "iol-xe", "cat8000v", "router"),
        ("IR1101-K9", "iol-xe", "cat8000v", "router"),
        ("IE3400-8T2S", "ioll2-xe", "cat9000v-uadp", "switch"),
        ("Meraki MR46", None, None, "other"),
        ("totally unknown box", None, None, "unknown"),
    ],
)
def test_platform_mapping(platform: str, light: str | None, faithful: str | None, kind: str) -> None:
    assert map_platform(platform, "light")["definition"] == light
    assert map_platform(platform, "faithful")["definition"] == faithful
    assert map_platform(platform, "light")["kind"] == kind


SITE = [
    {"name": "syd-core1.mcp.lab", "platform": "C9500-24Y4C", "role": "CORE"},
    {"name": "syd-acc1", "platform": "C9300-48U", "role": "ACCESS"},
    {"name": "syd-acc2", "platform": "C9300-48U", "role": "ACCESS"},
    {"name": "syd-wan1", "platform": "C8300-1N1S-6T"},
    {"name": "syd-fw1", "platform": "FPR-2130"},
    {"name": "syd-ap1", "platform": "C9120AXI-B"},
]
LINKS = [
    {"a": "syd-core1.mcp.lab", "b": "syd-acc1"},
    {"a": "syd-core1.mcp.lab", "b": "syd-acc2"},
    {"a": "syd-core1.mcp.lab", "b": "syd-wan1"},
    {"a": "syd-wan1", "b": "syd-fw1"},
    {"a": "syd-acc1", "b": "syd-ap1"},
]


def test_budget_keeps_firewalls_and_routers_first() -> None:
    p = plan_replica(SITE, LINKS, max_nodes=4)
    labels = [n["label"] for n in p["build"]["nodes"]]
    assert labels == ["syd-fw1", "syd-wan1", "syd-core1", "syd-acc1"]
    assert [d["name"] for d in p["dropped"]] == ["syd-acc2"]
    assert [g["name"] for g in p["gaps"]] == ["syd-ap1"]
    assert p["build"]["links"] == ["syd-core1 syd-acc1", "syd-core1 syd-wan1", "syd-wan1 syd-fw1"]
    twice = plan_replica(SITE[:2], [LINKS[0], LINKS[0]])
    assert twice["build"]["links"] == ["syd-core1 syd-acc1", "syd-core1 syd-acc1"]
    assert p["links_skipped"] == 2


def test_ram_budget_and_unavailable_images() -> None:
    p = plan_replica(
        SITE, LINKS, fidelity="faithful", max_ram_gb=30, available={"ftdv", "cat8000v", "cat9000v-uadp"}
    )
    assert [n["definition"] for n in p["build"]["nodes"]] == ["ftdv", "cat8000v", "cat9000v-uadp"]
    assert p["estimated_ram_gb"] == 30
    p = plan_replica(SITE, fidelity="faithful", available={"cat8000v"})
    assert any("isn't installed" in g.get("note", "") for g in p["gaps"])


def test_labels_are_unique_and_clean() -> None:
    p = plan_replica([{"name": "A B.x", "platform": "C9300"}, {"name": "a-b", "platform": "C9300"}])
    assert [n["label"] for n in p["build"]["nodes"]] == ["a-b", "a-b-2"]


async def test_plan_replica_tool_warns_about_licences(api: respx.MockRouter) -> None:
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/image_definitions").mock(
        return_value=httpx.Response(200, json=fixture("image_definitions.json"))
    )
    api.get("/nodes").mock(return_value=httpx.Response(200, json=[]))
    data = await call_tool(
        create_server(make_settings(node_license_limit=2)),
        "cml_plan_replica",
        {"devices": SITE, "links": LINKS},
    )
    assert data["licences"]["limit"] == 2 and "needs" in data["warning"]


async def test_replicate_site_prompt_references_real_tools(api: respx.MockRouter) -> None:
    await assert_prompt_contract(
        create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)),
        "cml",
        samples={
            "cml_build_test_lab": {"recipe": "ise-access"},
            "cml_replicate_site": {"site": "Global/SYD", "fidelity": "light", "max_nodes": "6"},
        },
        external_tools=load_tool_manifests("tests/manifests"),
    )


def test_family_fallback() -> None:
    m = map_platform("XYZ-123", "light", "Switches and Hubs")
    assert m["definition"] == "ioll2-xe" and "family" in m["note"]


@pytest.mark.parametrize("platform", ["WS-C3850-48P-E", "C9300-24UX-1MS1", "C1000-24P-4X-L"])
def test_meraki_lookalikes_stay_cisco(platform: str) -> None:
    assert map_platform(platform, "light")["kind"] == "switch"


def test_every_mapped_definition_has_a_ram_figure() -> None:
    from cml_mcp.replica import RAM_GB, RULES

    for rule in RULES:
        for d in (rule.light, rule.faithful):
            assert d is None or d in RAM_GB, d


def test_duplicate_names_are_merged() -> None:
    devs = [{"name": "fw1", "platform": "FPR-2130"}, {"name": "FW1", "platform": "Firepower 2130"}]
    p = plan_replica(devs)
    assert [n["label"] for n in p["build"]["nodes"]] == ["fw1"]
    assert p["dropped"][0]["why"].startswith("duplicate name")


def test_ip_named_devices_and_short_name_links() -> None:
    devs = [{"name": "10.1.1.1", "platform": "ISR4331"}, {"name": "core1.syd.lab", "platform": "C9500"}]
    p = plan_replica(devs, [{"a": "10.1.1.1", "b": "core1"}, {"a": "core1", "b": "ghost"}])
    labels = [n["label"] for n in p["build"]["nodes"]]
    assert "10-1-1-1" in labels and p["build"]["links"] == ["10-1-1-1 core1"]
    assert p["unmatched_link_ends"] == ["ghost"] and p["links_skipped"] == 1


def test_ram_budget_skips_big_and_keeps_small() -> None:
    devs = [{"name": "fw", "platform": "FTD"}, {"name": "r1", "platform": "ISR4331"}]
    p = plan_replica(devs, max_ram_gb=4)
    assert [n["label"] for n in p["build"]["nodes"]] == ["r1"] and p["dropped"][0]["name"] == "fw"


def test_prompt_validates_arguments() -> None:
    import asyncio

    from fastmcp import Client
    from mcp.shared.exceptions import MCPError

    async def go() -> None:
        async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
            with pytest.raises(MCPError):
                await c.get_prompt("cml_replicate_site", {"site": "x", "fidelity": "max"})
            with pytest.raises(MCPError):
                await c.get_prompt("cml_replicate_site", {"site": "x'; drop", "max_nodes": "5"})
            ok = await c.get_prompt("cml_replicate_site", {"site": "Global/SYD", "max_nodes": "6"})
            assert "max_nodes=6" in ok.messages[0].content.text  # type: ignore[union-attr]

    asyncio.run(go())
