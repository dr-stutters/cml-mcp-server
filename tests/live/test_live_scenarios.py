"""L8 link scenarios on a throwaway two-router lab: netem profile -> RTT, flap -> loss then recovery."""

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest
from fastmcp import Client

from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import rw
from .labkit import confirm_call, create_lab, delete_lab

pytestmark = pytest.mark.live
TITLE = "mcp-test-live-scenarios"


@pytest.fixture(scope="module")
def lab() -> Iterator[str]:
    from stutters_mcp_core.testing import live_settings

    from .conftest import ROOT

    settings = live_settings(Settings, "CML_", _env_file=ROOT / ".env", mcp_cache_dir="")
    lab_id = create_lab(settings, TITLE, start=True)
    yield lab_id
    delete_lab(settings, lab_id)


async def ping(c: Client, lab: str) -> dict[str, Any]:
    res = await c.call_tool(
        "cml_check_reachability", {"lab": lab, "nodes": ["r1"], "targets": ["10.99.0.2"], "count": 5}
    )
    out: dict[str, Any] = res.structured_content["results"][0]  # type: ignore[index]
    return out


async def test_satellite_then_flap_then_clear(settings: Settings, lab: str) -> None:
    async with Client(create_server(rw(settings))) as c:
        await ping(c, lab)  # ARP
        res = await confirm_call(
            c, "cml_apply_link_scenario", {"lab": lab, "link": "r1<->r2", "scenario": "wan-satellite"}
        )
        assert res["expected_ping_delta"]["rtt_added_ms"] == 600
        sat = await ping(c, lab)
        assert sat["ok"] and 540 <= sat["rtt_avg_ms"] <= 700
        await confirm_call(c, "cml_clear_link_scenarios", {"lab": lab})
        args = {
            "lab": lab,
            "link": "r1<->r2",
            "scenario": "flap",
            "down_seconds": 20,
            "up_seconds": 5,
            "cycles": 1,
        }
        await confirm_call(c, "cml_apply_link_scenario", args)
        await asyncio.sleep(3)
        assert (await ping(c, lab))["success_percent"] == 0
        for _ in range(30):
            listed = (await c.call_tool("cml_get_link_scenarios", {"lab": lab})).structured_content
            if not listed["flaps"][0]["running"]:  # type: ignore[index]
                break
            await asyncio.sleep(2)
        assert listed["flaps"][0]["phase"] == "done"  # type: ignore[index]
        await asyncio.sleep(3)
        assert (await ping(c, lab))["ok"]
