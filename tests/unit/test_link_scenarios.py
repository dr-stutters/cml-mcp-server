import asyncio
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp.netops import ping_result
from cml_mcp.scenarios import SCENARIOS, FlapJob, FlapManager, match_scenario, netem_body
from cml_mcp.server import create_server

from .conftest import LID, LINK, fixture, make_settings
from .test_write_tools import RW, data, preview_apply


def test_expected_deltas_are_round_trip() -> None:
    sat = SCENARIOS["wan-satellite"].expected()
    assert sat["rtt_added_ms"] == 600 and sat["rtt_spread_ms"] == 40
    assert sat["round_trip_loss_pct"] == pytest.approx(1.0, abs=0.01)
    brown = SCENARIOS["brownout"].expected()
    assert brown["round_trip_loss_pct"] == 36.0 and brown["throughput_kbps_max"] == 256
    assert "while_down" in SCENARIOS["flap"].expected()


def test_netem_body_resets_unused_fields_and_match() -> None:
    body = netem_body(SCENARIOS["lossy-wifi"])
    assert body["enabled"] is True and body["bandwidth"] is None and body["duplicate"] == 1
    cond = {"latency": 5, "jitter": 30, "loss": 5.0, "duplicate": 1, "bandwidth": None, "enabled": True}
    assert match_scenario(cond) == "lossy-wifi"
    assert match_scenario({"latency": 7, "enabled": True}) == "custom"
    assert match_scenario({"latency": 7, "enabled": False}) is None


def test_ping_result_parses_rtt() -> None:
    ios = "Success rate is 100 percent (10/10), round-trip min/avg/max = 101/102/103 ms"
    assert ping_result(ios)["rtt_avg_ms"] == 102.0
    linux = "3 packets transmitted, 3 received, 0% packet loss\nrtt min/avg/max/mdev = 0.1/40.5/80.2/1.0 ms"
    assert ping_result(linux)["rtt_avg_ms"] == 40.5
    busybox = (
        "3 packets transmitted, 2 packets received, 33% packet loss\nround-trip min/avg/max = 1.0/2.5/4.0 ms"
    )
    res = ping_result(busybox)
    assert res["rtt_avg_ms"] == 2.5 and res["success_percent"] == 67
    assert "rtt_avg_ms" not in ping_result("Success rate is 0 percent (0/5)")


async def test_list_scenarios_with_lab(lab_api: respx.MockRouter) -> None:
    topo = fixture("topology.json")
    topo["links"][0]["conditioning"] = {
        "latency": 300,
        "jitter": 20,
        "loss": 0.5,
        "bandwidth": 5000,
        "enabled": True,
    }
    lab_api.get(f"/labs/{LID}/topology").mock(return_value=httpx.Response(200, json=topo))
    async with Client(create_server(make_settings())) as c:
        out = data(await c.call_tool("cml_get_link_scenarios", {"lab": LID}))
    assert {s["name"] for s in out["scenarios"]} == set(SCENARIOS)
    assert out["conditioned_links"][0]["scenario"] == "wan-satellite"
    assert out["conditioned_links"][0]["link"] == "r1:Ethernet0/0<->r2:Ethernet0/0"
    assert out["flaps"] == []


async def test_apply_netem_scenario(lab_api: respx.MockRouter) -> None:
    patch = lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=httpx.Response(200, json={"latency": 150, "loss": 20, "enabled": True})
    )
    preview, applied = await preview_apply(
        "cml_apply_link_scenario", {"lab": LID, "link": "r1<->r2", "scenario": "brownout"}
    )
    assert preview["preview"]["new"]["bandwidth"] == 256
    sent = json.loads(patch.calls.last.request.content)
    assert sent == {**netem_body(SCENARIOS["brownout"])}
    assert applied["result"]["expected_ping_delta"]["rtt_added_ms"] == 300


async def test_flap_runs_in_background_and_restores(lab_api: respx.MockRouter) -> None:
    states: list[str] = []

    def record(req: httpx.Request) -> httpx.Response:
        states.append(req.url.path.rsplit("/", 1)[-1])
        return httpx.Response(204)

    lab_api.put(url__regex=rf".*/labs/{LID}/links/{LINK}/state/(start|stop)$").mock(side_effect=record)
    args = {
        "lab": LID,
        "link": "r1<->r2",
        "scenario": "flap",
        "down_seconds": 2,
        "up_seconds": 2,
        "cycles": 2,
    }
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_apply_link_scenario", args))
        assert preview["status"] == "preview" and preview["preview"]["cycles"] == 2
        applied = data(await c.call_tool("cml_apply_link_scenario", {**args, "confirm": preview["confirm"]}))
        assert applied["result"]["flap"]["running"] is True
        again = data(await c.call_tool("cml_apply_link_scenario", args))
        assert again["status"] == "blocked" and "already flapping" in again["blockers"][0]
        await asyncio.sleep(0.2)
        assert states == ["stop"]
        # stop it early: the link is brought back up
        pv = data(await c.call_tool("cml_clear_link_scenarios", {"lab": LID}))
        assert pv["preview"]["flaps"] == ["r1:Ethernet0/0<->r2:Ethernet0/0"]
        done = data(await c.call_tool("cml_clear_link_scenarios", {"lab": LID, "confirm": pv["confirm"]}))
        assert done["result"]["flaps_stopped"][0]["phase"] == "cancelled"
        assert states == ["stop", "start"]
        listed = data(await c.call_tool("cml_get_link_scenarios", {"lab": LID}))
        assert listed["flaps"][0]["running"] is False


async def test_flap_blocked_when_link_not_started(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/labs/{LID}/links").mock(
        return_value=httpx.Response(200, json=[dict(fixture("links.json")[0], state="STOPPED")])
    )
    blocked, _ = await preview_apply(
        "cml_apply_link_scenario", {"lab": LID, "link": "r1<->r2", "scenario": "flap"}
    )
    assert blocked["status"] == "blocked" and "started lab" in blocked["blockers"][0]
    blocked, _ = await preview_apply(
        "cml_apply_link_scenario",
        {
            "lab": LID,
            "link": "r1<->r2",
            "scenario": "flap",
            "down_seconds": 3600,
            "up_seconds": 3600,
            "cycles": 3,
        },
    )
    assert any("maximum" in b for b in blocked["blockers"])


async def test_clear_removes_conditioning(lab_api: respx.MockRouter) -> None:
    topo = fixture("topology.json")
    topo["links"][0]["conditioning"] = {"latency": 20, "enabled": True}
    lab_api.get(f"/labs/{LID}/topology").mock(return_value=httpx.Response(200, json=topo))
    delete = lab_api.delete(f"/labs/{LID}/links/{LINK}/condition").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_clear_link_scenarios", {"lab": LID})
    assert list(preview["preview"]["conditioning"]) == ["r1:Ethernet0/0<->r2:Ethernet0/0"]
    assert delete.called and applied["result"]["cleared"] == ["r1:Ethernet0/0<->r2:Ethernet0/0"]


async def test_flap_manager_records_failure_and_restores() -> None:
    calls: list[str] = []

    async def set_state(s: str) -> None:
        calls.append(s)
        if s == "down" and calls.count("down") == 2:
            raise RuntimeError("boom")

    mgr = FlapManager()
    job = mgr.start(FlapJob("l", "lab", "k", "a<->b", 0.01, 0.01, 3), set_state)
    assert job.task is not None
    await job.task
    assert job.phase == "failed" and "boom" in (job.error or "")
    assert calls == ["down", "up", "down", "up"]  # last 'up' is the restore


async def test_shutdown_brings_links_up() -> None:
    calls: list[str] = []

    async def set_state(s: str) -> None:
        calls.append(s)

    mgr = FlapManager()
    job: Any = mgr.start(FlapJob("l", "lab", "k", "a<->b", 30, 30, 2), set_state)
    await asyncio.sleep(0.05)
    await mgr.shutdown()
    assert job.phase == "cancelled" and calls == ["down", "up"]


async def test_server_shutdown_restores_flapping_link(lab_api: respx.MockRouter) -> None:
    states: list[str] = []

    def record(req: httpx.Request) -> httpx.Response:
        states.append(req.url.path.rsplit("/", 1)[-1])
        return httpx.Response(204)

    lab_api.put(url__regex=rf".*/labs/{LID}/links/{LINK}/state/(start|stop)$").mock(side_effect=record)
    args = {"lab": LID, "link": "r1<->r2", "scenario": "flap", "down_seconds": 60, "up_seconds": 60}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_apply_link_scenario", args))
        await c.call_tool("cml_apply_link_scenario", {**args, "confirm": preview["confirm"]})
        await asyncio.sleep(0.1)
    # leaving the client ends the server lifespan -> CmlApp.aclose -> flaps restored
    assert states == ["stop", "start"]


async def test_restore_retries_then_flags_link_down() -> None:
    async def set_state(s: str) -> None:
        if s == "up":
            raise RuntimeError("controller unreachable")
        await asyncio.sleep(10)

    mgr = FlapManager()
    job = mgr.start(FlapJob("l", "lab", "k", "a<->b", 30, 30, 1), set_state)
    await asyncio.sleep(0)
    with pytest.MonkeyPatch.context() as mp:
        real_sleep = asyncio.sleep
        mp.setattr("cml_mcp.scenarios.asyncio.sleep", lambda s: real_sleep(0))
        await mgr.cancel([job])
    assert job.error and job.error.startswith("LINK MAY STILL BE DOWN")


async def test_apply_scenario_preview_lists_reset_impairments(lab_api: respx.MockRouter) -> None:
    """The scenario PATCH resets what the profile leaves out (core 0.12.4 replace=True diff)."""
    lab_api.get(f"/labs/{LID}/links/{LINK}/condition").mock(
        return_value=httpx.Response(200, json={"latency": 600, "duplicate": 1, "enabled": True})
    )
    lab_api.patch(f"/labs/{LID}/links/{LINK}/condition").mock(return_value=httpx.Response(200, json={}))
    preview, _ = await preview_apply(
        "cml_apply_link_scenario", {"lab": LID, "link": "r1<->r2", "scenario": "brownout"}
    )
    changes = preview["preview"]["changes"]
    assert changes["duplicate"] == {"from": 1, "to": None, "removed": True}
    assert changes["latency"] == {"from": 600, "to": 150} and "enabled" not in changes
