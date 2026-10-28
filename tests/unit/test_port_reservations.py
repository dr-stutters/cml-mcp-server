"""#69: parallel cml_connect_nodes previews to one unmanaged switch get different ports, and a confirm
whose previewed port was taken meanwhile re-picks (or refuses when nothing is free). Synthetic payloads:
the captured two-router lab plus an unmanaged switch 'sw' with three free ports."""

import asyncio
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp.server import create_server
from cml_mcp.tools.topology_writes import PortReservations

from .conftest import LID, LINKS, NODES, fixture, make_settings

RW = {"mcp_enable_writes": True}
SW = "5a1c0000-0000-4000-8000-000000000000"
PORTS = [f"5a1c0000-0000-4000-8000-00000000010{n}" for n in range(3)]


def data(res: Any) -> Any:
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


class Lab:
    """Mutable lab state behind the respx routes: POST /links really adds a link."""

    def __init__(self, lab_api: respx.MockRouter) -> None:
        self.links: list[dict[str, Any]] = [dict(lk) for lk in LINKS]
        sw = dict(NODES[0], id=SW, label="sw", node_definition="unmanaged_switch", x=400)
        ports = [
            {"id": pid, "label": f"port{n}", "node": SW, "slot": n, "type": "physical", "state": "STARTED"}
            for n, pid in enumerate(PORTS)
        ]
        self.ifaces = fixture("interfaces.json") + ports
        lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=[*NODES, sw]))
        lab_api.get(f"/labs/{LID}/interfaces").mock(
            side_effect=lambda r: httpx.Response(200, json=self.ifaces)
        )
        lab_api.get(f"/labs/{LID}/links").mock(side_effect=lambda r: httpx.Response(200, json=self.links))
        self.posts = lab_api.post(f"/labs/{LID}/links").mock(side_effect=self._post)

    def _post(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.connect(body["src_int"], body["dst_int"])
        return httpx.Response(200, json={"id": self.links[-1]["id"]})

    def connect(self, a: str, b: str) -> None:
        self.links.append({"id": f"link-{len(self.links)}", "interface_a": a, "interface_b": b})


def args(node: str) -> dict[str, Any]:
    return {"lab": LID, "node_a": node, "node_b": "sw"}


async def test_parallel_previews_get_different_switch_ports(lab_api: respx.MockRouter) -> None:
    lab = Lab(lab_api)
    async with Client(create_server(make_settings(**RW))) as c:
        p1, p2 = await asyncio.gather(
            c.call_tool("cml_connect_nodes", args("r1")), c.call_tool("cml_connect_nodes", args("r2"))
        )
        p1, p2 = data(p1), data(p2)
        assert p1["status"] == p2["status"] == "preview"
        assert {p1["preview"]["b"], p2["preview"]["b"]} == {"sw:port0", "sw:port1"}
        assert "held for this preview" in p1["preview"]["reserved"]
        # Both confirms apply: the first link no longer invalidates the second token.
        a1 = data(await c.call_tool("cml_connect_nodes", {**args("r1"), "confirm": p1["confirm"]}))
        a2 = data(await c.call_tool("cml_connect_nodes", {**args("r2"), "confirm": p2["confirm"]}))
    assert a1["status"] == a2["status"] == "applied"
    assert a1["result"]["b"] == p1["preview"]["b"] and a2["result"]["b"] == p2["preview"]["b"]
    assert "repicked" not in a1["result"] and "repicked" not in a2["result"]
    dst = [json.loads(call.request.content)["dst_int"] for call in lab.posts.calls]
    assert len(set(dst)) == 2 and set(dst) <= set(PORTS)


async def test_confirm_repicks_when_previewed_port_was_taken(lab_api: respx.MockRouter) -> None:
    lab = Lab(lab_api)
    async with Client(create_server(make_settings(**RW))) as c:
        p = data(await c.call_tool("cml_connect_nodes", args("r1")))
        assert p["preview"]["b"] == "sw:port0"
        lab.connect("outside-iface", PORTS[0])  # someone else (the CML UI) cabled port0 meanwhile
        a = data(await c.call_tool("cml_connect_nodes", {**args("r1"), "confirm": p["confirm"]}))
    assert a["status"] == "applied" and a["action"].endswith("sw:port1")
    assert a["result"]["repicked"] == ["sw:port0 was connected since the preview; used port1 instead"]
    assert json.loads(lab.posts.calls.last.request.content)["dst_int"] == PORTS[1]


async def test_confirm_refuses_when_no_port_is_left(lab_api: respx.MockRouter) -> None:
    lab = Lab(lab_api)
    async with Client(create_server(make_settings(**RW))) as c:
        p = data(await c.call_tool("cml_connect_nodes", args("r1")))
        for n, port in enumerate(PORTS):
            lab.connect(f"outside-{n}", port)
        res = await c.call_tool(
            "cml_connect_nodes", {**args("r1"), "confirm": p["confirm"]}, raise_on_error=False
        )
    assert res.is_error
    text = res.content[0].text
    assert "sw:port0 was connected since the preview and sw has no free interface" in text
    assert "Nothing was changed" in text and not lab.posts.called


async def test_preview_skips_ports_held_by_other_previews(lab_api: respx.MockRouter) -> None:
    Lab(lab_api)
    async with Client(create_server(make_settings(**RW))) as c:
        held = [data(await c.call_tool("cml_connect_nodes", args("r1"))) for _ in PORTS]
        assert [p["preview"]["b"] for p in held] == ["sw:port0", "sw:port1", "sw:port2"]
        last = data(await c.call_tool("cml_connect_nodes", args("r2")))
    assert last["status"] == "blocked"
    assert "sw has no free interface (the others are held for pending previews)" in last["blockers"][0]


async def test_named_interface_is_not_reserved_or_swapped(lab_api: respx.MockRouter) -> None:
    lab = Lab(lab_api)
    named = {**args("r1"), "interface_b": "port0"}
    async with Client(create_server(make_settings(**RW))) as c:
        p = data(await c.call_tool("cml_connect_nodes", named))
        other = data(await c.call_tool("cml_connect_nodes", args("r2")))
        assert other["preview"]["b"] == "sw:port0"  # a named port holds nothing on the switch side
        lab.connect("outside-iface", PORTS[0])
        res = await c.call_tool("cml_connect_nodes", {**named, "confirm": p["confirm"]}, raise_on_error=False)
    assert res.is_error and "sw:port0 is already connected" in res.content[0].text


def test_reservations_expire_and_release(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [100.0]
    monkeypatch.setattr("cml_mcp.tools.topology_writes.time.monotonic", lambda: now[0])
    res = PortReservations()
    res.hold("tmp", ["i1"], ttl=60)
    res.rekey("tmp", "pv_a")
    assert res.held_by("pv_a") == {"i1"} and res.held_by_others("pv_b") == {"i1"}
    assert res.held_by_others("pv_a") == set() and res.held_by(None) == set()
    now[0] = 161.0
    assert res.held_by_others(None) == set()  # expired with the token
    res.hold("pv_c", ["i2"], ttl=60)
    res.release("pv_c")
    assert res.held_by_others(None) == set()
