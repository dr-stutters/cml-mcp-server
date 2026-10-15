"""cat9000v serials: unique per node at build time, duplicates flagged by verify (CatC keys by serial)."""

from typing import Any

import httpx
import respx
from fastmcp import Client

from cml_mcp.build import serial_of, unique_serial, with_serial
from cml_mcp.client import CmlApp
from cml_mcp.server import create_server
from cml_mcp.verify import cat9kv_serial_checks

from .conftest import fixture, make_settings

VSWITCH = (
    '<?xml version="1.0"?>\n<switch>\n  <board_id>20612</board_id>\n'
    "  <prod_serial_number>CMLUADP</prod_serial_number>\n  <port_count>24</port_count>\n</switch>\n"
)
NODE_DEF = (
    "id: cat9000v-uadp\nconfiguration:\n  provisioning:\n    files:\n"
    "      - name: iosxe_config.txt\n        content: hostname x\n"
    "      - name: conf/vswitch.xml\n        content: |\n"
    + "".join(f"          {line}\n" for line in VSWITCH.splitlines())
)


def test_serial_helpers() -> None:
    s = unique_serial("lab", "sw1")
    assert len(s) == 11 and s == unique_serial("lab", "sw1") and s != unique_serial("lab", "sw2")
    assert serial_of(with_serial(VSWITCH, s)) == s and serial_of(VSWITCH) == "CMLUADP"


async def test_build_assigns_unique_serials(api: respx.MockRouter) -> None:
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/node_definitions/cat9000v-uadp").mock(return_value=httpx.Response(200, json=NODE_DEF))
    imported = api.post("/import").mock(return_value=httpx.Response(200, json={"id": "L1"}))
    args = {
        "title": "mcp-test-serials",
        "nodes": [
            {"label": "sw1", "definition": "cat9000v-uadp"},
            {"label": "sw2", "definition": "cat9000v-uadp"},
            {
                "label": "sw3",
                "definition": "cat9000v-uadp",
                "files": {"conf/vswitch.xml": with_serial(VSWITCH, "MINE1")},
            },
        ],
        "links": [],
    }
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        p = (await c.call_tool("cml_build_lab", args)).structured_content
        serials = p["preview"]["cat9000v_serials"]
        assert serials["sw3"] == "MINE1" and len(set(serials.values())) == 3
        await c.call_tool("cml_build_lab", {**args, "confirm": p["confirm"]})
    body = imported.calls.last.request.content.decode()
    assert serials["sw1"] in body and serials["sw2"] in body and "CMLUADP" not in body


async def test_verify_flags_duplicate_serials(api: respx.MockRouter) -> None:
    def node(nid: str, label: str, serial: str | None) -> dict[str, Any]:
        files = [{"name": "conf/vswitch.xml", "content": with_serial(VSWITCH, serial)}] if serial else []
        return {
            "id": nid,
            "label": label,
            "node_definition": "cat9000v-uadp",
            "state": "BOOTED",
            "configuration": files,
        }

    mine = [node("n1", "sw1", None), node("n2", "sw2", "CMLAAAA0001")]
    other = [node("o1", "edge", "CMLAAAA0001")]
    for n in mine:
        api.get(f"/labs/L1/nodes/{n['id']}").mock(return_value=httpx.Response(200, json=n))
    api.get("/labs/L2/nodes/o1").mock(return_value=httpx.Response(200, json=other[0]))
    api.get("/labs").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": "L1", "lab_title": "mine", "state": "STARTED"},
                {"id": "L2", "lab_title": "theirs", "state": "STARTED"},
            ],
        )
    )
    api.get("/labs/L2/nodes").mock(return_value=httpx.Response(200, json=other))
    app = CmlApp(make_settings())
    try:
        (chk,) = await cat9kv_serial_checks(app, "L1", mine)
    finally:
        await app.aclose()
    assert chk["ok"] is True and "share serial CMLAAAA0001 with theirs/edge" in chk["warning"]
    dup = [node("n1", "sw1", None), node("n3", "sw3", None)]
    api.get("/labs/L1/nodes/n3").mock(return_value=httpx.Response(200, json=dup[1]))
    app = CmlApp(make_settings())
    try:
        (chk,) = await cat9kv_serial_checks(app, "L1", dup)
    finally:
        await app.aclose()
    assert chk["ok"] is False and "sw1, sw3 share serial CMLUADP" in chk["detail"]
