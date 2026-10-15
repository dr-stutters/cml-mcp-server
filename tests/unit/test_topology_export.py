"""L9: topology export (mermaid/drawio/json), annotations list/annotate, recipe annotations."""

import json
import xml.dom.minidom
from typing import Any

import httpx
import respx
from fastmcp import Client

from cml_mcp.recipes import recipe_names
from cml_mcp.server import create_server
from cml_mcp.tools.recipes_tools import recipe_annotations
from cml_mcp.topology import (
    MCP_Z,
    config_addresses,
    is_address_label,
    place_notes,
    short_if,
    text_annotation,
    to_drawio,
    to_mermaid,
)

from .conftest import LID, make_settings
from .test_recipes_tools import KNOWN_SECRETS
from .test_write_tools import RW, data, preview_apply


def test_config_addresses() -> None:
    ios = (
        "interface Loopback0\n ip address 1.1.1.1 255.255.255.255\n!\ninterface Gi2\n no ip address\n"
        "router ospf 1\n"
    )
    assert config_addresses("iol-xe", ios) == [("Loopback0", "1.1.1.1/32")]
    ftd = json.dumps({"IPv4Addr": "198.18.128.151", "IPv4Mask": "255.255.192.0", "AdminPassword": "x"})
    assert config_addresses("ftdv", ftd) == [("Management0/0", "198.18.128.151/18")]
    alpine = "hostname h1\nip addr add 10.0.10.10/24 dev eth0\nip route add default via 10.0.10.1\n"
    assert config_addresses("alpine", alpine) == [("eth0", "10.0.10.10/24")]
    netplan = "network:\n  ethernets:\n    ens2:\n      addresses: [10.1.1.5/24]\n"
    assert config_addresses("ubuntu", netplan) == [("ens2", "10.1.1.5/24")]
    assert config_addresses("iol-xe", None) == []


def test_short_if_and_address_label() -> None:
    assert short_if("GigabitEthernet1/0/1") == "Gi1/0/1" and short_if("eth0") == "eth0"
    assert is_address_label({"text_content": "Gi1 10.0.0.1/24\nLo0 1.1.1.1"})
    assert not is_address_label({"text_content": "recipe: ise-access"})


def test_place_notes_above_the_lab_and_near() -> None:
    nodes = [{"label": "r1", "x": 0, "y": 0}, {"label": "r2", "x": 200, "y": 100}]
    out = place_notes([{"text": "a\nb"}, {"text": "c"}, {"text": "n", "near": "r2"}], nodes)
    assert all(a["z_index"] == MCP_Z and a["type"] == "text" for a in out)
    assert out[0]["y1"] < out[1]["y1"] < 0  # stacked, above the top node
    assert out[2]["x1"] == 250


def test_mermaid_escapes_and_shapes() -> None:
    model: dict[str, Any] = {
        "nodes": [
            {
                "label": "ext",
                "definition": "external_connector",
                "connector": "System Bridge",
                "addresses": [],
            },
            {"label": "sw", "definition": "unmanaged_switch", "addresses": []},
            {"label": 'r"1', "definition": "iol-xe", "addresses": [("Ethernet0/0", "10.0.0.1/24")]},
        ],
        "links": [{"a_node": "ext", "a_if": "port", "b_node": "sw", "b_if": "port0"}],
        "notes": ["<b>"],
    }
    text = to_mermaid(model)
    assert text.startswith("graph LR\n")
    assert 'n0(("ext<br/>external_connector<br/>System Bridge"))' in text
    assert 'n1{{"sw<br/>unmanaged_switch"}}' in text
    assert "r#quot;1" in text and "E0/0 10.0.0.1/24" in text and "#lt;b#gt;" in text
    assert 'n0 ---|"port - port0"| n1' in text


def mock_annotations(api: respx.MockRouter, items: list[dict[str, Any]]) -> None:
    api.get(f"/labs/{LID}/annotations").mock(return_value=httpx.Response(200, json=items))


async def test_export_formats(lab_api: respx.MockRouter) -> None:
    mock_annotations(
        lab_api,
        [{"id": "a1", "type": "text", "text_content": "demo lab", "x1": 0, "y1": -80, "z_index": MCP_Z}],
    )
    async with Client(create_server(make_settings())) as c:
        mer = data(await c.call_tool("cml_export_topology", {"lab": LID}))
        dio = data(await c.call_tool("cml_export_topology", {"lab": LID, "format": "drawio"}))
        js = data(
            await c.call_tool("cml_export_topology", {"lab": LID, "format": "json", "addresses": "none"})
        )
    assert mer["nodes"] == 2 and mer["links"] == 1
    assert "Lo0 1.1.1.1/32" in mer["content"] and "E0/0 10.0.12.2/24" in mer["content"]
    assert 'notes["demo lab"]' in mer["content"]
    doc = xml.dom.minidom.parseString(dio["content"])
    assert len([c for c in doc.getElementsByTagName("mxCell") if c.getAttribute("edge") == "1"]) == 1
    assert js["content"]["nodes"][0]["addresses"] == []
    assert js["content"]["annotations"][0]["ours"] is True


async def test_list_annotations(lab_api: respx.MockRouter) -> None:
    mock_annotations(
        lab_api, [{"id": "a1", "type": "rectangle", "x1": 1, "y1": 2, "x2": 3, "y2": 4, "z_index": 0}]
    )
    async with Client(create_server(make_settings())) as c:
        out = data(await c.call_tool("cml_list_annotations", {"lab": LID, "response_format": "json"}))
    assert out["results"][0]["type"] == "rectangle" and out["results"][0]["ours"] is False


async def test_annotate_replaces_only_ours(lab_api: respx.MockRouter) -> None:
    mine = dict(text_annotation("old", 0, 0), id="old1")
    hand = {"id": "hand1", "type": "text", "text_content": "drawn by a person", "z_index": 0}
    mock_annotations(lab_api, [mine, hand])
    post = lab_api.post(f"/labs/{LID}/annotations").mock(return_value=httpx.Response(200, json={"id": "new"}))
    delete = lab_api.delete(f"/labs/{LID}/annotations/old1").mock(return_value=httpx.Response(204))
    args = {"lab": LID, "notes": [{"text": "PoC lab", "bold": True}], "addresses": "config"}
    preview, applied = await preview_apply("cml_annotate_lab", args)
    assert preview["preview"]["remove"] == ["old1"]
    assert preview["preview"]["add"][0] == "PoC lab" and len(preview["preview"]["add"]) == 3  # + r1, r2
    assert delete.called and post.call_count == 3
    assert applied["result"] == {"added": ["new", "new", "new"], "removed": 1}
    sent = json.loads(post.calls[0].request.content)
    assert sent["z_index"] == MCP_Z and sent["text_bold"] is True


async def test_annotate_recipe_flag_needs_recipe_lab(lab_api: respx.MockRouter) -> None:
    mock_annotations(lab_api, [])
    blocked, _ = await preview_apply("cml_annotate_lab", {"lab": LID, "recipe": True}, **RW)
    assert blocked["status"] == "blocked" and "not a recipe" in blocked["blockers"][0]


def test_recipe_annotations_have_no_secrets() -> None:
    for name in recipe_names():
        anns = recipe_annotations(name)
        text = json.dumps(anns)
        assert f"recipe: {name}" in text and "credentials.where" in text
        assert not [s for s in KNOWN_SECRETS if s in text], name


def test_renderers_resist_injection() -> None:
    model: dict[str, Any] = {
        "lab": "x\x01",
        "nodes": [
            {"label": "a", "definition": "iol-xe", "addresses": [], "x": 0, "y": 0},
            {"label": "b\nclick a call evil()", "definition": "iol-xe", "addresses": [], "x": 1, "y": 1},
        ],
        "links": [
            {
                "a_node": "a",
                "a_if": "<img src=x onerror=alert(1)>",
                "b_node": "b\nclick a call evil()",
                "b_if": "e#1&",
            }
        ],
    }
    mer = to_mermaid(model)
    assert "\nclick" not in mer and "#35;1#amp;" in mer
    dio = to_drawio(model)
    xml.dom.minidom.parseString(dio)
    assert "<img" not in dio and "&lt;img" not in dio  # double-escaped for the html=1 label


def test_recipe_secret_values_never_in_annotations() -> None:
    from cml_mcp.recipes import get_recipe
    from cml_mcp.tools.recipes_tools import recipe_secrets

    for name in recipe_names():
        text = json.dumps(recipe_annotations(name))
        assert not [s for s in recipe_secrets(get_recipe(name)) if len(s) > 5 and s in text], name
