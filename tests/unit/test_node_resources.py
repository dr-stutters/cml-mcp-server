"""L77 (#81): cml_update_node resource fields and parameters; cml_set_node_config files=."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from cml_mcp.server import create_server

from .conftest import LID, NODES, R1, R2, make_settings

RW = {"mcp_enable_writes": True}


def data(res: Any) -> Any:
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


async def preview_apply(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool(name, args))
        if preview.get("status") != "preview":
            return preview, None
        applied = data(await c.call_tool(name, {**args, "confirm": preview["confirm"]}))
        return preview, applied


def with_nodes(api: respx.MockRouter, **changes: Any) -> list[dict[str, Any]]:
    """The probe lab's nodes, r2 changed (state, parameters, operational...)."""
    nodes = [dict(n, **changes) if n["id"] == R2 else n for n in NODES]
    api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=nodes))
    return nodes


async def test_update_node_resources_on_wiped_node(lab_api: respx.MockRouter) -> None:
    with_nodes(lab_api, state="DEFINED_ON_CORE", parameters={"smbios.bios.vendor": "x"})
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=httpx.Response(200, json=R2))
    args = {
        "lab": LID,
        "node": "r2",
        "cpus": 4,
        "ram": 12288,
        "cpu_limit": 80,
        "data_volume": 200,
        "boot_disk_size": 64,
        "parameters": {"smbios.system.serial": "SN0001"},
    }
    preview, applied = await preview_apply("cml_update_node", args)
    assert preview["status"] == "preview", preview
    changes = preview["preview"]["changes"]
    assert changes["cpu_limit"] == {"from": None, "to": 80}
    assert changes["data_volume"] == {"from": None, "to": 200}
    assert changes["boot_disk_size"] == {"from": None, "to": 64}
    assert changes["parameters.smbios.system.serial"] == {"from": None, "to": "SN0001"}
    assert "parameters.smbios.bios.vendor" not in changes
    assert applied["status"] == "applied"
    assert json.loads(patch.calls.last.request.content) == {
        "cpus": 4,
        "ram": 12288,
        "cpu_limit": 80,
        "data_volume": 200,
        "boot_disk_size": 64,
        "parameters": {"smbios.bios.vendor": "x", "smbios.system.serial": "SN0001"},
    }


async def test_update_node_parameters_null_removes_key(lab_api: respx.MockRouter) -> None:
    with_nodes(lab_api, state="DEFINED_ON_CORE", parameters={"a": "1", "b": "2"})
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=httpx.Response(200, json=R2))
    preview, _ = await preview_apply(
        "cml_update_node", {"lab": LID, "node": "r2", "parameters": {"b": None, "c": "3"}}
    )
    assert preview["preview"]["changes"] == {
        "parameters.b": {"from": "2", "to": None, "removed": True},
        "parameters.c": {"from": None, "to": "3"},
    }
    assert json.loads(patch.calls.last.request.content) == {"parameters": {"a": "1", "c": "3"}}


async def test_update_node_resources_blocked_while_booted(lab_api: respx.MockRouter) -> None:
    for field, value in (("data_volume", 100), ("cpu_limit", 50), ("boot_disk_size", 32)):
        preview, _ = await preview_apply("cml_update_node", {"lab": LID, "node": "r2", field: value})
        assert preview["status"] == "blocked"
        assert field in preview["blockers"][0] and "wipe" in preview["blockers"][0]
    preview, _ = await preview_apply("cml_update_node", {"lab": LID, "node": "r2", "parameters": {"k": "v"}})
    assert preview["status"] == "blocked" and "parameters.k" in preview["blockers"][0]


async def test_update_node_unchanged_parameters_are_nothing_to_change(lab_api: respx.MockRouter) -> None:
    with_nodes(lab_api, state="DEFINED_ON_CORE", parameters={"a": "1"})
    preview, _ = await preview_apply("cml_update_node", {"lab": LID, "node": "r2", "parameters": {"a": "1"}})
    assert preview["status"] == "blocked" and "already has that value" in preview["blockers"][0]


async def test_update_node_warns_on_shrinking_disks(lab_api: respx.MockRouter) -> None:
    op = dict(NODES[1]["operational"], data_volume=250, boot_disk_size=32)
    with_nodes(lab_api, state="DEFINED_ON_CORE", operational=op)
    lab_api.patch(f"/labs/{LID}/nodes/{R2}").mock(return_value=httpx.Response(200, json=R2))
    preview, _ = await preview_apply(
        "cml_update_node", {"lab": LID, "node": "r2", "data_volume": 100, "boot_disk_size": 16}
    )
    text = json.dumps(preview)
    assert "data_volume 100 GB is smaller than the 250 GB" in text
    assert "boot_disk_size 16 GB is smaller than the 32 GB" in text


async def test_update_node_validates_ranges(lab_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(**RW))) as c:
        for field, value in (
            ("cpu_limit", 10),
            ("cpu_limit", 101),
            ("data_volume", -1),
            ("boot_disk_size", 0),
        ):
            res = await c.call_tool(
                "cml_update_node", {"lab": LID, "node": "r2", field: value}, raise_on_error=False
            )
            assert res.is_error, (field, value)


UBUNTU_FILES = [
    {"name": "user-data", "content": "#cloud-config\nhostname: u1\n"},
    {"name": "network-config", "content": "version: 2\nethernets:\n  ens2:\n    dhcp4: true\n"},
]


def ubuntu_node(api: respx.MockRouter, files: list[dict[str, Any]] | None = None) -> None:
    """r1 as a wiped ubuntu node with user-data + network-config (ubuntu's definition is not readable)."""
    node = dict(NODES[0], state="DEFINED_ON_CORE", node_definition="ubuntu")
    nodes = [node if n["id"] == R1 else n for n in NODES]
    api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=nodes))
    full = dict(node, configuration=files if files is not None else UBUNTU_FILES)
    api.get(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=full))
    api.get("/node_definitions/ubuntu").mock(return_value=httpx.Response(404, json={"description": "x"}))


async def test_set_node_config_files_merges_and_keeps_main(lab_api: respx.MockRouter) -> None:
    ubuntu_node(lab_api)
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=R1))
    new_net = "version: 2\nethernets:\n  ens2:\n    addresses: [192.0.2.10/24]\n"
    preview, applied = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "files": {"network-config": new_net}}
    )
    assert preview["status"] == "preview", preview
    diff = preview["preview"]["diff"]
    assert list(diff) == ["network-config"] and "+    addresses: [192.0.2.10/24]" in diff["network-config"]
    assert applied["result"]["files"] == ["network-config"]
    assert json.loads(patch.calls.last.request.content) == {
        "configuration": [
            {"name": "Main", "content": UBUNTU_FILES[0]["content"]},
            {"name": "network-config", "content": new_net},
        ]
    }


async def test_set_node_config_main_and_files_together(lab_api: respx.MockRouter) -> None:
    ubuntu_node(lab_api)
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=R1))
    preview, _ = await preview_apply(
        "cml_set_node_config",
        {"lab": LID, "node": "r1", "configuration": "#cloud-config\nhostname: u2\n", "files": {"extra": "x"}},
    )
    assert set(preview["preview"]["diff"]) == {"user-data", "extra"}
    assert "(new file)" in preview["preview"]["diff"]["extra"]
    assert json.loads(patch.calls.last.request.content)["configuration"] == [
        {"name": "Main", "content": "#cloud-config\nhostname: u2\n"},
        {"name": "network-config", "content": UBUNTU_FILES[1]["content"]},
        {"name": "extra", "content": "x"},
    ]


async def test_set_node_config_main_file_named_in_files(lab_api: respx.MockRouter) -> None:
    ubuntu_node(lab_api)
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=R1))
    _, applied = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "files": {"user-data": "#cloud-config\n"}}
    )
    assert applied["status"] == "applied"
    assert json.loads(patch.calls.last.request.content) == {
        "configuration": [
            {"name": "Main", "content": "#cloud-config\n"},
            {"name": "network-config", "content": UBUNTU_FILES[1]["content"]},
        ]
    }
    preview, _ = await preview_apply(
        "cml_set_node_config",
        {"lab": LID, "node": "r1", "configuration": "a", "files": {"user-data": "b"}},
    )
    assert preview["status"] == "blocked" and "not both" in preview["blockers"][0]


async def test_set_node_config_checks_definition_files(lab_api: respx.MockRouter) -> None:
    wiped = [dict(n, state="DEFINED_ON_CORE") for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=wiped))
    preview, _ = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "files": {"config.json": "{}"}}
    )
    assert preview["status"] == "blocked" and "not an editable file of iol-xe" in preview["blockers"][0]
    lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=R1))
    preview, _ = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "files": {"notes.txt": "x"}}
    )
    assert preview["status"] == "preview"
    assert "'notes.txt' is not a day-0 file of iol-xe" in json.dumps(preview)


async def test_set_node_config_needs_something(lab_api: respx.MockRouter) -> None:
    wiped = [dict(n, state="DEFINED_ON_CORE") for n in NODES]
    lab_api.get(f"/labs/{LID}/nodes").mock(return_value=httpx.Response(200, json=wiped))
    preview, _ = await preview_apply("cml_set_node_config", {"lab": LID, "node": "r1"})
    assert preview["status"] == "blocked" and "give configuration, files or both" in preview["blockers"][0]


async def test_set_node_config_main_only_keeps_other_files(lab_api: respx.MockRouter) -> None:
    ubuntu_node(lab_api)
    patch = lab_api.patch(f"/labs/{LID}/nodes/{R1}").mock(return_value=httpx.Response(200, json=R1))
    preview, _ = await preview_apply(
        "cml_set_node_config", {"lab": LID, "node": "r1", "configuration": "#cloud-config\n"}
    )
    assert preview["preview"]["kept"] == ["network-config"]
    assert json.loads(patch.calls.last.request.content)["configuration"] == [
        {"name": "Main", "content": "#cloud-config\n"},
        {"name": "network-config", "content": UBUNTU_FILES[1]["content"]},
    ]
