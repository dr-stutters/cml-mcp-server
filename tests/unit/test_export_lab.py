"""#71: a masked cml_export_lab is valid YAML that cml_import_lab accepts, cloud-init passwords become a
${LAB_NODE_PASSWORD} reference the import fills, and a large export comes back whole in pages."""

import hashlib
import json
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from cml_mcp._core.formatting import max_chars
from cml_mcp._core.testing import call_tool
from cml_mcp.server import create_server
from cml_mcp.tools.common import parse_topology_yaml
from cml_mcp.tools.labs import NODE_PASSWORD_PLACEHOLDER, export_page, mask_export

from .conftest import LID, make_settings

RW = {"mcp_enable_writes": True}
NODE_PW = "Fake-Node-Pw9"
PYATS_PW = "fake-pyats-pw"

# The shape CML 2.7+ downloads for an Ubuntu node with cloud-init plus an IOS-XE node (synthetic values)
EXPORT = f"""\
annotations:
  - border_color: '#00000000'
    text_content: |-
      ubuntu login: cisco
      password: {NODE_PW}
    type: text
lab:
  description: ''
  notes: ''
  title: mcp-test-export
  version: 0.3.0
links:
  - id: l0
    i1: i0
    i2: i0
    n1: n0
    n2: n1
    label: ubuntu1-ens2<->r1-Ethernet0/0
nodes:
  - boot_disk_size: null
    configuration:
      - name: user-data
        content: |-
          #cloud-config
          hostname: ubuntu1
          manage_etc_hosts: True
          system_info:
            default_user:
              name: cisco
          password: {NODE_PW}
          chpasswd: {{ expire: False }}
          users:
            - name: ops
              plain_text_passwd: {NODE_PW}
          write_files:
            - path: /etc/motd
              content: |
                lab host
      - name: network-config
        content: |-
          version: 2
          ethernets:
            ens2:
              addresses: [192.0.2.10/24]
    id: n0
    label: ubuntu1
    node_definition: ubuntu
    pyats:
      username: null
      password: {PYATS_PW}
      enable_password: null
    interfaces:
      - id: i0
        label: ens2
        type: physical
        slot: 0
  - boot_disk_size: null
    configuration:
      - name: iosxe_config.txt
        content: |-
          hostname r1
          username netadmin privilege 15 secret 9 $9$fakehash
          interface Ethernet0/0
           ip address 192.0.2.1 255.255.255.0
          end
    id: n1
    label: r1
    node_definition: iol-xe
    pyats:
      username: netadmin
      password: '{PYATS_PW}'
      enable_password: {PYATS_PW}*x
    interfaces:
      - id: i0
        label: Ethernet0/0
        type: physical
        slot: 0
"""


async def call(name: str, args: dict[str, Any], **settings: Any) -> Any:
    return await call_tool(create_server(make_settings(**settings)), name, args)


def data(res: Any) -> Any:
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


def test_masked_export_is_valid_yaml_with_secrets_gone() -> None:
    with pytest.raises(yaml.YAMLError):  # what 0.14.0 wrote: '*' starts a YAML alias
        yaml.safe_load("pyats:\n  password: ********\n")
    masked = mask_export(EXPORT)
    assert NODE_PW not in masked and PYATS_PW not in masked
    topo = parse_topology_yaml(masked)  # cml_import_lab's parser
    assert topo == yaml.safe_load(masked)
    ubuntu, r1 = topo["nodes"]
    assert ubuntu["pyats"] == {"username": None, "password": "********", "enable_password": None}
    assert r1["pyats"] == {"username": "netadmin", "password": "********", "enable_password": "********"}
    user_data = ubuntu["configuration"][0]["content"]
    assert f"password: {NODE_PASSWORD_PLACEHOLDER}" in user_data
    assert f"plain_text_passwd: {NODE_PASSWORD_PLACEHOLDER}" in user_data
    cloud = yaml.safe_load(user_data)  # still valid cloud-config
    assert cloud["password"] == NODE_PASSWORD_PLACEHOLDER and cloud["users"][0]["name"] == "ops"
    # everything else is unchanged: configs, the nested write_files block, links, annotations' other lines
    original = yaml.safe_load(EXPORT)
    assert r1["configuration"] == original["nodes"][1]["configuration"]
    assert ubuntu["configuration"][1] == original["nodes"][0]["configuration"][1]
    assert topo["links"] == original["links"]
    assert topo["lab"] == original["lab"]
    assert "ubuntu login: cisco" in topo["annotations"][0]["text_content"]
    assert NODE_PASSWORD_PLACEHOLDER in topo["annotations"][0]["text_content"]


def test_mask_keeps_nulls_and_lab_references() -> None:
    text = "pyats:\n  password: ${LAB_CLI_PASSWORD}\n  enable_password: null\n  - password: ~\n"
    assert mask_export(text) == text
    assert mask_export("    enable_password: y\n") == "    enable_password: '********'\n"


async def test_masked_export_reimports_and_fills_the_node_password(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_api.get(f"/labs/{LID}/download").mock(return_value=httpx.Response(200, text=EXPORT))
    masked = await call("cml_export_lab", {"lab": LID})
    assert isinstance(masked, str) and NODE_PW not in masked and PYATS_PW not in masked
    raw = await call("cml_export_lab", {"lab": LID, "include_credentials": True})
    assert raw == EXPORT

    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new", "warnings": []}))
    args = {"topology_yaml": masked, "title": "mcp-test-restore"}
    async with Client(create_server(make_settings(**RW))) as c:
        blocked = data(await c.call_tool("cml_import_lab", args))
        assert blocked["status"] == "blocked" and "LAB_NODE_PASSWORD" in json.dumps(blocked)
        monkeypatch.setenv("LAB_NODE_PASSWORD", "Fake-Restore-Pw9")
        preview = data(await c.call_tool("cml_import_lab", args))
        assert preview["status"] == "preview", preview
        assert preview["preview"]["lab_secrets"] == {"LAB_NODE_PASSWORD": ["ubuntu1"]}
        applied = data(await c.call_tool("cml_import_lab", {**args, "confirm": preview["confirm"]}))
    assert applied["status"] == "applied", applied
    sent = yaml.safe_load(route.calls.last.request.content.decode())
    cloud = yaml.safe_load(sent["nodes"][0]["configuration"][0]["content"])
    assert (
        cloud["password"] == "Fake-Restore-Pw9"
        and cloud["users"][0]["plain_text_passwd"] == "Fake-Restore-Pw9"
    )


def _big_export(nodes: int) -> str:
    rows = []
    for i in range(nodes):
        cfg = "\n".join(f'          description "link {j} of node {i}"' for j in range(40))
        rows.append(
            f"  - id: n{i}\n    label: r{i}\n    node_definition: iol-xe\n    configuration:\n"
            f"      - name: ios_config.txt\n        content: |-\n          hostname r{i}\n{cfg}\n"
            f"    pyats:\n      username: netadmin\n      password: {PYATS_PW}\n"
        )
    return "lab:\n  title: mcp-test-big\n  version: 0.3.0\nlinks: []\nnodes:\n" + "".join(rows)


async def test_large_export_pages_back_whole(lab_api: respx.MockRouter) -> None:
    big = _big_export(80)
    masked = mask_export(big)
    assert len(masked) > 3 * max_chars()
    lab_api.get(f"/labs/{LID}/download").mock(return_value=httpx.Response(200, text=big))
    parts: list[str] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        res = await call("cml_export_lab", {"lab": LID, "offset": offset})
        page = res if isinstance(res, dict) else json.loads(res)
        assert page["offset"] == offset and page["total_chars"] == len(masked)
        assert page["sha256"] == hashlib.sha256(masked.encode()).hexdigest()
        assert len(json.dumps(page, separators=(",", ":"))) <= max_chars()
        assert page["yaml"].endswith("\n") or page["complete"]
        parts.append(page["yaml"])
        offset = page["next_offset"]
        assert page["complete"] is (offset is None)
        pages += 1
    whole = "".join(parts)
    assert pages >= 4 and whole == masked and PYATS_PW not in whole
    assert len(parse_topology_yaml(whole)["nodes"]) == 80


async def test_small_export_with_limit_pages_and_bad_offset(lab_api: respx.MockRouter) -> None:
    lab_api.get(f"/labs/{LID}/download").mock(return_value=httpx.Response(200, text=EXPORT))
    masked = mask_export(EXPORT)
    first = await call("cml_export_lab", {"lab": LID, "limit": 1000})
    first = first if isinstance(first, dict) else json.loads(first)
    assert first["next_offset"] and len(first["yaml"]) <= 1000 and masked.startswith(first["yaml"])
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool("cml_export_lab", {"lab": LID, "offset": 10**6}, raise_on_error=False)
    assert res.is_error and "past the end" in res.content[0].text


def test_export_page_splits_at_line_breaks() -> None:
    text = "aaaa\nbbbb\ncccc\n"
    assert export_page(text, 0, 7) == ("aaaa\n", 5)
    assert export_page(text, 5, 100) == ("bbbb\ncccc\n", 15)
    assert export_page("x" * 10, 0, 4) == ("xxxx", 4)  # one long line is cut at the limit
