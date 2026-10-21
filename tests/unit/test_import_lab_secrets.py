"""cml_import_lab fills ${LAB_*} lab secrets on the server (a `cookbook render` file with
admin_password='${LAB_FTD_ADMIN_PASSWORD}'): the tool call, the preview, the result and the audit log only
ever carry the placeholder; the YAML sent to CML carries the value."""

import json
import logging
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from cml_mcp.server import create_server

from .conftest import make_settings

RW = {"mcp_enable_writes": True}
PW = "Fake-Ftd-Pw9!"  # conftest FAKE_LAB_SECRETS["LAB_FTD_ADMIN_PASSWORD"]

# The shape `cookbook render ftd-sdwan-single-hub --input admin_password='${LAB_FTD_ADMIN_PASSWORD}'` writes
# (trimmed to one FTD and one host)
COOKBOOK_LAB = """\
# CML lab for the CML Cookbook recipe ftd-sdwan-single-hub v1.0.0, written by cookbook render.
lab:
  version: 0.2.2
  title: FTD SD-WAN with one hub (ftd-sdwan-single-hub v1.0.0)
  notes: |-
    Log in to the FTDs as admin with ${LAB_FTD_ADMIN_PASSWORD}.
nodes:
- id: n0
  label: hub1
  node_definition: ftdv
  x: 0
  y: -400
  pyats:
    username: admin
    password: ${LAB_FTD_ADMIN_PASSWORD}
  configuration: |
    {
        "EULA": "accept",
        "Hostname": "hub1",
        "AdminPassword": "${LAB_FTD_ADMIN_PASSWORD}",
        "FirewallMode": "routed",
        "FmcIp": "192.0.2.10",
        "FmcRegKey": "cookbook",
        "ManageLocally": "No"
    }
  interfaces:
  - {id: i0, label: Management0/0, slot: 0, type: physical}
- id: n1
  label: h8
  node_definition: alpine
  x: 0
  y: -600
  configuration: |
    hostname h8
  interfaces:
  - {id: i0, label: eth0, slot: 0, type: physical}
links:
- {id: l0, n1: n0, n2: n1, i1: i0, i2: i0, label: hub1:Management0/0<->h8:eth0}
annotations:
- {type: text, text_content: "admin / ${LAB_FTD_ADMIN_PASSWORD}", x1: 0, y1: 0}
"""
ARGS = {"topology_yaml": COOKBOOK_LAB, "title": "mcp-test-cookbook"}


def data(res: Any) -> Any:
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


@pytest.fixture
def audit_lines() -> Iterator[list[str]]:
    """Everything the audit logger writes (it doesn't propagate, so caplog doesn't see it)."""
    log = logging.getLogger("stutters_mcp_core.audit")
    handler = _Records()
    log.addHandler(handler)
    old = log.level
    log.setLevel(logging.INFO)
    try:
        yield handler.lines
    finally:
        log.removeHandler(handler)
        log.setLevel(old)


def _posted(route: respx.Route) -> dict[str, Any]:
    return dict(yaml.safe_load(route.calls.last.request.content.decode()))


async def test_import_fills_lab_secrets_only_in_what_goes_to_cml(
    lab_api: respx.MockRouter, audit_lines: list[str]
) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new", "warnings": []}))
    assert PW not in json.dumps(ARGS) and "${LAB_FTD_ADMIN_PASSWORD}" in ARGS["topology_yaml"]
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_import_lab", ARGS))
        assert preview["status"] == "preview", preview
        assert preview["preview"]["lab_secrets"] == {"LAB_FTD_ADMIN_PASSWORD": ["hub1"]}
        assert any("never shown" in s for s in preview["side_effects"])
        assert not route.called
        applied = data(await c.call_tool("cml_import_lab", {**ARGS, "confirm": preview["confirm"]}))
    assert applied["status"] == "applied" and applied["result"]["id"] == "new", applied
    for shown in (preview, applied, audit_lines):
        assert PW not in json.dumps(shown)
    assert any('"applied"' in line for line in audit_lines)

    sent = _posted(route)
    hub1 = sent["nodes"][0]
    assert json.loads(hub1["configuration"])["AdminPassword"] == PW  # the day-0 JSON is still JSON
    assert hub1["pyats"]["password"] == PW
    assert sent["nodes"][1]["configuration"] == "hostname h8\n"
    assert sent["links"] == yaml.safe_load(COOKBOOK_LAB)["links"]
    # notes and annotations say where the credential is kept: they keep the reference
    assert "${LAB_FTD_ADMIN_PASSWORD}" in sent["lab"]["notes"]
    assert sent["annotations"][0]["text_content"] == "admin / ${LAB_FTD_ADMIN_PASSWORD}"
    assert route.calls.last.request.url.params["title"] == "mcp-test-cookbook"


async def test_import_names_a_missing_lab_secret(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    monkeypatch.delenv("LAB_FTD_ADMIN_PASSWORD")
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_import_lab", ARGS))
    assert preview["status"] == "blocked" and "confirm" not in preview
    blocker = " ".join(preview["blockers"])
    assert "LAB_FTD_ADMIN_PASSWORD" in blocker and "CML_LAB_SECRETS_FILE" in blocker
    assert preview["preview"]["lab_secrets"] == {"LAB_FTD_ADMIN_PASSWORD": ["hub1"]}
    assert not route.called


async def test_import_refuses_when_a_secret_goes_missing_before_confirm(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_import_lab", ARGS))
        assert preview["status"] == "preview"
        monkeypatch.delenv("LAB_FTD_ADMIN_PASSWORD")
        res = await c.call_tool(
            "cml_import_lab", {**ARGS, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "LAB_FTD_ADMIN_PASSWORD" in text and "Nothing was changed" in text
    assert not route.called


async def test_import_reads_the_lab_secrets_file_and_quotes_values(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """From CML_LAB_SECRETS_FILE; a value YAML would misread in a plain scalar (': ', ' #') still lands
    intact, since the parsed topology is filled and re-serialised, not the text."""
    tricky = "From-File: Pw7 #x"
    secrets = tmp_path / "lab-secrets.env"
    secrets.write_text(f"LAB_FTD_ADMIN_PASSWORD='{tricky}'\n")
    monkeypatch.delenv("LAB_FTD_ADMIN_PASSWORD")
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    async with Client(create_server(make_settings(**RW, lab_secrets_file=str(secrets)))) as c:
        preview = data(await c.call_tool("cml_import_lab", ARGS))
        assert preview["status"] == "preview", preview
        applied = data(await c.call_tool("cml_import_lab", {**ARGS, "confirm": preview["confirm"]}))
    assert applied["status"] == "applied"
    hub1 = _posted(route)["nodes"][0]
    assert hub1["pyats"]["password"] == tricky
    assert json.loads(hub1["configuration"])["AdminPassword"] == tricky
    assert tricky not in json.dumps(preview) + json.dumps(applied)


async def test_import_never_echoes_secrets_in_cml_warnings_or_errors(
    lab_api: respx.MockRouter, audit_lines: list[str]
) -> None:
    """CML's warnings and errors can quote the configs it was sent."""
    route = lab_api.post("/import").mock(
        return_value=httpx.Response(
            200, json={"id": "new", "warnings": [f"hub1: odd line AdminPassword {PW}"]}
        )
    )
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_import_lab", ARGS))
        applied = data(await c.call_tool("cml_import_lab", {**ARGS, "confirm": preview["confirm"]}))
        assert applied["result"]["warnings"] == ["hub1: odd line AdminPassword ${LAB_FTD_ADMIN_PASSWORD}"]

        route.mock(return_value=httpx.Response(500, json={"description": f"bad config: AdminPassword {PW}"}))
        preview = data(await c.call_tool("cml_import_lab", ARGS))
        res = await c.call_tool(
            "cml_import_lab", {**ARGS, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "${LAB_FTD_ADMIN_PASSWORD}" in text and PW not in text
    assert any("apply_failed" in line for line in audit_lines)
    assert PW not in json.dumps(audit_lines)


async def test_import_without_node_placeholders_sends_the_yaml_as_given(lab_api: respx.MockRouter) -> None:
    """A placeholder only in the notes is documentation, not a secret to fill: nothing is re-serialised."""
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    text = (
        "lab: {title: x, notes: 'password in ${LAB_CLI_PASSWORD}'}\n"
        "nodes:\n  - {id: n0, label: a, node_definition: iol-xe}\nlinks: []\n"
    )
    args = {"topology_yaml": text, "title": "mcp-test-plain"}
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_import_lab", args))
        assert "lab_secrets" not in preview["preview"] and "side_effects" not in preview
        await c.call_tool("cml_import_lab", {**args, "confirm": preview["confirm"]})
    assert route.calls.last.request.content.decode() == text
