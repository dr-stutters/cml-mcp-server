"""cml_build_lab fills ${LAB_*} lab secrets on the server (L42): a node's config, files and credentials can
carry references instead of values. The tool call, the preview, the result and the audit log only ever carry
the references; the topology sent to CML carries the values."""

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
CLI_PW = "Fake-Cli-Pw9"  # conftest FAKE_LAB_SECRETS
SNMP_RW = "fake-rw"
SECRETS = (CLI_PW, SNMP_RW)

ARGS: dict[str, Any] = {
    "title": "mcp-test-secrets",
    "description": "Log in as admin with ${LAB_CLI_PASSWORD}",
    "nodes": [
        {
            "label": "r1",
            "definition": "iol-xe",
            "config": "hostname r1\nusername admin privilege 15 secret ${LAB_CLI_PASSWORD}\n",
            "credentials": {"username": "admin", "password": "${LAB_CLI_PASSWORD}"},
            "tags": ["login:${LAB_CLI_PASSWORD}"],
        },
        {
            "label": "r2",
            "definition": "iol-xe",
            "config": "hostname r2\n",
            "files": {"snmp.cfg": "snmp-server community ${LAB_SNMP_RW} RW\n"},
        },
    ],
    "links": ["r1 r2"],
}


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


def _shows_no_secret(*shown: Any) -> None:
    blob = json.dumps(shown)
    assert not [s for s in SECRETS if s in blob], blob


async def test_build_lab_fills_lab_secrets_only_in_what_goes_to_cml(
    lab_api: respx.MockRouter, audit_lines: list[str]
) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new", "warnings": []}))
    _shows_no_secret(ARGS)
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", ARGS))
        assert preview["status"] == "preview", preview
        assert preview["preview"]["lab_secrets"] == {"LAB_CLI_PASSWORD": ["r1"], "LAB_SNMP_RW": ["r2"]}
        assert any("never shown" in s for s in preview["side_effects"])
        assert not route.called
        applied = data(await c.call_tool("cml_build_lab", {**ARGS, "confirm": preview["confirm"]}))
    assert applied["status"] == "applied" and applied["result"]["id"] == "new", applied
    _shows_no_secret(preview, applied, audit_lines)
    assert any('"applied"' in line for line in audit_lines)

    sent = _posted(route)
    r1, r2 = sent["nodes"]
    assert f"username admin privilege 15 secret {CLI_PW}" in r1["configuration"][0]["content"]
    assert r1["pyats"] == {"username": "admin", "password": CLI_PW}
    assert r2["configuration"][1] == {"name": "snmp.cfg", "content": f"snmp-server community {SNMP_RW} RW\n"}
    # only what reaches the devices is filled: the description and tags keep the reference
    assert sent["lab"]["description"] == "Log in as admin with ${LAB_CLI_PASSWORD}"
    assert r1["tags"] == ["login:${LAB_CLI_PASSWORD}"]
    assert route.calls.last.request.url.params["title"] == "mcp-test-secrets"


async def test_build_lab_names_a_missing_lab_secret(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, audit_lines: list[str]
) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    monkeypatch.delenv("LAB_SNMP_RW")
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", ARGS))
    assert preview["status"] == "blocked" and "confirm" not in preview
    blocker = " ".join(preview["blockers"])
    assert "LAB_SNMP_RW" in blocker and "CML_LAB_SECRETS_FILE" in blocker
    assert "LAB_CLI_PASSWORD" not in blocker  # only the missing one is named
    assert preview["preview"]["lab_secrets"] == {"LAB_CLI_PASSWORD": ["r1"], "LAB_SNMP_RW": ["r2"]}
    _shows_no_secret(preview, audit_lines)
    assert not route.called


async def test_build_lab_refuses_when_a_secret_goes_missing_before_confirm(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", ARGS))
        assert preview["status"] == "preview"
        monkeypatch.delenv("LAB_CLI_PASSWORD")
        res = await c.call_tool(
            "cml_build_lab", {**ARGS, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = json.dumps(data(res)) if not res.is_error else res.content[0].text  # type: ignore[union-attr]
    assert "LAB_CLI_PASSWORD" in text and "Nothing was changed" in text, text
    assert not route.called


async def test_build_lab_reads_the_lab_secrets_file(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """From CML_LAB_SECRETS_FILE; a value YAML would misread in a plain scalar (': ', ' #') still lands
    intact."""
    tricky = "From-File: Pw7 #x"
    secrets = tmp_path / "lab-secrets.env"
    secrets.write_text(f"LAB_CLI_PASSWORD='{tricky}'\n")
    monkeypatch.delenv("LAB_CLI_PASSWORD")
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    async with Client(create_server(make_settings(**RW, lab_secrets_file=str(secrets)))) as c:
        preview = data(await c.call_tool("cml_build_lab", ARGS))
        assert preview["status"] == "preview", preview
        applied = data(await c.call_tool("cml_build_lab", {**ARGS, "confirm": preview["confirm"]}))
    assert applied["status"] == "applied"
    r1 = _posted(route)["nodes"][0]
    assert r1["pyats"]["password"] == tricky and f"secret {tricky}\n" in r1["configuration"][0]["content"]
    assert tricky not in json.dumps(preview) + json.dumps(applied)


async def test_build_lab_never_echoes_secrets_in_cml_warnings_or_errors(
    lab_api: respx.MockRouter, audit_lines: list[str]
) -> None:
    """CML's warnings and errors can quote the configs it was sent."""
    route = lab_api.post("/import").mock(
        return_value=httpx.Response(200, json={"id": "new", "warnings": [f"r1: odd line secret {CLI_PW}"]})
    )
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", ARGS))
        applied = data(await c.call_tool("cml_build_lab", {**ARGS, "confirm": preview["confirm"]}))
        assert applied["result"]["warnings"] == ["r1: odd line secret ${LAB_CLI_PASSWORD}"]

        route.mock(return_value=httpx.Response(500, json={"description": f"bad config: secret {CLI_PW}"}))
        preview = data(await c.call_tool("cml_build_lab", ARGS))
        res = await c.call_tool(
            "cml_build_lab", {**ARGS, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "${LAB_CLI_PASSWORD}" in text and CLI_PW not in text
    assert any("apply_failed" in line for line in audit_lines)
    _shows_no_secret(audit_lines)


async def test_build_lab_cleans_a_filled_value_from_blockers(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, audit_lines: list[str]
) -> None:
    """A filled config can reach a blocker (an external connector's name is its config); the blocker and the
    audit log name the reference (the redacting middleware never sees the audit log)."""
    monkeypatch.setenv("LAB_BRIDGE_NAME", "Hidden-Bridge7")
    lab_api.get("/system/external_connectors").mock(
        return_value=httpx.Response(200, json=[{"label": "System Bridge", "device_name": "bridge0"}])
    )
    args = {
        "title": "mcp-test-ext",
        "nodes": [{"label": "ext", "definition": "external_connector", "config": "${LAB_BRIDGE_NAME}"}],
    }
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", args))
    assert preview["status"] == "blocked", preview
    assert "'${LAB_BRIDGE_NAME}' does not exist" in " ".join(preview["blockers"])
    assert any("blocked" in line for line in audit_lines)
    assert "Hidden-Bridge7" not in json.dumps(preview) + json.dumps(audit_lines)


async def test_build_lab_without_references_is_unchanged(lab_api: respx.MockRouter) -> None:
    route = lab_api.post("/import").mock(return_value=httpx.Response(200, json={"id": "new"}))
    args = {
        "title": "mcp-test-plain",
        "nodes": [{"label": "r1", "definition": "iol-xe", "config": "hostname r1\n"}],
    }
    async with Client(create_server(make_settings(**RW))) as c:
        preview = data(await c.call_tool("cml_build_lab", args))
        assert "lab_secrets" not in preview["preview"] and "side_effects" not in preview
        await c.call_tool("cml_build_lab", {**args, "confirm": preview["confirm"]})
    assert _posted(route)["nodes"][0]["configuration"][0]["content"] == "hostname r1\n"
