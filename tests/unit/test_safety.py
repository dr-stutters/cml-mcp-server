"""L20: CML safety rails (protected/managed labs, blast radius, device command deny-list, TLS pinning)."""

import importlib.metadata
import ssl
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import Client
from pydantic import ValidationError
from stutters_mcp_core.testing import call_tool

from cml_mcp.safety import denied_lines, lab_matches
from cml_mcp.server import create_server

from .conftest import LID, make_settings
from .test_write_tools import RW, RWD, preview_apply


async def preview_only(name: str, args: dict[str, Any], **settings: Any) -> dict[str, Any]:
    async with Client(create_server(make_settings(**settings))) as c:
        res = await c.call_tool(name, args)
    return dict(res.structured_content or {})


def test_lab_matching_by_glob_and_id() -> None:
    lab = {"id": LID, "lab_title": "Customer-Demo 1"}
    assert lab_matches(lab, ["customer-*"]) == "customer-*"
    assert lab_matches(lab, [LID.upper()]) == LID.upper()
    assert lab_matches(lab, ["mcp-*", "other"]) is None


@pytest.mark.parametrize(
    "line",
    [
        "write erase",
        "  do write erase",
        "erase startup-config",
        "reload in 5",
        "format flash:",
        "delete /force flash:x.bin",
        "crypto key zeroize rsa",
        "configure manager delete",
        "rm -rf /etc",
        "reboot",
    ],
)
def test_deny_list_blocks_destructive_lines(line: str) -> None:
    assert denied_lines([line], make_settings()) == [line]


@pytest.mark.parametrize(
    "line",
    [
        "interface Gi1",
        " description reload test",
        "no ip address",
        "show reload",
        "configure manager add 1.2.3.4 k",
    ],
)
def test_deny_list_allows_normal_lines(line: str) -> None:
    assert denied_lines([line], make_settings()) == []


def test_deny_list_settings() -> None:
    assert denied_lines(["reload"], make_settings(config_deny_defaults=False)) == []
    assert denied_lines(["clear ip ospf process"], make_settings(config_deny=r"clear\s+ip\s+ospf")) == [
        "clear ip ospf process"
    ]
    with pytest.raises(ValidationError):
        make_settings(config_deny="(unclosed")


async def test_protected_lab_blocks_writes_and_dangerous(lab_api: respx.MockRouter) -> None:
    for tool, args in [
        ("cml_stop_lab", {"lab": LID}),
        ("cml_delete_lab", {"lab": "mcp-test-probe", "force": True}),
        ("cml_set_link_condition", {"lab": LID, "link": "r1<->r2", "latency_ms": 5}),
    ]:
        preview, applied = await preview_apply(tool, args, **RWD, protected_labs="other, MCP-TEST-*")
        assert preview["status"] == "blocked" and applied is None, (tool, preview)
        assert any("CML_PROTECTED_LABS matches 'MCP-TEST-*'" in b for b in preview["blockers"]), preview


async def test_managed_labs_limit_only_dangerous_tools(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply(
        "cml_delete_link", {"lab": LID, "link": "r1<->r2"}, **RWD, managed_labs="mcp-cml-*"
    )
    assert preview["status"] == "blocked" and "not managed by this server" in preview["blockers"][0]
    # a write tool on the same lab is fine
    preview = await preview_only("cml_stop_lab", {"lab": LID}, **RW, managed_labs="mcp-cml-*")
    assert not any("managed" in b for b in preview.get("blockers") or [])
    # matching lab: allowed
    preview = await preview_only(
        "cml_delete_link", {"lab": LID, "link": "r1<->r2"}, **RWD, managed_labs="mcp-test-*"
    )
    assert preview["status"] == "preview"


async def test_blast_radius_is_nodes_affected_and_limited(lab_api: respx.MockRouter) -> None:
    preview = await preview_only("cml_stop_lab", {"lab": LID}, **RW)
    assert preview["blast_radius"] == 2  # both routers of the fixture lab
    preview = await preview_only(
        "cml_stop_lab", {"lab": LID}, **RW, mcp_blast_radius_overrides="cml_stop_lab=1"
    )
    assert preview["status"] == "blocked"


async def test_configure_node_preview_blocks_denied_lines(lab_api: respx.MockRouter) -> None:
    args = {"lab": LID, "node": "r1", "lines": ["hostname r1", "do write erase"]}
    preview, _ = await preview_apply("cml_configure_node", args, **RW)
    assert preview["status"] == "blocked"
    assert any("deny-list" in b and "do write erase" in b for b in preview["blockers"])


def self_signed_pem() -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cml-test-controller")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_tls_pinning_settings(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        make_settings(tls_check_hostname=False)  # without a pinned certificate
    ca = tmp_path / "controller.pem"
    ca.write_bytes(self_signed_pem())
    s = make_settings(ca_bundle=str(ca), tls_check_hostname=False)
    ctx = s.tls_verify()
    assert isinstance(ctx, ssl.SSLContext) and ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    checked = make_settings(ca_bundle=str(ca)).tls_verify()
    assert isinstance(checked, ssl.SSLContext) and checked.check_hostname is True
    assert make_settings(verify_ssl=False).tls_verify() is False


async def test_status_reports_security(api: respx.MockRouter) -> None:
    data = await call_tool(create_server(make_settings(protected_labs="prod-*")), "cml_status")
    sec = data["cml"]["security"]
    assert sec["protected_labs"] == ["prod-*"] and sec["config_deny"] >= 10
    assert "verified" in sec["tls"]


# --- review fixes -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "wr er",
        "wr e",
        "rel",
        "reloa in 5",
        "del flash:x",
        "era nvram:",
        "cry key zer rsa",
        "sudo reboot",
        "/sbin/reboot",
        "systemctl poweroff",
        "init 0",
        "shutdown now",
        "rm -f -r /tmp/x",
        "rm --recursive /x",
        "sh -c 'echo'",
        "clear configure all",
    ],
)
def test_deny_list_catches_abbreviations_and_variants(line: str) -> None:
    assert denied_lines([line], make_settings()) == [line]


@pytest.mark.parametrize("line", ["delay 10", "release-notes", "weight 5", "shutdown", "description era"])
def test_deny_list_leaves_lookalikes(line: str) -> None:
    assert denied_lines([line], make_settings()) == []


def test_custom_deny_regex_is_validated_as_used() -> None:
    with pytest.raises(ValidationError):
        make_settings(config_deny="(?i)clear")  # a global flag isn't valid inside the anchored rule


async def test_configure_node_refuses_control_characters(lab_api: respx.MockRouter) -> None:
    args = {"lab": LID, "node": "r1", "lines": ["show clock\rreload"]}
    preview, _ = await preview_apply("cml_configure_node", args, **RW)
    assert preview["status"] == "blocked" and any("control characters" in b for b in preview["blockers"])


def test_pinning_needs_exactly_one_certificate(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(self_signed_pem() + self_signed_pem())
    with pytest.raises(ValidationError, match="exactly one certificate"):
        make_settings(ca_bundle=str(bundle), tls_check_hostname=False)
    one = tmp_path / "one.pem"
    one.write_bytes(self_signed_pem())
    ctx = make_settings(ca_bundle=str(one), tls_check_hostname=False).tls_verify()
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


def test_stop_candidates_for_non_admin_scope() -> None:
    from cml_mcp.licence import stop_candidates

    labs = [{"id": "a", "own": True}, {"id": "b", "own": False}]
    assert stop_candidates({"labs": labs, "scope": "visible labs only"}) == [labs[0]]
    assert stop_candidates({"labs": labs}) == labs
    unknown = [{"id": "a"}, {"id": "b"}]
    assert stop_candidates({"labs": unknown, "pool_binds": True}) == unknown


async def test_redactor_replaces_lab_secret_values(fake_lab_secrets: dict[str, str]) -> None:
    from fastmcp.exceptions import ToolError
    from fastmcp.tools.base import ToolResult
    from mcp.types import TextContent

    from cml_mcp.redaction import LabSecretRedactor

    red = LabSecretRedactor(None)

    async def ok(_: Any) -> ToolResult:
        text = "enable secret Fake-Cli-Pw9\nkey fake-radius-key"
        return ToolResult(content=[TextContent(type="text", text=text)], structured_content={"config": text})

    res = await red.on_call_tool(None, ok)
    assert (
        "Fake-Cli-Pw9" not in str(res.content) and "${LAB_CLI_PASSWORD}" in res.structured_content["config"]
    )
    assert "${LAB_RADIUS_SECRET}" in res.content[0].text

    async def fail(_: Any) -> Any:
        raise ValueError("CML said: bad config 'radius key fake-radius-key'")

    with pytest.raises(ToolError) as err:
        await red.on_call_tool(None, fail)
    assert "fake-radius-key" not in str(err.value) and "${LAB_RADIUS_SECRET}" in str(err.value)


async def test_recipe_lab_config_reads_are_redacted(lab_api: respx.MockRouter) -> None:
    """A recipe lab's day-0 config holds the real values; reading it back must not return them."""
    import httpx

    from .conftest import NODES

    nid = NODES[0]["id"]
    node = {**NODES[0], "configuration": "hostname r1\nusername netadmin secret Fake-Cli-Pw9\n"}
    lab_api.get(f"/labs/{LID}/nodes/{nid}").mock(return_value=httpx.Response(200, json=node))
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool("cml_get_node", {"lab": LID, "node": nid, "include_config": True})
    assert "Fake-Cli-Pw9" not in str(res.content) + str(res.structured_content)


def test_substitute_cannot_repoint_secret_references(monkeypatch: pytest.MonkeyPatch) -> None:
    from stutters_mcp_core import InvalidRequest

    from cml_mcp.recipes import check_substitute, resolve_secrets

    with pytest.raises(InvalidRequest):
        check_substitute({"LAB_SNMP_RO": "LAB_SNMP_RW"})
    monkeypatch.setenv("LAB_X", "two\nlines")
    with pytest.raises(InvalidRequest, match="line break"):
        resolve_secrets("x ${LAB_X}", None)


async def test_wireless_capture_refuses_wired_nodes(lab_api: respx.MockRouter) -> None:
    import httpx

    from .conftest import NODES

    lab_api.get(f"/wireless/pcap/{NODES[0]['id']}").mock(return_value=httpx.Response(404, json={"code": 404}))
    preview = await preview_only("cml_capture_wireless", {"lab": LID, "node": "r1"}, **RW)
    assert preview["status"] == "blocked" and "wireless captures run at" in preview["blockers"][0]


# --- L24 ---------------------------------------------------------------------------------------------


async def test_guard_uses_the_lab_the_tool_resolved(lab_api: respx.MockRouter) -> None:
    """The guard reuses the tool's own (exact) resolution: one /labs listing per write preview, not two."""
    import traceback

    import httpx

    from .conftest import fixture

    calls = {"n": 0}

    def labs(request: httpx.Request) -> httpx.Response:
        if any(f.filename.endswith("cml_mcp/safety.py") for f in traceback.extract_stack()):
            calls["n"] += 1  # a listing made by the guard itself
        return httpx.Response(200, json=fixture("labs.json"))

    lab_api.get("/labs").mock(side_effect=labs)
    preview = await preview_only("cml_stop_lab", {"lab": "mcp-test-probe"}, **RW, protected_labs="mcp-test-*")
    assert preview["status"] == "blocked" and "CML_PROTECTED_LABS" in preview["blockers"][-1]
    assert calls["n"] == 0


def test_console_all_toggle_only_for_non_admins() -> None:
    from cml_mcp.console import ConsoleServer

    srv = ConsoleServer("https://cml.test", "u", "p")
    assert srv.admin is None  # unknown until login: the retry is allowed


async def test_status_reports_server_version(api: respx.MockRouter) -> None:
    data = await call_tool(create_server(make_settings()), "cml_status")
    assert "server_version" not in data["cml"]  # core reports it under server
    assert data["server"]["server_version"] == importlib.metadata.version("cml-mcp-server")
    assert data["server"]["core_version"] == importlib.metadata.version("stutters-mcp-core")
