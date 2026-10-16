"""L20 live: TLS + console host key pinned (scripts/pin_controller.py), protected-lab refusal."""

import subprocess
import sys
from pathlib import Path

import asyncssh
import pytest
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .conftest import ROOT, rw
from .labkit import _create, _delete

pytestmark = pytest.mark.live
SHOW = {"lab": "mcp-test-live-safety", "nodes": ["r1"], "commands": ["show clock"]}
TITLE = "mcp-test-live-safety"


@pytest.fixture
def pinned(settings: Settings, tmp_path: Path) -> Settings:
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "pin_controller.py"), settings.url, "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "ssh host key:" in out
    return settings.model_copy(
        update={
            "verify_ssl": True,
            "ca_bundle": tmp_path / "cml-ca.pem",
            "tls_check_hostname": "CML_TLS_CHECK_HOSTNAME=false" not in out,
            "console_known_hosts": str(tmp_path / "cml-known_hosts"),
        }
    )


async def test_pinned_tls_and_console(settings: Settings, pinned: Settings, tmp_path: Path) -> None:
    lab_id = await _create(settings, TITLE, start=True)  # replaces a leftover lab of the same title
    try:
        status = await call_tool(create_server(pinned), "cml_status")
        assert status["cml"]["ready"] is True and "CML_CA_BUNDLE" in status["cml"]["security"]["tls"]
        assert "CML_CONSOLE_KNOWN_HOSTS" in status["cml"]["security"]["console_ssh"]
        out = await call_tool(
            create_server(pinned),
            "cml_run_commands",
            SHOW,
        )
        assert out["results"][0]["outputs"][0]["output"], out

        # a different pinned host key: the console must refuse to connect
        wrong = tmp_path / "wrong_known_hosts"
        host = settings.url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        other_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()
        wrong.write_text(f"{host} {other_key}\n")
        bad = pinned.model_copy(update={"console_known_hosts": str(wrong)})
        out = await call_tool(
            create_server(bad),
            "cml_run_commands",
            SHOW,
        )
        assert "host key" in str(out).lower(), out

        # a pinned certificate with host-name checking on fails when the name doesn't match the URL
        if not pinned.tls_check_hostname:
            async with Client(create_server(pinned.model_copy(update={"tls_check_hostname": True}))) as c:
                res = await c.call_tool("cml_status", {}, raise_on_error=False)
                assert "certificate" in str(res.content).lower() or "ssl" in str(res.content).lower()

        # protected lab: preview is blocked, nothing changes
        guarded = rw(settings, protected_labs=f"{TITLE},other-*", mcp_enable_dangerous=True)
        async with Client(create_server(guarded)) as c:
            for tool, args in [
                ("cml_stop_lab", {"lab": TITLE}),
                ("cml_delete_lab", {"lab": TITLE, "force": True}),
            ]:
                preview = (await c.call_tool(tool, args)).structured_content
                assert preview["status"] == "blocked" and "CML_PROTECTED_LABS" in preview["blockers"][-1]
    finally:
        await _delete(settings, lab_id)
