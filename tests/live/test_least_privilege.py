"""L17: the server as non-admin CML accounts (docs/least-privilege.md).

- `mcp-cml-operator` (CML_RW_USERNAME/PASSWORD, MCP role rw) builds, starts and changes a lab it owns, and
  shares it with the viewers group;
- `mcp-cml-viewer` (CML_RO_USERNAME/PASSWORD, MCP role ro) runs every read tool against that lab.

The accounts come from `scripts/seed_lab.py --least-privilege` (run here first, as the admin in .env).
Skipped when the CML_RO_*/CML_RW_* credentials are not in .env.
"""

from collections.abc import AsyncIterator
from typing import Any

import pytest
from dotenv import dotenv_values
from fastmcp import Client

from cml_mcp._core.testing import as_caller, live_settings
from cml_mcp._core.testing.least_privilege import read_tier_report
from cml_mcp.client import CmlApp
from cml_mcp.config import Settings
from cml_mcp.least_privilege import seed_least_privilege
from cml_mcp.server import create_server

from .conftest import ROOT
from .labkit import confirm_call

pytestmark = pytest.mark.live
TITLE = "mcp-test-least-privilege"
ENV = dotenv_values(ROOT / ".env")

# Read tools that are expected to fail for a non-admin account (documented in docs/least-privilege.md).
ADMIN_ONLY = {"cml_get_licensing"}


def account(prefix: str, caller: str, role: str) -> Settings:
    user, password = ENV.get(f"{prefix}USERNAME"), ENV.get(f"{prefix}PASSWORD")
    if not user or not password:
        pytest.skip(
            f"{prefix}USERNAME / {prefix}PASSWORD not in .env (scripts/seed_lab.py --least-privilege)"
        )
    return live_settings(
        Settings,
        "CML_",
        _env_file=ROOT / ".env",
        mcp_cache_dir="",
        username=user,
        password=password,
        mcp_enable_writes=True,
        mcp_roles=f"{caller}:{role}",
    )


def samples() -> dict[str, dict[str, Any]]:
    lab = {"lab": TITLE}
    out: dict[str, dict[str, Any]] = {
        name: dict(lab)
        for name in (
            "cml_get_lab",
            "cml_get_lab_topology",
            "cml_list_nodes",
            "cml_list_interfaces",
            "cml_list_links",
            "cml_list_lab_events",
            "cml_export_lab",
            "cml_get_pyats_testbed",
            "cml_get_layer3_addresses",
            "cml_wait_for_converged",
            "cml_list_annotations",
            "cml_export_topology",
            "cml_get_link_scenarios",
        )
    }
    node = {"lab": TITLE, "node": "r1"}
    out.update({n: dict(node) for n in ("cml_get_node", "cml_get_node_console_log", "cml_diff_node_config")})
    link = {"lab": TITLE, "link": "r1<->r2"}
    out.update({n: dict(link) for n in ("cml_get_link", "cml_list_capture_packets", "cml_summarize_capture")})
    out["cml_run_commands"] = {"lab": TITLE, "nodes": ["r1"], "commands": ["show ip interface brief"]}
    out["cml_check_reachability"] = {"lab": TITLE, "nodes": ["r1"], "targets": ["10.99.0.2"]}
    out["cml_diff_lab"] = {"lab": TITLE, "other_lab": TITLE}
    out["cml_get_node_definition"] = {"definition": "iol-xe"}
    out["cml_plan_licences"] = {"target": TITLE}
    out["cml_search_spec"] = {"query": "labs"}
    out["cml_get_definition"] = {"name": "/labs"}
    return out


@pytest.fixture
async def accounts() -> AsyncIterator[dict[str, Any]]:
    admin = CmlApp(live_settings(Settings, "CML_", _env_file=ROOT / ".env", mcp_cache_dir=""))
    try:
        ids = await seed_least_privilege(admin)
        yield ids
    finally:
        for lab in await admin.list_labs():  # never leave the test lab behind, whoever owns it
            if lab.get("lab_title") == TITLE:
                await admin.api.put(f"/labs/{lab['id']}/stop")
                await admin.api.put(f"/labs/{lab['id']}/wipe")
                await admin.api.delete(f"/labs/{lab['id']}")
        await admin.aclose()


async def share(app: CmlApp, lab_id: str, group_id: str, permissions: list[str]) -> None:
    await app.api.patch(
        f"/labs/{lab_id}/associations", {"groups": [{"id": group_id, "permissions": permissions}]}
    )


async def test_operator_writes_and_viewer_reads(accounts: dict[str, Any]) -> None:
    op = account("CML_RW_", "op", "rw")
    viewer = account("CML_RO_", "least-privilege-check", "ro")
    viewers_group = accounts[viewer.username]["group_id"]  # type: ignore[index]

    # --- write tier as the non-admin operator (MCP role rw) ---
    async with Client(create_server(op)) as c:
        with as_caller("op"):
            status = (await c.call_tool("cml_status", {})).structured_content
            assert status["cml"]["admin"] is False and status["cml"]["resource_pool"]["licenses_limit"] == 12
            built = await confirm_call(
                c,
                "cml_build_lab",
                {
                    "title": TITLE,
                    "nodes": [
                        {"label": "r1", "definition": "iol-xe", "config": "hostname r1\nend\n"},
                        {"label": "r2", "definition": "iol-xe", "config": "hostname r2\nend\n"},
                    ],
                    "links": ["r1 r2"],
                    "start": True,
                },
            )
            assert built["convergence"]["converged"] is True
            plan = (await c.call_tool("cml_plan_licences", {"target": TITLE})).structured_content
            assert "not a CML admin" in plan["licences"]["scope"]
            assert plan["licences"]["by_lab"].get(TITLE) == 2
            await confirm_call(
                c,
                "cml_configure_node",
                {
                    "lab": TITLE,
                    "node": "r1",
                    "lines": ["interface Ethernet0/0", " ip address 10.99.0.1 255.255.255.0", " no shutdown"],
                },
            )
            await confirm_call(
                c,
                "cml_configure_node",
                {
                    "lab": TITLE,
                    "node": "r2",
                    "lines": ["interface Ethernet0/0", " ip address 10.99.0.2 255.255.255.0", " no shutdown"],
                },
            )
            await confirm_call(
                c, "cml_set_link_condition", {"lab": TITLE, "link": "r1<->r2", "latency_ms": 5}
            )
            await confirm_call(c, "cml_set_link_condition", {"lab": TITLE, "link": "r1<->r2", "clear": True})
            await confirm_call(
                c, "cml_annotate_lab", {"lab": TITLE, "notes": [{"text": "least-privilege test"}]}
            )

    op_app = CmlApp(op)
    try:
        lab_id = (await op_app.resolve_lab(TITLE, exact=True))["id"]
        # the owner (non-admin) can share its lab; view only first: CML then opens the console read-only,
        # so commands can't run (the tool reports an error per node, it never hangs)
        await share(op_app, lab_id, viewers_group, ["lab_view"])
        async with Client(create_server(viewer.model_copy(update={"timeout": 15.0}))) as c:
            with as_caller("least-privilege-check"):
                res = await c.call_tool(
                    "cml_run_commands",
                    {"lab": TITLE, "nodes": ["r1"], "commands": ["show clock"]},
                    raise_on_error=False,
                )
                assert res.is_error or "error" in str(res.structured_content["results"][0])
        # view + exec: every read tool must work (consoles included)
        await share(op_app, lab_id, viewers_group, ["lab_view", "lab_exec"])
    finally:
        await op_app.aclose()

    report = await read_tier_report(create_server(viewer), samples(), skip={"cml_api_call", *ADMIN_ONLY})
    print(report.summary())
    assert not report.denied, report.summary()
    assert "cml_build_lab" in report.hidden_writes and "cml_configure_node" in report.hidden_writes
    # the errors left are 'no data yet' answers, not permissions
    for name, err in report.errors.items():
        assert name in {"cml_summarize_capture", "cml_list_capture_packets"}, (name, err)
    assert {"cml_run_commands", "cml_diff_node_config", "cml_check_reachability"} <= set(report.ok)

    # the admin-only read tool fails with a clear message, not a stack of 403s
    async with Client(create_server(viewer)) as c:
        with as_caller("least-privilege-check"):
            res = await c.call_tool("cml_get_licensing", {}, raise_on_error=False)
            assert res.is_error and "admin-only" in str(res.content)
