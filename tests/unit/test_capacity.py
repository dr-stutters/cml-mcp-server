"""L28 RAM checks, L30 per-lab usage, L32 compact licence blocks, L33 cml_stop_labs."""

from typing import Any

import httpx
import respx
from fastmcp import Client
from stutters_mcp_core.testing import call_tool

from cml_mcp.licence import compact_usage, nodes_ram_mb, ram_check
from cml_mcp.server import create_server

from .conftest import make_settings
from .test_planning import _cml

GIB = 2**30


def _stats(api: respx.MockRouter, total_gb: float, used_gb: float, allocated_gb: float) -> None:
    api.get("/system_stats").mock(
        return_value=httpx.Response(
            200,
            json={
                "all": {"memory": {"total": int(total_gb * GIB), "used": int(used_gb * GIB)}},
                "computes": {"c": {"stats": {"dominfo": {"allocated_memory": int(allocated_gb * 2**20)}}}},
            },
        )
    )


def test_ram_check_and_node_ram() -> None:
    defs = {"iol-xe": {"sim": {"ram": 1024}}}
    assert nodes_ram_mb([{"node_definition": "iol-xe"}, {"definition": "x", "ram": 512}], defs) == 1536
    ram = {"total_mb": 4096, "used_mb": 1000, "allocated_to_running_nodes_mb": 3000, "free_mb": 1096}
    assert ram_check(ram, 1000) == {"needed_mb": 1000, "free_mb": 1096, "total_mb": 4096, "ok": True}
    short = ram_check(ram, 2048)
    assert short and short["ok"] is False and "only 1.1 GB of 4 GB" in short["warning"]
    assert ram_check(None, 10) is None and ram_check(ram, 0) is None


def test_compact_usage_keeps_numbers_only_when_free() -> None:
    usage = {
        "running_licensed_nodes": 3,
        "by_lab": {"a": 3},
        "labs": [{}],
        "limit": 70,
        "free": 67,
        "limit_source": "x",
    }
    assert compact_usage(usage) == {"running_licensed_nodes": 3, "limit": 70, "free": 67, "limit_source": "x"}
    assert compact_usage({**usage, "free": 0}) == {**usage, "free": 0}


async def test_plan_licences_warns_when_ram_is_short(api: respx.MockRouter) -> None:
    _cml(api)
    _stats(api, total_gb=32, used_gb=10, allocated_gb=20)  # 12 GB free; cat9000v needs 18
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=[{"id": "cat9000v-uadp", "sim": {"ram": 18432}}])
    )
    data = await call_tool(create_server(make_settings()), "cml_plan_licences", {"target": "ise-access"})
    assert data["ram"]["ok"] is False and data["ram"]["free_mb"] == 12 * 1024
    assert "GB RAM" in data["plan"]["summary"]


def _labs(api: respx.MockRouter) -> None:
    labs = [
        {"id": "L1", "lab_title": "mcp-cml-a", "state": "STARTED", "owner": "u1"},
        {"id": "L2", "lab_title": "mcp-cml-b", "state": "STARTED", "owner": "u2"},
        {"id": "L3", "lab_title": "customer", "state": "STARTED", "owner": "u2"},
        {"id": "L4", "lab_title": "off", "state": "STOPPED", "owner": "u1"},
    ]
    api.get("/labs").mock(return_value=httpx.Response(200, json=labs))
    api.get("/users").mock(
        return_value=httpx.Response(
            200, json=[{"id": "u1", "username": "admin"}, {"id": "u2", "username": "bob"}]
        )
    )
    for lab in labs:
        api.get(f"/labs/{lab['id']}/nodes").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"id": "n", "label": "r1", "node_definition": "iol-xe", "state": "BOOTED", "ram": 1024},
                    {"id": "x", "label": "ext", "node_definition": "external_connector", "state": "BOOTED"},
                ],
            )
        )
        api.put(f"/labs/{lab['id']}/stop").mock(return_value=httpx.Response(204))
        api.get(f"/labs/{lab['id']}/state").mock(return_value=httpx.Response(200, json="STOPPED"))
        api.get(f"/labs/{lab['id']}").mock(return_value=httpx.Response(200, json={**lab, "state": "STOPPED"}))


async def test_stop_labs_preview_and_apply(api: respx.MockRouter) -> None:
    _labs(api)
    settings = make_settings(mcp_enable_writes=True, protected_labs="customer")
    args: dict[str, Any] = {"all_running": True, "keep": ["mcp-cml-b"], "wait": False}
    async with Client(create_server(settings)) as c:
        preview = (await c.call_tool("cml_stop_labs", args)).structured_content
        assert preview and preview["status"] == "preview", preview
        d = preview["preview"]
        assert [r["lab"] for r in d["labs"]] == ["mcp-cml-a"] and d["labs"][0]["owner"] == "admin"
        assert d["labs"][0]["licences_freed"] == 1 and d["ram_freed_mb"] == 1024
        assert d["refused_protected"] == ["customer (CML_PROTECTED_LABS 'customer')"]
        done = (
            await c.call_tool("cml_stop_labs", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert (
        done
        and done["status"] == "applied"
        and done["result"] == {"stopping": [{"lab": "mcp-cml-a", "id": "L1"}]}
    )
    stops = [r for r in api.calls if r.request.method == "PUT"]
    assert [str(r.request.url).rsplit("/", 2)[-2] for r in stops] == ["L1"]


async def test_stop_labs_needs_a_choice_and_skips_stopped(api: respx.MockRouter) -> None:
    _labs(api)
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        bad = await c.call_tool("cml_stop_labs", {}, raise_on_error=False)
        assert bad.is_error
        res = (await c.call_tool("cml_stop_labs", {"labs": ["off", "mcp-cml-b"]})).structured_content
    assert res and res["preview"]["already_stopped"] == ["off"]
    assert [r["lab"] for r in res["preview"]["labs"]] == ["mcp-cml-b"]


async def test_stop_labs_reports_a_failed_stop_and_goes_on(api: respx.MockRouter) -> None:
    _labs(api)
    api.put("/labs/L1/stop").mock(return_value=httpx.Response(403, json={"description": "not yours"}))
    args: dict[str, Any] = {"labs": ["mcp-cml-a", "mcp-cml-b"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_stop_labs", args)).structured_content
        assert preview
        res = await c.call_tool("cml_stop_labs", {**args, "confirm": preview["confirm"]})
    out = (res.structured_content or {})["result"]
    assert [f["lab"] for f in out["failed"]] == ["mcp-cml-a"]
    assert out["stopped"] == [{"lab": "mcp-cml-b", "id": "L2", "state": "STOPPED"}]
