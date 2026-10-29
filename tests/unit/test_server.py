from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp._core.testing import assert_tool_contract, call_tool
from cml_mcp.client import cml_error_detail, jwt_claims
from cml_mcp.server import create_server

from .conftest import TOKEN, make_settings


@pytest.mark.parametrize("kw", [{}, {"mcp_enable_writes": True, "mcp_enable_dangerous": True}])
async def test_contract(api: respx.MockRouter, kw: dict[str, Any]) -> None:
    await assert_tool_contract(create_server(make_settings(**kw)), "cml", undo_allow={"cml_api_call"})


async def test_status_logs_in_and_summarises(api: respx.MockRouter) -> None:
    api.get("/labs").mock(return_value=httpx.Response(200, json=["a", "b"]))
    data = await call_tool(create_server(make_settings()), "cml_status")
    cml = data["cml"]
    assert cml["version"] == "2.10.0+build.13"
    assert cml["user"] == "admin" and cml["admin"] is True
    assert cml["health"] == {"valid": True, "computes": 1, "problems": []}
    assert cml["licensing"]["authorization"] == "EVAL"
    assert cml["labs_visible"] == 2
    # every authenticated call carried the JWT from /auth_extended
    authed = [c.request for c in api.calls if c.request.url.path.endswith("/labs")]
    assert authed[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert "pw" not in str(data)


async def test_status_with_static_token(api: respx.MockRouter) -> None:
    api.get("/labs").mock(return_value=httpx.Response(200, json=[]))
    api.get("/users/00000000-0000-4000-a000-000000000000").mock(
        return_value=httpx.Response(200, json={"username": "svc", "id": "x", "admin": False})
    )
    pool = "11111111-1111-4111-8111-111111111111"
    api.get("/users/x").mock(
        return_value=httpx.Response(
            200, json={"username": "svc", "id": "x", "admin": False, "resource_pool": pool}
        )
    )
    api.get(f"/resource_pool_usage/{pool}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": pool,
                "label": "svc-pool",
                "limit": {"licenses": 12, "ram": 65536},
                "usage": {"licenses": 2, "ram": 2048},
            },
        )
    )
    settings = make_settings(username=None, password=None, token=f"Bearer {TOKEN}")
    data = await call_tool(create_server(settings), "cml_status")
    assert data["cml"]["user"] == "svc"
    assert data["cml"]["resource_pool"]["label"] == "svc-pool"
    assert data["cml"]["resource_pool"]["licenses_used"] == 2
    assert not api.routes[0].called  # no login with a static token


async def test_status_reports_bad_credentials(api: respx.MockRouter) -> None:
    api.post("/auth_extended").mock(
        return_value=httpx.Response(403, json={"code": 403, "description": "Authentication failed!"})
    )
    data = await call_tool(create_server(make_settings()), "cml_status")
    assert "Authentication failed!" in data["cml"]["error"]
    assert "CML_USERNAME" in data["cml"]["error"]


async def test_login_falls_back_to_authenticate(api: respx.MockRouter) -> None:
    api.post("/auth_extended").mock(return_value=httpx.Response(404, json={"code": 404}))
    api.post("/authenticate").mock(return_value=httpx.Response(200, json=TOKEN))
    api.get("/labs").mock(return_value=httpx.Response(200, json=[]))
    data = await call_tool(create_server(make_settings()), "cml_status")
    assert data["cml"]["user"] == "admin"


async def test_health_problems_are_listed(api: respx.MockRouter) -> None:
    api.get("/labs").mock(return_value=httpx.Response(200, json=[]))
    api.get("/system_health").mock(
        return_value=httpx.Response(
            200,
            json={
                "valid": False,
                "computes": {
                    "c1": {
                        "hostname": "h1",
                        "libvirt": False,
                        "cpu_overload": True,
                        "admission_state": "UNREACHABLE",
                    }
                },
                "controller": {"core_connected": False},
            },
        )
    )
    data = await call_tool(create_server(make_settings()), "cml_status")
    problems = data["cml"]["health"]["problems"]
    assert "compute h1: libvirt is false" in problems
    assert "compute h1: cpu_overload" in problems
    assert "compute h1: admission_state=UNREACHABLE" in problems
    assert "controller: core_connected is false" in problems


async def test_spec_tools_use_controller_openapi(api: respx.MockRouter) -> None:
    doc = {
        "openapi": "3.1.0",
        "info": {"version": "2.10.0"},
        "paths": {"/labs/{lab_id}/start": {"put": {"operationId": "start_lab", "summary": "Start a lab"}}},
    }
    api.get("/openapi.json").mock(return_value=httpx.Response(200, json=doc))
    async with Client(create_server(make_settings())) as c:
        res = await c.call_tool("cml_search_spec", {"query": "start lab"})
    assert res.structured_content["results"][0]["name"] == "PUT /labs/{lab_id}/start"


def test_error_detail_parses_validation_errors() -> None:
    body = {
        "code": 400,
        "description": '{"Input validation failed": [{"location": ["body", "node_definition"], '
        '"type": "missing", "message": "Field required"}]}',
    }
    assert cml_error_detail(body) == "body.node_definition: Field required"
    assert cml_error_detail({"code": 404, "description": "Lab not found: x"}) == "Lab not found: x"
    assert cml_error_detail({"detail": [{"loc": ["q", "x"], "msg": "bad"}]}) == "q.x: bad"
    assert cml_error_detail("plain") == "plain"
    assert cml_error_detail(None) is None


def test_jwt_claims() -> None:
    assert jwt_claims(TOKEN)["sub"] == "00000000-0000-4000-a000-000000000000"
    assert jwt_claims("garbage") == {}
