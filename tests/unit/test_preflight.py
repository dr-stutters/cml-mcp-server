"""L37: `cml-mcp-server check` against a mocked CML controller, one test per failure mode."""

import json
from typing import Any

import httpx
import pytest
import respx

from cml_mcp import main
from cml_mcp._core.preflight import run_preflight
from cml_mcp.preflight import preflight
from tests.unit.conftest import API, BASE, make_jwt, make_settings

UID = "00000000-0000-4000-a000-000000000001"
POOL = "11111111-0000-4000-a000-000000000001"


def _mock(
    router: respx.MockRouter,
    *,
    version: str = "2.10.0+build.13",
    admin: bool | None = False,
    extended: bool = True,
    pool: dict[str, Any] | None = None,
    licensing: httpx.Response | None = None,
) -> None:
    token = make_jwt(UID)
    if extended:
        router.post(f"{API}/auth_extended").respond(
            json={"username": "mcp-cml-viewer", "id": UID, "token": token, "admin": admin}
        )
    else:  # older controllers: plain /authenticate returns the JWT as a JSON string
        router.post(f"{API}/auth_extended").respond(404)
        router.post(f"{API}/authenticate").respond(json=token)
    router.get(f"{API}/system_information").respond(json={"version": version, "ready": True})
    user: dict[str, Any] = {"id": UID, "username": "mcp-cml-viewer", "resource_pool": POOL if pool else None}
    if admin is not None:
        user["admin"] = admin
    router.get(f"{API}/users/{UID}").respond(json=user)
    if pool is not None:
        router.get(f"{API}/resource_pool_usage/{POOL}").respond(json=pool)
    router.get(f"{API}/licensing").mock(return_value=licensing or httpx.Response(403))


def _pool(limit: int, used: int = 0) -> dict[str, Any]:
    return {
        "id": POOL,
        "label": "mcp-cml-operator-pool",
        "limit": {"licenses": limit, "ram": 65536},
        "usage": {"licenses": used, "ram": 0},
    }


async def _run(**kw: Any) -> dict[str, Any]:
    return await run_preflight(
        make_settings(**kw), preflight, server="cml-mcp-server", product="CML", env_prefix="CML_"
    )


def _rows(report: dict[str, Any], check: str, inst: int = 0) -> list[dict[str, Any]]:
    return [c for c in report["instances"][inst]["checks"] if c["check"] == check]


def _one(report: dict[str, Any], check: str) -> dict[str, Any]:
    (row,) = _rows(report, check)
    return row


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as r:
        yield r


async def test_healthy_read_only(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run()
    assert report["ok"]
    reach = _one(report, "reachability")
    assert reach["outcome"] == "ok" and reach["surface"] == "api" and "mcp-cml-viewer" in reach["detail"]
    assert _one(report, "tls")["outcome"] == "ok"
    assert _one(report, "auth")["outcome"] == "ok"
    role = _one(report, "role")
    assert role["outcome"] == "ok" and "regular user" in role["detail"]
    assert _one(report, "version")["outcome"] == "ok"
    assert not _rows(report, "licences")  # only checked when writes are on
    assert '"pw"' not in json.dumps(report)


async def test_plain_authenticate_login(router: respx.MockRouter) -> None:
    _mock(router, extended=False, admin=False)
    report = await _run()
    assert report["ok"]
    assert router.calls  # the fallback login and GET /users/<id> told us the admin flag
    assert "regular user" in _one(report, "role")["detail"]


async def test_unreachable(router: respx.MockRouter) -> None:
    router.route().mock(side_effect=httpx.ConnectError("[Errno 111] Connection refused"))
    report = await _run()
    reach = _one(report, "reachability")
    assert reach["outcome"] == "fail" and "CML_URL" in reach["hint"]
    assert _one(report, "auth")["outcome"] == "skip"
    assert not report["ok"]


async def test_tls_not_trusted(router: respx.MockRouter) -> None:
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed")
    router.route().mock(side_effect=err)
    report = await _run()
    tls = _one(report, "tls")
    assert tls["outcome"] == "fail" and "CML_CA_BUNDLE" in tls["hint"]
    assert _one(report, "role")["outcome"] == "skip"


@pytest.mark.parametrize("status", [401, 403])  # CML answers a bad login with 403 "Authentication failed!"
async def test_wrong_password(router: respx.MockRouter, status: int) -> None:
    body = {"code": status, "description": "Authentication failed!"}
    router.post(f"{API}/auth_extended").respond(status, json=body)
    router.post(f"{API}/authenticate").respond(status, json=body)
    router.route().respond(401)
    report = await _run()
    auth = _one(report, "auth")
    assert auth["outcome"] == "fail" and "CML_PASSWORD" in auth["hint"]
    assert not _rows(report, "role") or _one(report, "role")["outcome"] == "skip"
    assert _one(report, "version")["outcome"] == "skip"
    assert not report["ok"]


async def test_admin_on_read_only_server_warns(router: respx.MockRouter) -> None:
    _mock(router, admin=True)
    report = await _run()
    role = _one(report, "role")
    assert role["outcome"] == "warn" and "CML admin" in role["detail"]
    assert "read-only account" in role["hint"]
    assert report["ok"]


async def test_admin_with_every_tier_is_ok(router: respx.MockRouter) -> None:
    lic = httpx.Response(200, json={"authorization": {"status": "EVAL"}, "features": []})
    _mock(router, admin=True, licensing=lic)
    report = await _run(mcp_enable_writes=True, mcp_enable_dangerous=True)
    assert _one(report, "role")["outcome"] == "ok"
    lic_row = _one(report, "licences")
    assert lic_row["outcome"] == "ok" and lic_row["data"]["limit"] == 5


async def test_regular_user_with_writes_is_ok(router: respx.MockRouter) -> None:
    _mock(router, pool=_pool(12, 3))
    report = await _run(mcp_enable_writes=True)
    assert _one(report, "role")["outcome"] == "ok"
    lic = _one(report, "licences")
    assert lic["outcome"] == "ok" and "9 of 12" in lic["detail"]


async def test_regular_user_with_dangerous_warns(router: respx.MockRouter) -> None:
    _mock(router, pool=_pool(12))
    report = await _run(mcp_enable_writes=True, mcp_enable_dangerous=True)
    role = _one(report, "role")
    assert role["outcome"] == "warn" and "cml_upload_image" in role["detail"]
    assert report["ok"]  # a warning, not a failure: dangerous tools still work on its own labs


async def test_licences_zero_warns(router: respx.MockRouter) -> None:
    _mock(router, pool=_pool(0))
    report = await _run(mcp_enable_writes=True)
    lic = _one(report, "licences")
    assert lic["outcome"] == "warn" and "0 node licences" in lic["detail"]
    assert report["ok"]


async def test_licences_unknown_warns(router: respx.MockRouter) -> None:
    _mock(router)  # no pool, /licensing refused (non-admin)
    report = await _run(mcp_enable_writes=True)
    lic = _one(report, "licences")
    assert lic["outcome"] == "warn" and "CML_NODE_LICENSE_LIMIT" in lic["hint"]


async def test_admin_flag_unknown(router: respx.MockRouter) -> None:
    _mock(router, admin=None, extended=False)
    assert _one(await _run(), "role")["outcome"] == "ok"  # reads work; nothing more is enabled
    assert _one(await _run(mcp_enable_writes=True), "role")["outcome"] == "warn"


@pytest.mark.parametrize(
    ("version", "outcome"),
    [("2.10.0+build.13", "ok"), ("2.9.1+build.2", "warn"), ("2.6.1+build.11", "fail")],
)
async def test_version_matrix(router: respx.MockRouter, version: str, outcome: str) -> None:
    _mock(router, version=version)
    assert _one(await _run(), "version")["outcome"] == outcome


async def test_two_instances(router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CML_LAB2_URL", "https://cml-lab2.test")
    monkeypatch.setenv("CML_LAB2_USERNAME", "mcp-cml-viewer")
    monkeypatch.setenv("CML_LAB2_PASSWORD", "x")
    _mock(router)
    router.route(host="cml-lab2.test").mock(side_effect=httpx.ConnectError("no route to host"))
    report = await _run(instances="lab2")
    assert [i["instance"] for i in report["instances"]] == ["default", "lab2"]
    assert report["instances"][0]["ok"] and not report["instances"][1]["ok"]


def test_cli_check_json(
    router: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    for k, v in {
        "CML_URL": BASE,
        "CML_USERNAME": "mcp-cml-viewer",
        "CML_PASSWORD": "s3cret",
        "CML_RETRIES": "0",
        "MCP_CACHE_DIR": "",
    }.items():
        monkeypatch.setenv(k, v)
    _mock(router)
    monkeypatch.setattr("sys.argv", ["cml-mcp-server", "check", "--json"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert json.loads(out)["ok"] is True and "s3cret" not in out
