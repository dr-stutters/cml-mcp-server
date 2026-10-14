import base64
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from cml_mcp.config import Settings

BASE = "https://cml.test"
API = BASE + "/api/v0"
FIXTURES = Path(__file__).parent.parent / "fixtures"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def make_jwt(sub: str = "00000000-0000-4000-a000-000000000000", exp: float | None = None) -> str:
    def b64(d: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    claims = {"sub": sub, "exp": int(exp or time.time() + 86400), "iss": "com.cisco.virl"}
    return f"{b64({'alg': 'HS256'})}.{b64(claims)}.sig"


TOKEN = make_jwt()


def make_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "url": BASE,
        "username": "admin",
        "password": "pw",
        "retries": 0,
        "mcp_cache_dir": "",
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=API, assert_all_called=False) as mock:
        mock.post("/auth_extended").mock(
            return_value=httpx.Response(
                200,
                json={
                    "username": "admin",
                    "id": "00000000-0000-4000-a000-000000000000",
                    "token": TOKEN,
                    "admin": True,
                },
            )
        )
        mock.get("/system_information").mock(
            return_value=httpx.Response(200, json={"version": "2.10.0+build.13", "ready": True})
        )
        mock.get("/system_health").mock(return_value=httpx.Response(200, json=fixture("system_health.json")))
        mock.get("/licensing").mock(return_value=httpx.Response(200, json=fixture("licensing.json")))
        mock.get("/labs").mock(return_value=httpx.Response(200, json=[]))
        yield mock
