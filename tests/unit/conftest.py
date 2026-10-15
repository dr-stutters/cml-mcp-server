import base64
import json
import os
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


# Fake lab secrets for the recipes' ${LAB_*} placeholders (never the real lab values).
FAKE_LAB_SECRETS = {
    "LAB_CLI_PASSWORD": "Fake-Cli-Pw9",
    "LAB_SNMP_RO": "fake-ro",
    "LAB_SNMP_RW": "fake-rw",
    "LAB_RADIUS_SECRET": "fake-radius-key",
    "LAB_FTD_REG_KEY": "fake-reg-key",
    "LAB_FTD_ADMIN_PASSWORD": "Fake-Ftd-Pw9!",
    "LAB_FTD_HA_ADMIN_PASSWORD": "Fake-FtdHa-Pw9!",
}


@pytest.fixture(autouse=True)
def fake_lab_secrets(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for k in [k for k in os.environ if k.startswith("LAB_")]:
        monkeypatch.delenv(k)
    for k, v in FAKE_LAB_SECRETS.items():
        monkeypatch.setenv(k, v)
    return FAKE_LAB_SECRETS


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
        mock.get("/users/00000000-0000-4000-a000-000000000000").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "00000000-0000-4000-a000-000000000000",
                    "username": "admin",
                    "admin": True,
                    "resource_pool": None,
                },
            )
        )
        yield mock


LAB = fixture("lab.json")
LID = LAB["id"]
NODES = fixture("nodes.json")
NODE_CONFIGS = fixture("node_configs.json")
LINKS = fixture("links.json")
R1, R2 = NODES[0]["id"], NODES[1]["id"]
LINK = LINKS[0]["id"]

TESTBED = """devices:
  r1:
    credentials:
      default:
        password: cisco
        username: cisco
  r2:
    credentials:
      default:
        password: cisco
        username: cisco
  terminal_server:
    credentials:
      default:
        password: change_me
        username: change_me
"""


def _node(request: httpx.Request, node_id: str) -> httpx.Response:
    with_config = request.url.params.get("exclude_configurations") != "true"
    source = NODE_CONFIGS if with_config else NODES
    for n in source:
        if n["id"] == node_id:
            return httpx.Response(200, json=n)
    return httpx.Response(404, json={"code": 404, "description": f"Node not found: {node_id}"})


@pytest.fixture
def lab_api(api: respx.MockRouter) -> respx.MockRouter:
    """The api fixture plus the captured 'mcp-test-probe' lab (two IOL routers, one link)."""

    def ok(data: Any) -> httpx.Response:
        return httpx.Response(200, json=data)

    lab = f"/labs/{LID}"
    api.get("/labs").mock(
        side_effect=lambda r: ok(fixture("labs.json") if r.url.params.get("with_data") else [LID])
    )
    api.get(lab).mock(return_value=ok(LAB))
    api.get(f"{lab}/nodes").mock(
        side_effect=lambda r: ok(
            NODES if r.url.params.get("exclude_configurations") == "true" else NODE_CONFIGS
        )
    )
    for nid in (R1, R2):
        api.get(f"{lab}/nodes/{nid}").mock(side_effect=lambda r, nid=nid: _node(r, nid))
        api.get(f"{lab}/nodes/{nid}/consoles/0/log").mock(return_value=ok(fixture("console_log.json")))
        api.get(f"{lab}/nodes/{nid}/check_if_converged").mock(return_value=ok(True))
    api.get(f"{lab}/interfaces").mock(return_value=ok(fixture("interfaces.json")))
    api.get(f"{lab}/links").mock(return_value=ok(LINKS))
    api.get(f"{lab}/links/{LINK}").mock(return_value=ok(LINKS[0]))
    api.get(f"{lab}/links/{LINK}/condition").mock(return_value=ok(fixture("link_condition.json")))
    api.get(f"{lab}/links/{LINK}/capture/status").mock(return_value=ok(fixture("capture_status.json")))
    api.get(f"/pcap/{LINK}/packets").mock(return_value=ok(fixture("capture_packets.json")))
    api.get(f"{lab}/topology").mock(return_value=ok(fixture("topology.json")))
    api.get(f"{lab}/layer3_addresses").mock(return_value=ok(fixture("layer3_addresses.json")))
    api.get(f"{lab}/events").mock(return_value=ok(fixture("events.json")))
    api.get(f"{lab}/simulation_stats").mock(return_value=ok(fixture("simulation_stats.json")))
    api.get(f"{lab}/lab_element_state").mock(return_value=ok(fixture("element_state.json")))
    api.get(f"{lab}/check_if_converged").mock(return_value=ok(True))
    api.get(f"{lab}/state").mock(return_value=ok("STARTED"))
    api.get(f"{lab}/download").mock(
        return_value=httpx.Response(200, text=(FIXTURES / "lab_export.yaml").read_text())
    )
    api.get(f"{lab}/pyats_testbed").mock(return_value=httpx.Response(200, text=TESTBED))
    api.get("/system_stats").mock(return_value=ok(fixture("system_stats.json")))
    api.get("/simplified_node_definitions").mock(return_value=ok(fixture("simplified_node_definitions.json")))
    api.get("/image_definitions").mock(return_value=ok(fixture("image_definitions.json")))
    api.get("/node_definitions/iol-xe").mock(return_value=ok(fixture("node_definition_iol_xe.json")))
    api.get("/node_definitions/iol-xe/image_definitions").mock(
        return_value=ok([i for i in fixture("image_definitions.json") if i["node_definition_id"] == "iol-xe"])
    )
    return api
