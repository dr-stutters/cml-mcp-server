"""L1: cml_list_recipes, cml_build_recipe, the cml_build_test_lab prompt."""

import json

import httpx
import pytest
import respx
from fastmcp import Client
from stutters_mcp_core.testing import assert_prompt_contract, call_tool

from cml_mcp.recipes import get_recipe, recipe_names
from cml_mcp.server import create_server
from cml_mcp.tools.recipes_tools import recipe_detail, recipe_secrets

from .conftest import fixture, make_settings

KNOWN_SECRETS = ("***REDACTED***", "***REDACTED***", "***REDACTED***", "mcp-rw")


@pytest.mark.parametrize("name", recipe_names())
def test_recipe_detail_never_carries_secrets(name: str) -> None:
    blob = json.dumps(recipe_detail(name))
    assert not [s for s in KNOWN_SECRETS if s in blob]
    assert recipe_secrets(get_recipe(name))  # something was found to scrub


async def test_prompt_contract(api: respx.MockRouter) -> None:
    await assert_prompt_contract(
        create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)),
        "cml",
        samples={"cml_build_test_lab": {"recipe": "ise-access"}},
        known_prefixes={"cml", "ise", "fmc", "catc"},
    )


async def test_prompt_renders_and_is_hidden_without_writes(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        res = await c.get_prompt("cml_build_test_lab", {"recipe": "ftd-fmc", "reuse": "false"})
        text = res.messages[0].content.text  # type: ignore[union-attr]
    for tool in ("cml_plan_licences", "cml_build_recipe", "cml_wait_for_converged", "cml_verify_recipe"):
        assert f"`{tool}`" in text
    assert "ftd-fmc" in text and "delete and rebuild" in text
    async with Client(create_server(make_settings())) as c:
        assert "cml_build_test_lab" not in {p.name for p in await c.list_prompts()}


async def test_list_recipes_tool(api: respx.MockRouter) -> None:
    api.get("/labs").mock(
        return_value=httpx.Response(200, json=[{"id": "L1", "lab_title": "mcp-cml-ise", "state": "STOPPED"}])
    )
    srv = create_server(make_settings())
    rows = await call_tool(srv, "cml_list_recipes", {"response_format": "json"})
    by = {r["name"]: r for r in rows["results"]}
    assert by["ise-access"]["lab_state"] == "STOPPED" and by["ftd-fmc"]["lab_state"] == "not built"
    detail = await call_tool(srv, "cml_list_recipes", {"recipe": "ise-access"})
    assert detail["lab_state"] == "STOPPED" and "radius_shared_secret" in detail["credentials"]["keys"]
    assert not [s for s in KNOWN_SECRETS if s in json.dumps(detail)]


async def test_build_recipe_preview(api: respx.MockRouter) -> None:
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/system/external_connectors").mock(
        return_value=httpx.Response(
            200, json=[{"label": "System Bridge", "device_name": "bridge0", "tags": ["System Bridge"]}]
        )
    )
    api.get("/nodes").mock(return_value=httpx.Response(200, json=[]))
    data = await call_tool(
        create_server(make_settings(mcp_enable_writes=True)), "cml_build_recipe", {"recipe": "catc-routers"}
    )
    assert data["status"] in ("preview", "blocked"), data
    assert "mcp-cml-catc" in data["action"] and data["preview"]["start"] is True
    assert not [s for s in KNOWN_SECRETS if s in json.dumps(data)]
