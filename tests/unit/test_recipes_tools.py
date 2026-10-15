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

KNOWN_SECRETS = ("Fake-Cli-Pw9", "Fake-Ftd-Pw9!", "Fake-FtdHa-Pw9!", "fake-radius-key", "fake-rw")


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


def test_recipe_secrets_reads_dict_files() -> None:
    from cml_mcp.tools.recipes_tools import recipe_secrets

    r = {"build": {"nodes": [{"label": "u", "files": {"network-config": "password: Sup3rSecret9"}}]}}
    assert "Sup3rSecret9" in recipe_secrets(r)


async def test_build_recipe_copy_with_substitute(api: respx.MockRouter) -> None:
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/system/external_connectors").mock(
        return_value=httpx.Response(200, json=[{"label": "System Bridge", "device_name": "bridge0"}])
    )
    data = await call_tool(
        create_server(make_settings(mcp_enable_writes=True)),
        "cml_build_recipe",
        {
            "recipe": "catc-routers",
            "title": "mcp-cml2-x",
            "substitute": {"198.18.128.152": "198.18.128.199"},
            "start": False,
        },
    )
    assert "mcp-cml2-x" in data["action"], data
    assert not [s for s in KNOWN_SECRETS if s in json.dumps(data)]


# --- L21: ${LAB_*} secret references ----------------------------------------------------------------


@pytest.mark.parametrize("name", recipe_names())
def test_packaged_recipes_only_carry_references(name: str, fake_lab_secrets: dict[str, str]) -> None:
    from cml_mcp.recipes import RECIPE_DIR, placeholders

    raw = (RECIPE_DIR / f"{name}.yaml").read_text()
    assert placeholders(get_recipe(name)), "every recipe has at least one lab secret"
    assert not [v for v in fake_lab_secrets.values() if v in raw]


def _catc_build_mocks(api: respx.MockRouter) -> respx.Route:
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    api.get("/system/external_connectors").mock(
        return_value=httpx.Response(
            200, json=[{"label": "System Bridge", "device_name": "bridge0", "tags": ["System Bridge"]}]
        )
    )
    return api.post("/import").mock(return_value=httpx.Response(200, json={"id": "L-new"}))


async def test_build_recipe_fills_secrets_only_in_what_goes_to_cml(api: respx.MockRouter) -> None:
    imported = _catc_build_mocks(api)
    args = {"recipe": "catc-routers", "start": False}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("cml_build_recipe", args)).structured_content
        assert preview["status"] == "preview", preview
        assert "Fake-Cli-Pw9" not in json.dumps(preview) and "fake-ro" not in json.dumps(preview)
        applied = (
            await c.call_tool("cml_build_recipe", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied["status"] == "applied", applied
    body = imported.calls.last.request.content.decode()
    assert (
        "secret Fake-Cli-Pw9" in body
        and "community fake-ro RO" in body
        and "${LAB_" not in body.split("annotations")[0]
    )
    assert "Fake-Cli-Pw9" not in json.dumps(applied)


async def test_build_recipe_names_missing_secrets(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _catc_build_mocks(api)
    monkeypatch.delenv("LAB_SNMP_RW")
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        res = await c.call_tool(
            "cml_build_recipe", {"recipe": "catc-routers", "start": False}, raise_on_error=False
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "LAB_SNMP_RW" in text and "CML_LAB_SECRETS_FILE" in text
    assert "Fake-Cli-Pw9" not in text


def test_lab_secrets_file_and_env_override(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cml_mcp.recipes import lab_secrets, resolve_secrets

    f = tmp_path / "lab-secrets.env"  # type: ignore[operator]
    f.write_text("LAB_SNMP_RO=from-file\nLAB_ONLY_FILE=x1\nOTHER=ignored\n")
    monkeypatch.setenv("LAB_SNMP_RO", "from-env")
    values = lab_secrets(str(f))
    assert values["LAB_SNMP_RO"] == "from-env" and values["LAB_ONLY_FILE"] == "x1" and "OTHER" not in values
    assert resolve_secrets({"a": ["k ${LAB_ONLY_FILE}"]}, str(f)) == {"a": ["k x1"]}
    assert lab_secrets(str(tmp_path / "missing.env"))["LAB_SNMP_RO"] == "from-env"  # type: ignore[operator]


async def test_list_recipes_shows_secret_names_not_values(api: respx.MockRouter) -> None:
    detail = await call_tool(create_server(make_settings()), "cml_list_recipes", {"recipe": "ftd-fmc"})
    assert detail["credentials"]["references"] == ["LAB_FTD_ADMIN_PASSWORD", "LAB_FTD_REG_KEY"]
    assert "fake-reg-key" not in json.dumps(detail)


def test_fabric_recipe_shape() -> None:
    from cml_mcp.recipes import placeholders, recipe_licensed_nodes

    r = get_recipe("fabric")
    assert r["build"]["title"] == "mcp-cml-fabric" and recipe_licensed_nodes(r) == 5
    assert placeholders(r) == {"LAB_CLI_PASSWORD", "LAB_SNMP_RO", "LAB_SNMP_RW"}
    labels = {n["label"] for n in r["build"]["nodes"]}
    assert {"bcp", "edge1", "edge2", "fusion", "client"} <= labels
    # CML's own address block only (.190-.199)
    assert set(r["verify"]["addresses"]) == {"bcp", "edge1", "edge2"}
    assert all(
        a.startswith("198.18.128.19")
        for a in [r["verify"]["addresses"][n][0] for n in ("bcp", "edge1", "edge2")]
    )


def test_wireless_recipe_shape() -> None:
    from cml_mcp.recipes import placeholders, recipe_licensed_nodes

    r = get_recipe("wireless")
    assert r["build"]["title"] == "mcp-cml-wireless" and recipe_licensed_nodes(r) == 3
    assert placeholders(r) == {"LAB_CLI_PASSWORD", "LAB_SNMP_RO", "LAB_SNMP_RW", "LAB_RADIUS_SECRET"}
    defs = {n["label"]: n["definition"] for n in r["build"]["nodes"]}
    assert defs["wlc"] == "cat9800" and defs["ap"] == "wireless-ap" and defs["client"] == "wireless-client"
