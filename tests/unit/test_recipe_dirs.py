"""CML_RECIPE_DIRS (L42): recipes from directories outside the package (e.g. a recipe checkout mounted into
the container) are listed, built and verified like packaged ones. A packaged recipe wins on a name clash,
files that aren't used are reported with why, and recipe YAML never comes from a tool caller."""

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from cml_mcp import recipes
from cml_mcp._core.testing import call_tool
from cml_mcp.recipes import get_recipe, recipe_names, recipe_source, skipped_recipe_files, use_recipe_dirs
from cml_mcp.server import create_server

from .conftest import LAB, fixture, make_settings
from .test_verify import _ftd_console

CLI_PW = "Fake-Cli-Pw9"  # conftest FAKE_LAB_SECRETS


def extra_recipe(title: str = "mcp-test-extra", tcp_port: int = 1) -> dict[str, Any]:
    return {
        "name": "extra-routers",
        "summary": "Two IOL routers from a recipe checkout",
        "boot_minutes": 1,
        "address_plan": {"r1": "198.18.128.151"},
        "credentials": {"cli": "admin / ${LAB_CLI_PASSWORD}"},
        "build": {
            "title": title,
            "nodes": [
                {
                    "label": "r1",
                    "definition": "iol-xe",
                    "config": "hostname r1\nusername admin privilege 15 secret ${LAB_CLI_PASSWORD}\n",
                    "credentials": {"username": "admin", "password": "${LAB_CLI_PASSWORD}"},
                },
                {"label": "r2", "definition": "iol-xe", "config": "hostname r2\n"},
            ],
            "links": ["r1 r2"],
        },
        "verify": {
            "nodes": ["r1"],
            "targets": ["198.18.134.76"],
            "addresses": {"r1": ["198.18.128.151"]},
            "probes": [
                {"name": "manager", "node": "r1", "command": "show managers", "expect": r"198\.18\.134\.76"},
                {"name": "ssh", "tcp": f"127.0.0.1:{tcp_port}"},
            ],
        },
    }


def write(directory: Path, name: str, recipe: Any) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.yaml"
    path.write_text(recipe if isinstance(recipe, str) else yaml.safe_dump(recipe, sort_keys=False))
    return path


@pytest.fixture(autouse=True)
def no_extra_dirs() -> Iterator[None]:
    """create_server sets the module's recipe directories: don't leak them into other tests."""
    yield
    use_recipe_dirs(None)


def test_extra_recipes_load_after_the_packaged_ones(tmp_path: Path) -> None:
    packaged = recipe_names()
    path = write(tmp_path / "a", "extra-routers", extra_recipe())
    use_recipe_dirs(f"{tmp_path / 'a'},{tmp_path / 'missing'}")
    assert recipe_names() == [*packaged, "extra-routers"]
    assert get_recipe("extra-routers")["build"]["title"] == "mcp-test-extra"
    assert recipe_source("extra-routers") == str(path) and recipe_source("ftd-fmc") == "package"
    assert recipes.recipe_for_lab("mcp-test-extra") == "extra-routers"
    assert skipped_recipe_files() == [{"file": str(tmp_path / "missing"), "problem": "not a directory"}]
    use_recipe_dirs(None)
    assert recipe_names() == packaged


def test_packaged_recipe_wins_and_the_clash_is_reported(tmp_path: Path) -> None:
    changed = {**get_recipe("ftd-fmc"), "summary": "an edited copy"}
    clash = write(tmp_path / "x", "ftd-fmc", changed)
    write(tmp_path / "x", "catc-routers", get_recipe("catc-routers"))  # an identical copy: nothing to say
    write(tmp_path / "y", "extra-routers", {**extra_recipe(), "summary": "first"})
    later = write(tmp_path / "z", "extra-routers", {**extra_recipe(), "summary": "second"})
    use_recipe_dirs(f"{tmp_path / 'x'}:{tmp_path / 'y'}:{tmp_path / 'z'}")
    assert get_recipe("ftd-fmc")["summary"] != "an edited copy" and recipe_source("ftd-fmc") == "package"
    assert get_recipe("extra-routers")["summary"] == "first"
    skipped = {s["file"]: s["problem"] for s in skipped_recipe_files()}
    assert set(skipped) == {str(clash), str(later)}
    assert "packaged one is used" in skipped[str(clash)] and "another name" in skipped[str(clash)]
    assert str(tmp_path / "y") in skipped[str(later)]


def test_unusable_files_are_skipped_without_quoting_them(tmp_path: Path) -> None:
    bad = write(tmp_path, "broken", f"name: broken\nbuild:\n  nodes: [\n  secret: {CLI_PW}: x\n")
    lab = write(tmp_path, "a-lab-export", {"lab": {"title": "x"}, "nodes": []})
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"\xff\xfe name: x\n")
    use_recipe_dirs(str(tmp_path))
    skipped = {s["file"]: s["problem"] for s in skipped_recipe_files()}
    assert skipped[str(bad)].startswith("invalid YAML at line ")
    assert skipped[str(lab)] == "not a recipe (no build: mapping)"
    assert skipped[str(binary)] == "not UTF-8 text"
    assert CLI_PW not in json.dumps(skipped)
    assert "broken" not in recipe_names()


def test_a_recipe_added_later_is_there_without_a_restart(tmp_path: Path) -> None:
    use_recipe_dirs(str(tmp_path))
    assert "extra-routers" not in recipe_names()
    path = write(tmp_path, "extra-routers", extra_recipe())
    assert "extra-routers" in recipe_names()
    path.write_text(yaml.safe_dump({**extra_recipe(), "summary": "edited"}))
    assert get_recipe("extra-routers")["summary"] == "edited"


async def test_list_recipes_shows_extra_recipes_and_skipped_files(
    api: respx.MockRouter, tmp_path: Path
) -> None:
    path = write(tmp_path, "extra-routers", extra_recipe())
    write(tmp_path, "notes", "just: text\n")
    srv = create_server(make_settings(recipe_dirs=str(tmp_path)))
    rows = await call_tool(srv, "cml_list_recipes", {"response_format": "json"})
    by = {r["name"]: r for r in rows["results"]}
    assert by["extra-routers"]["source"] == str(path) and by["extra-routers"]["lab_state"] == "not built"
    assert "source" not in by["ftd-fmc"]
    assert rows["skipped"] == [f"{tmp_path / 'notes.yaml'}: not a recipe (no build: mapping)"]
    detail = await call_tool(srv, "cml_list_recipes", {"recipe": "extra-routers"})
    assert detail["source"] == str(path) and detail["credentials"]["references"] == ["LAB_CLI_PASSWORD"]
    assert CLI_PW not in json.dumps(rows) + json.dumps(detail)


async def test_build_recipe_from_an_extra_dir(api: respx.MockRouter, tmp_path: Path) -> None:
    write(tmp_path, "extra-routers", extra_recipe())
    api.get("/simplified_node_definitions").mock(
        return_value=httpx.Response(200, json=fixture("simplified_node_definitions.json"))
    )
    imported = api.post("/import").mock(return_value=httpx.Response(200, json={"id": "L-new"}))
    args = {"recipe": "extra-routers", "start": False}
    async with Client(create_server(make_settings(mcp_enable_writes=True, recipe_dirs=str(tmp_path)))) as c:
        preview = (await c.call_tool("cml_build_recipe", args)).structured_content
        assert preview["status"] == "preview", preview
        assert preview["preview"]["links"] == ["r1:Ethernet0/0<->r2:Ethernet0/0"]
        applied = (
            await c.call_tool("cml_build_recipe", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied["status"] == "applied", applied
    assert CLI_PW not in json.dumps(preview) + json.dumps(applied)
    sent = yaml.safe_load(imported.calls.last.request.content.decode())
    r1 = sent["nodes"][0]
    assert f"secret {CLI_PW}" in r1["configuration"][0]["content"] and r1["pyats"]["password"] == CLI_PW
    assert recipes.read_recipe_marker(sent["lab"]["notes"]) == {"recipe": "extra-routers", "substitute": {}}
    notes = " ".join(a.get("text_content", "") for a in sent.get("annotations") or [])
    assert "cml-mcp-server recipe: extra-routers" in notes and CLI_PW not in notes


async def test_verify_recipe_from_an_extra_dir(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    write(tmp_path, "extra-routers", extra_recipe(title=LAB["lab_title"], tcp_port=port))
    _ftd_console(monkeypatch, "Host: 198.18.134.76\r\nRegistration: Completed")
    async with server:
        data = await call_tool(
            create_server(make_settings(recipe_dirs=str(tmp_path))),
            "cml_verify_recipe",
            {"recipe": "extra-routers"},
        )
    assert data["passed"] is True, data
    assert {c["kind"] for c in data["checks"]} == {"state", "ping", "address", "console", "tcp"}


async def test_recipe_tools_take_no_recipe_yaml_from_the_caller() -> None:
    """Probes and actions run console commands because they come from recipe files: no tool takes recipe
    YAML."""
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        tools = {t.name: set(t.input_schema["properties"]) for t in await c.list_tools()}
    assert tools["cml_build_recipe"] == {
        "recipe",
        "title",
        "substitute",
        "start",
        "wait",
        "timeout",
        "confirm",
    }
    assert tools["cml_verify_recipe"] == {"recipe", "lab", "substitute"}
    assert tools["cml_run_recipe_action"] == {"recipe", "action", "lab", "confirm"}
    assert tools["cml_list_recipes"] == {"recipe", "limit", "offset", "response_format"}
