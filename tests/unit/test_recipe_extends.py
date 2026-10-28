"""L40 (cml #14): a recipe can `extends:` another one and add to it. Nodes merge by label, links by their
ends, verify lists and probes by name, actions by name; cycles, unknown bases and removals that match
nothing make the recipe unusable (listed under `skipped`) without breaking the other recipes."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
import yaml

from cml_mcp import recipes
from cml_mcp._core import InvalidRequest
from cml_mcp._core.testing import call_tool
from cml_mcp.recipes import get_recipe, recipe_actions, recipe_names, skipped_recipe_files, use_recipe_dirs
from cml_mcp.server import create_server

from .conftest import make_settings

FIXTURES = Path(__file__).parent.parent / "fixtures" / "recipes"


def base_recipe() -> dict[str, Any]:
    return {
        "name": "base-hub",
        "summary": "A hub and two spokes",
        "boot_minutes": 2,
        "address_plan": {"hub": "198.51.100.1"},
        "credentials": {"cli": "admin / ${LAB_CLI_PASSWORD}"},
        "build": {
            "title": "mcp-test-base",
            "description": "base lab",
            "nodes": [
                {"label": "hub", "definition": "iol-xe", "config": "hostname hub\n", "x": 0, "y": 0},
                {"label": "s1", "definition": "iol-xe", "config": "hostname s1\n"},
                {"label": "s2", "definition": "iol-xe", "config": "hostname s2\n"},
            ],
            "links": ["hub:Ethernet0/1 s1:Ethernet0/0", "hub:Ethernet0/2 s2:Ethernet0/0", "s1 s2"],
        },
        "verify": {
            "booted": ["hub", "s1", "s2"],
            "nodes": ["hub"],
            "targets": ["198.51.100.11"],
            "addresses": {"hub": ["198.51.100.1"]},
            "probes": [
                {"name": "hub up", "node": "hub", "command": "show version", "expect": "IOS"},
                {"name": "s2 route", "node": "s2", "command": "show ip route", "expect": "0.0.0.0"},
            ],
        },
        "actions": {
            "bounce-s2": {"node": "s2", "command": "clear ip route *", "description": "flush s2 routes"},
            "hub-ping": {"node": "hub", "command": "ping 198.51.100.11", "description": "ping"},
        },
    }


def write(directory: Path, name: str, recipe: Any) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.yaml"
    path.write_text(recipe if isinstance(recipe, str) else yaml.safe_dump(recipe, sort_keys=False))
    return path


@pytest.fixture(autouse=True)
def no_extra_dirs() -> Iterator[None]:
    yield
    use_recipe_dirs(None)


def test_child_adds_to_and_overrides_its_base(tmp_path: Path) -> None:
    write(tmp_path, "base-hub", base_recipe())
    write(
        tmp_path,
        "child-hub",
        {
            "name": "child-hub",
            "extends": "base-hub",
            "summary": "The hub lab plus a firewall",
            "build": {
                "description": "child lab",
                "nodes": [
                    {"label": "hub", "ram": 4096, "config": "hostname hub\ninterface Ethernet0/3\n"},
                    {"label": "fw", "definition": "alpine"},
                ],
                "links": [
                    "s1:Ethernet0/0 hub:Ethernet0/1",  # the same link written the other way round: kept once
                    "hub:Ethernet0/2 fw:eth0",  # takes hub Ethernet0/2: replaces the hub-s2 link in place
                    "fw:eth1 s2:Ethernet0/1",
                ],
            },
            "verify": {
                "booted": ["fw", "hub"],
                "addresses": {"fw": ["198.51.100.20"]},
                "probes": [
                    {"name": "s2 route", "node": "s2", "command": "show ip route", "expect": "198.51.100"},
                    {"name": "fw up", "node": "fw", "command": "uname", "expect": "Linux"},
                ],
            },
            "actions": {"hub-ping": {"node": "hub", "command": "ping 198.51.100.20", "description": "fw"}},
        },
    )
    use_recipe_dirs(str(tmp_path))
    r = get_recipe("child-hub")
    assert r["name"] == "child-hub" and r["extends"] == "base-hub"
    assert r["summary"] == "The hub lab plus a firewall"
    assert r["boot_minutes"] == 2 and r["address_plan"] == {"hub": "198.51.100.1"}  # inherited
    b = r["build"]
    assert b["title"] == "mcp-test-base" and b["description"] == "child lab"
    nodes = {n["label"]: n for n in b["nodes"]}
    assert [n["label"] for n in b["nodes"]] == ["hub", "s1", "s2", "fw"]
    assert nodes["hub"] == {
        "label": "hub",
        "definition": "iol-xe",
        "config": "hostname hub\ninterface Ethernet0/3\n",
        "x": 0,
        "y": 0,
        "ram": 4096,
    }
    assert b["links"] == [
        "hub:Ethernet0/1 s1:Ethernet0/0",
        "hub:Ethernet0/2 fw:eth0",
        "s1 s2",
        "fw:eth1 s2:Ethernet0/1",
    ]
    v = r["verify"]
    assert v["booted"] == ["hub", "s1", "s2", "fw"] and v["nodes"] == ["hub"]
    assert v["addresses"] == {"hub": ["198.51.100.1"], "fw": ["198.51.100.20"]}
    assert [(p["name"], p["expect"]) for p in v["probes"]] == [
        ("hub up", "IOS"),
        ("s2 route", "198.51.100"),
        ("fw up", "Linux"),
    ]
    actions = recipe_actions(r)
    assert (
        set(actions) == {"bounce-s2", "hub-ping"} and actions["hub-ping"]["command"] == "ping 198.51.100.20"
    )
    # the base is untouched by its child
    base = get_recipe("base-hub")
    assert base == base_recipe() and "extends" not in base


def test_a_child_without_build_is_its_base_under_another_name(tmp_path: Path) -> None:
    write(tmp_path, "base-hub", base_recipe())
    write(tmp_path, "renamed", {"name": "renamed", "extends": "base-hub", "summary": "same lab, other words"})
    use_recipe_dirs(str(tmp_path))
    r = get_recipe("renamed")
    assert r["build"] == base_recipe()["build"] and r["summary"] == "same lab, other words"
    assert skipped_recipe_files() == []


def test_chains_resolve_in_order(tmp_path: Path) -> None:
    write(tmp_path, "base-hub", base_recipe())
    write(
        tmp_path,
        "mid",
        {"extends": "base-hub", "build": {"nodes": [{"label": "s3", "definition": "iol-xe"}]}},
    )
    write(tmp_path, "top", {"extends": "mid", "build": {"nodes": [{"label": "s3", "ram": 2048}]}})
    use_recipe_dirs(str(tmp_path))
    top = get_recipe("top")
    assert top["name"] == "top" and top["extends"] == "mid"  # the file name is the name
    assert top["build"]["nodes"][-1] == {"label": "s3", "definition": "iol-xe", "ram": 2048}
    assert [n["label"] for n in get_recipe("mid")["build"]["nodes"]] == ["hub", "s1", "s2", "s3"]


def test_remove_nodes_drops_their_links_checks_and_actions(tmp_path: Path) -> None:
    write(tmp_path, "base-hub", base_recipe())
    write(
        tmp_path,
        "no-s2",
        {
            "extends": "base-hub",
            "build": {"remove_nodes": ["s2"], "remove_links": ["s1:Ethernet0/0 hub:Ethernet0/1"]},
        },
    )
    use_recipe_dirs(str(tmp_path))
    r = get_recipe("no-s2")
    assert [n["label"] for n in r["build"]["nodes"]] == ["hub", "s1"]
    assert r["build"]["links"] == []
    assert "remove_nodes" not in r["build"] and "remove_links" not in r["build"]
    assert r["verify"]["booted"] == ["hub", "s1"]
    assert [p["name"] for p in r["verify"]["probes"]] == ["hub up"]
    assert set(recipe_actions(r)) == {"hub-ping"}


@pytest.mark.parametrize(
    ("child", "problem"),
    [
        ({"extends": "nowhere"}, "extends names no recipe 'nowhere'"),
        ({"extends": "bad"}, "extends makes a cycle: bad -> bad"),
        ({"extends": ["base-hub"]}, "extends must be the name of another recipe"),
        (
            {"extends": "base-hub", "build": {"remove_nodes": ["s9"]}},
            "remove_nodes names node(s) the base doesn't have: s9",
        ),
        (
            {"extends": "base-hub", "build": {"remove_links": ["hub s9"]}},
            "remove_links names link(s) the base doesn't have: hub s9",
        ),
        ({"extends": "base-hub", "build": {"links": ["hub"]}}, "Link 'hub': write it as"),
    ],
)
def test_unusable_extends_is_reported_and_refused(
    tmp_path: Path, child: dict[str, Any], problem: str
) -> None:
    write(tmp_path, "base-hub", base_recipe())
    path = write(tmp_path, "bad", {"name": "bad", "build": {"title": "x"}, **child})
    use_recipe_dirs(str(tmp_path))
    assert "bad" not in recipe_names() and "base-hub" in recipe_names()
    skipped = {s["file"]: s["problem"] for s in skipped_recipe_files()}
    assert skipped[str(path)].startswith(problem)
    with pytest.raises(InvalidRequest, match="can't be used"):
        get_recipe("bad")


def test_cycles_and_broken_bases(tmp_path: Path) -> None:
    write(tmp_path, "a", {"extends": "b"})
    write(tmp_path, "b", {"extends": "a"})
    write(tmp_path, "c", {"extends": "a"})
    use_recipe_dirs(str(tmp_path))
    skipped = {Path(s["file"]).stem: s["problem"] for s in skipped_recipe_files()}
    assert skipped["a"] == "extends makes a cycle: a -> b -> a"
    assert skipped["b"] == "extends makes a cycle: b -> a -> b"
    assert skipped["c"] == "extends makes a cycle: c -> a -> b -> a"
    assert not {"a", "b", "c"} & set(recipe_names())


def test_a_packaged_recipe_extends_only_packaged_ones(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write(tmp_path, "base-hub", base_recipe())
    use_recipe_dirs(str(tmp_path))
    packaged = dict(recipes._packaged())
    monkeypatch.setattr(recipes, "_packaged", lambda: {**packaged, "pkg-child": {"extends": "base-hub"}})
    with pytest.raises(InvalidRequest, match="a packaged recipe extends only packaged ones"):
        get_recipe("pkg-child")
    assert {
        "file": "package: pkg-child",
        "problem": recipes._resolved()[1]["pkg-child"],
    } in skipped_recipe_files()


def test_an_extra_recipe_can_extend_a_packaged_one(tmp_path: Path) -> None:
    write(
        tmp_path,
        "ftd-fmc-plus",
        {
            "extends": "ftd-fmc",
            "build": {"title": "mcp-test-ftd-plus", "nodes": [{"label": "h1", "definition": "alpine"}]},
        },
    )
    use_recipe_dirs(str(tmp_path))
    r = get_recipe("ftd-fmc-plus")
    base = get_recipe("ftd-fmc")
    assert r["build"]["nodes"] == [*base["build"]["nodes"], {"label": "h1", "definition": "alpine"}]
    assert r["build"]["title"] == "mcp-test-ftd-plus" and r["verify"] == base["verify"]


def test_every_packaged_recipe_resolves() -> None:
    assert recipes._resolved()[1] == {}
    assert skipped_recipe_files() == []


def test_cat_sdwan_secure_extends_the_fabric_and_builds_the_same_lab_as_before() -> None:
    """The rewrite of cat-sdwan-secure as `extends: cat-sdwan-fabric` (L40) resolves to exactly the recipe
    it was before (the full copy is the fixture). If cat-sdwan-fabric changes on purpose, secure changes
    with it: refresh the fixture from get_recipe('cat-sdwan-secure') then."""
    raw = yaml.safe_load((recipes.RECIPE_DIR / "cat-sdwan-secure.yaml").read_text())
    assert raw["extends"] == "cat-sdwan-fabric"
    assert len(raw["build"]["nodes"]) < len(get_recipe("cat-sdwan-secure")["build"]["nodes"])  # no copy
    before = yaml.safe_load((FIXTURES / "cat-sdwan-secure-before-extends.yaml").read_text())
    after = get_recipe("cat-sdwan-secure")
    assert after["extends"] == "cat-sdwan-fabric"
    assert {k: v for k, v in after.items() if k != "extends"} == before


async def test_list_recipes_shows_the_base(api: respx.MockRouter, tmp_path: Path) -> None:
    write(tmp_path, "base-hub", base_recipe())
    write(tmp_path, "child-hub", {"extends": "base-hub", "build": {"title": "mcp-test-child"}})
    write(tmp_path, "loop", {"extends": "loop"})
    srv = create_server(make_settings(recipe_dirs=str(tmp_path)))
    rows = await call_tool(srv, "cml_list_recipes", {"response_format": "json"})
    by = {r["name"]: r for r in rows["results"]}
    assert by["child-hub"]["extends"] == "base-hub" and by["child-hub"]["lab"] == "mcp-test-child"
    assert by["cat-sdwan-secure"]["extends"] == "cat-sdwan-fabric" and "extends" not in by["base-hub"]
    assert rows["skipped"] == [f"{tmp_path / 'loop.yaml'}: extends makes a cycle: loop -> loop"]
    detail = await call_tool(srv, "cml_list_recipes", {"recipe": "child-hub"})
    assert detail["extends"] == "base-hub" and [n["label"] for n in detail["nodes"]] == ["hub", "s1", "s2"]
    assert detail["credentials"]["references"] == ["LAB_CLI_PASSWORD"] and "Fake-Cli-Pw9" not in json.dumps(
        detail
    )
