"""#67: a superset recipe verifies a lab built from its base, and cml_build_recipe(extend=true) grows that lab
in place (only the missing nodes, links and notes; existing nodes never change).

The lab is the recorded 'mcp-test-probe' fixture (r1 and r2, iol-xe, linked Ethernet0/0<->Ethernet0/0)."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.recipes import (
    base_relation,
    read_recipe_marker,
    recipe_marker,
    set_recipe_marker,
    use_recipe_dirs,
)
from cml_mcp.server import create_server

from .conftest import LAB, LID, R2, fixture, make_settings

TITLE = LAB["lab_title"]
R3 = "33333333-3333-4333-8333-333333333333"


def base_recipe() -> dict[str, Any]:
    return {
        "name": "probe-base",
        "summary": "Two IOL routers",
        "address_plan": {"r1": "192.0.2.1", "r2": "192.0.2.2"},
        "build": {
            "title": TITLE,
            "nodes": [
                {"label": "r1", "definition": "iol-xe", "config": "hostname r1\n", "x": 0, "y": 0},
                {"label": "r2", "definition": "iol-xe", "config": "hostname r2\n", "x": 200, "y": 0},
            ],
            "links": ["r1 r2"],
        },
    }


def plus_recipe(*, extends: bool = True, **changes: Any) -> dict[str, Any]:
    """probe-base plus r3 behind r2 (a superset for the same lab)."""
    r = base_recipe()
    r["name"] = "probe-plus"
    r["summary"] = "Two IOL routers plus r3 behind r2"
    if extends:
        r["extends"] = "probe-base"
    r["build"]["nodes"].append(
        {
            "label": "r3",
            "definition": "iol-xe",
            "config": "hostname r3\ninterface Ethernet0/0\n ip address 192.0.2.3 255.255.255.0\n",
            "x": 400,
            "y": 0,
        }
    )
    r["build"]["links"].append("r2 r3")
    r["build"].update(changes)
    return r


@pytest.fixture
def recipe_dir(tmp_path: Path) -> Iterator[Path]:
    for r in (base_recipe(), plus_recipe()):
        (tmp_path / f"{r['name']}.yaml").write_text(yaml.safe_dump(r, sort_keys=False))
    use_recipe_dirs(str(tmp_path))
    yield tmp_path
    use_recipe_dirs(None)


def write_recipe(directory: Path, r: dict[str, Any]) -> None:
    (directory / f"{r['name']}.yaml").write_text(yaml.safe_dump(r, sort_keys=False))


def lab_notes(monkeypatch: pytest.MonkeyPatch, notes: str) -> None:
    from cml_mcp.client import CmlApp

    real = CmlApp.list_labs

    async def with_notes(self: CmlApp) -> list[dict[str, Any]]:
        return [{**lab, "lab_notes": notes} for lab in await real(self)]

    monkeypatch.setattr(CmlApp, "list_labs", with_notes)


def server(recipe_dir: Path) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, recipe_dirs=str(recipe_dir)))


class FakeLab:
    """Mutable interfaces/links/annotations behind the lab_api fixture, recording every write."""

    def __init__(self, api: respx.MockRouter) -> None:
        self.interfaces: list[dict[str, Any]] = fixture("interfaces.json")
        self.posts: list[tuple[str, Any]] = []
        self.notes: list[str] = []
        lab = f"/labs/{LID}"
        api.get(f"{lab}/interfaces").mock(side_effect=lambda r: httpx.Response(200, json=self.interfaces))
        api.get("/nodes").mock(return_value=httpx.Response(200, json=[]))  # licence use
        api.get(f"{lab}/annotations").mock(return_value=httpx.Response(200, json=[]))
        api.post(f"{lab}/nodes").mock(side_effect=self.add_node)
        api.post(f"{lab}/interfaces").mock(side_effect=self.add_interface)
        api.post(f"{lab}/links").mock(side_effect=self.record("link"))
        api.post(f"{lab}/annotations").mock(side_effect=self.record("annotation"))
        api.patch(lab).mock(side_effect=self.patch_lab)
        api.put(f"{lab}/nodes/{R3}/state/start").mock(side_effect=self.record("start"))

    def record(self, kind: str) -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            self.posts.append((kind, json.loads(request.content or b"null")))
            return httpx.Response(200, json={"id": f"{kind}-{len(self.posts)}"})

        return handler

    def add_node(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.posts.append(("node", body))
        assert request.url.params.get("populate_interfaces") == "true"
        names = ["Loopback0", "Ethernet0/0", "Ethernet0/1", "Ethernet0/2", "Ethernet0/3"]
        for slot, name in enumerate(names, start=-1):
            self.interfaces.append(
                {
                    "id": f"3333{slot + 1:04d}-0000-4000-8000-000000000000",
                    "node": R3,
                    "label": name,
                    "slot": None if slot < 0 else slot,
                    "type": "loopback" if slot < 0 else "physical",
                    "is_connected": False,
                }
            )
        return httpx.Response(200, json={"id": R3})

    def add_interface(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.posts.append(("interface", body))
        return httpx.Response(200, json={"id": "new-iface", "slot": body["slot"], "node": body["node"]})

    def patch_lab(self, request: httpx.Request) -> httpx.Response:
        self.notes.append(json.loads(request.content)["notes"])
        return httpx.Response(200, json=LAB)


# --- recipe relations -----------------------------------------------------------------------------------


def test_base_relation(recipe_dir: Path) -> None:
    assert base_relation("probe-plus", "probe-plus") == "same"
    assert base_relation("probe-plus", "probe-base") == "extends"
    assert base_relation("probe-base", "probe-plus") is None  # the smaller recipe can't verify the bigger lab
    assert base_relation("probe-plus", "no-such-recipe") is None
    write_recipe(recipe_dir, plus_recipe(extends=False))
    assert base_relation("probe-plus", "probe-base") == "subset"
    assert base_relation("probe-plus", "ise-access") is None


def test_packaged_superset_recognises_its_base() -> None:
    """The case #67 was filed for: cat-sdwan-secure on a lab built from cat-sdwan-fabric."""
    assert base_relation("cat-sdwan-secure", "cat-sdwan-fabric") == "extends"  # now named under extends:
    assert base_relation("cat-sdwan-fabric", "cat-sdwan-secure") is None


def test_set_recipe_marker_replaces_or_appends() -> None:
    old = "free text\n" + recipe_marker("probe-base", None) + "\nmore"
    new = set_recipe_marker(old, "probe-plus", {"192.0.2.1": "192.0.2.9"})
    assert new.startswith("free text\n") and new.endswith("\nmore")
    assert read_recipe_marker(new) == {"recipe": "probe-plus", "substitute": {"192.0.2.1": "192.0.2.9"}}
    assert read_recipe_marker(set_recipe_marker("hand notes", "probe-plus", None))["recipe"] == "probe-plus"
    assert read_recipe_marker(set_recipe_marker(None, "probe-plus", None))["recipe"] == "probe-plus"


# --- verify on a base-built lab --------------------------------------------------------------------------


async def test_verify_superset_on_a_base_built_lab(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    data = await call_tool(server(recipe_dir), "cml_verify_recipe", {"recipe": "probe-plus"})
    assert data["built_from"]["recipe"] == "probe-base" and data["built_from"]["relation"] == "extends"
    assert "extend=true" in data["built_from"]["note"]
    by = {c["check"]: c for c in data["checks"]}
    assert by["r1 booted"]["ok"] and by["r2 booted"]["ok"]
    assert not by["r3 booted"]["ok"] and data["passed"] is False  # not extended yet


async def test_verify_still_refuses_an_unrelated_recipe(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_notes(monkeypatch, recipe_marker("probe-plus", None))
    data = await call_tool(server(recipe_dir), "cml_verify_recipe", {"recipe": "probe-base"})
    assert data["passed"] is False and "built from 'probe-plus'" in str(data["checks"])
    assert "built_from" not in data


# --- build extend: preview, confirm, conflicts -----------------------------------------------------------


async def test_extend_preview_lists_only_the_additions(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    fake = FakeLab(lab_api)
    preview = await call_tool(
        server(recipe_dir), "cml_build_recipe", {"recipe": "probe-plus", "extend": True, "start": False}
    )
    d = preview["preview"]
    assert preview["confirm"] and not preview.get("blockers"), preview
    assert d["add_nodes"] == {"r3": "iol-xe"}
    assert d["add_links"] == ["r2:Ethernet0/1<->r3:Ethernet0/0"]
    assert d["unchanged"] == {"nodes": 2, "links": 1}
    assert d["built_from"] == {"recipe": "probe-base", "relation": "extends"}
    assert d["marker"] == {"recipe": "probe-plus", "substitute": {}}
    assert d["annotations"]["add"] >= 1 and "new_interfaces" not in d
    assert not fake.posts  # a preview writes nothing


async def test_extend_confirm_adds_node_link_notes_and_marker(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_notes(monkeypatch, "owner notes\n" + recipe_marker("probe-base", None))
    fake = FakeLab(lab_api)
    srv = server(recipe_dir)
    args = {"recipe": "probe-plus", "extend": True, "start": True}
    lab_api.get(f"/labs/{LID}/nodes/{R3}").mock(return_value=httpx.Response(200, json={"state": "STOPPED"}))
    async with Client(srv) as c:
        preview = (await c.call_tool("cml_build_recipe", args)).structured_content
        assert preview and preview["confirm"], preview
        done = (
            await c.call_tool("cml_build_recipe", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert done and done["status"] == "applied", done
    done = done["result"]
    assert done["added_nodes"] == {"r3": R3} and done["added_links"] == ["r2:Ethernet0/1<->r3:Ethernet0/0"]
    assert done["started"] == ["r3"] and done["marker"] == "probe-plus"
    kinds = [k for k, _ in fake.posts]
    assert kinds.count("node") == 1 and kinds.count("link") == 1 and "start" in kinds
    assert "interface" not in kinds  # r3's populated interfaces and r2's free Ethernet0/1 suffice
    node = next(b for k, b in fake.posts if k == "node")
    assert node["label"] == "r3" and node["node_definition"] == "iol-xe" and node["x"] == 400
    assert "hostname r3" in json.dumps(node["configuration"])
    link = next(b for k, b in fake.posts if k == "link")
    r2_e01 = next(i["id"] for i in fake.interfaces if i["node"] == R2 and i["label"] == "Ethernet0/1")
    r3_e00 = next(i["id"] for i in fake.interfaces if i["node"] == R3 and i["label"] == "Ethernet0/0")
    assert link == {"src_int": r2_e01, "dst_int": r3_e00}
    notes = [b["text_content"] for k, b in fake.posts if k == "annotation"]
    assert any("probe-plus" in n for n in notes) and any("192.0.2.3" in n for n in notes)
    assert fake.notes and fake.notes[-1].startswith("owner notes\n")
    assert read_recipe_marker(fake.notes[-1]) == {"recipe": "probe-plus", "substitute": {}}


async def test_extend_refuses_a_node_of_another_definition(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clash = plus_recipe(extends=False)
    clash["build"]["nodes"][1]["definition"] = "ioll2-xe"  # r2 is iol-xe in the lab
    write_recipe(recipe_dir, clash)
    lab_notes(monkeypatch, "")
    fake = FakeLab(lab_api)
    preview = await call_tool(
        server(recipe_dir), "cml_build_recipe", {"recipe": "probe-plus", "extend": True, "start": False}
    )
    assert "confirm" not in preview or not preview.get("confirm")
    assert any("'r2' is a iol-xe in the lab but a ioll2-xe" in b for b in preview["blockers"])
    assert not fake.posts


async def test_extend_refuses_a_link_end_already_in_use(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = plus_recipe(links=["r1:Ethernet0/1 r2:Ethernet0/1", "r1:Ethernet0/0 r3"])  # r1 Ethernet0/0 goes to r2
    write_recipe(recipe_dir, r)
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    FakeLab(lab_api)
    preview = await call_tool(
        server(recipe_dir), "cml_build_recipe", {"recipe": "probe-plus", "extend": True, "start": False}
    )
    assert any("r1:Ethernet0/0 is already connected to r2:Ethernet0/0" in b for b in preview["blockers"])


async def test_extend_refuses_a_lab_of_an_unrelated_recipe_and_other_substitutions(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_notes(monkeypatch, recipe_marker("ise-access", {"192.0.2.1": "192.0.2.9"}))
    FakeLab(lab_api)
    preview = await call_tool(
        server(recipe_dir), "cml_build_recipe", {"recipe": "probe-plus", "extend": True, "start": False}
    )
    text = " ".join(preview["blockers"])
    assert "built from recipe 'ise-access'" in text and "pass the same `substitute`" in text


async def test_extend_needs_the_lab_and_has_nothing_to_do_when_complete(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    FakeLab(lab_api)
    srv = server(recipe_dir)
    async with Client(srv) as c:
        res = await c.call_tool(
            "cml_build_recipe",
            {"recipe": "probe-plus", "title": "mcp-no-such-lab", "extend": True},
            raise_on_error=False,
        )
    assert res.is_error and "without extend" in res.content[0].text  # type: ignore[union-attr]
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    done = await call_tool(srv, "cml_build_recipe", {"recipe": "probe-base", "extend": True, "start": False})
    assert done["preview"]["add_nodes"] == {} and done["preview"]["add_links"] == []
    # the base lab has none of the recipe's notes yet (the fixture has no annotations): only notes are added
    assert done["preview"]["annotations"]["add"] >= 1 and not done.get("blockers")


async def test_extend_needs_a_wipe_for_a_new_interface_on_a_running_node(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = plus_recipe(links=["r1 r2", "r2:Ethernet1/0 r3"])  # the fixture's r2 has Ethernet0/0-0/3 only
    write_recipe(recipe_dir, r)
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    FakeLab(lab_api)
    preview = await call_tool(
        server(recipe_dir), "cml_build_recipe", {"recipe": "probe-plus", "extend": True, "start": False}
    )
    assert any(
        "r2 has no Ethernet1/0 and is BOOTED" in b and "cml_wipe_node" in b for b in preview["blockers"]
    )


async def test_extend_fills_secrets_only_in_what_goes_to_cml(
    lab_api: respx.MockRouter,
    recipe_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_lab_secrets: dict[str, str],
) -> None:
    r = plus_recipe()
    r["build"]["nodes"][2]["config"] += "username admin privilege 15 secret ${LAB_CLI_PASSWORD}\n"
    write_recipe(recipe_dir, r)
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    fake = FakeLab(lab_api)
    args = {"recipe": "probe-plus", "extend": True, "start": False}
    async with Client(server(recipe_dir)) as c:
        preview = (await c.call_tool("cml_build_recipe", args)).structured_content
        assert preview and preview["confirm"], preview
        done = (
            await c.call_tool("cml_build_recipe", {**args, "confirm": preview["confirm"]})
        ).structured_content
    secret = fake_lab_secrets["LAB_CLI_PASSWORD"]
    assert secret not in json.dumps(preview) + json.dumps(done)
    node = next(b for k, b in fake.posts if k == "node")
    assert secret in json.dumps(node["configuration"])
    assert secret not in json.dumps([b for k, b in fake.posts if k == "annotation"]) + "".join(fake.notes)


async def test_extend_refuses_a_protected_lab(
    lab_api: respx.MockRouter, recipe_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The recipe tool has no `lab` argument, so the extend flow checks CML_PROTECTED_LABS itself."""
    lab_notes(monkeypatch, recipe_marker("probe-base", None))
    fake = FakeLab(lab_api)
    srv = create_server(
        make_settings(mcp_enable_writes=True, recipe_dirs=str(recipe_dir), protected_labs="mcp-test-*")
    )
    preview = await call_tool(
        srv, "cml_build_recipe", {"recipe": "probe-plus", "extend": True, "start": False}
    )
    assert not preview.get("confirm")
    assert any("CML_PROTECTED_LABS" in b for b in preview["blockers"])
    assert not fake.posts
