"""L71: cml_archive_lab writes a restorable archive under CML_ARCHIVE_DIR; delete/wipe previews warn."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml

from cml_mcp._core import InvalidRequest
from cml_mcp.archive import archive_check, latest_archive, node_files, write_archive

from .conftest import FIXTURES, LAB, LID, R1, R2, make_settings
from .test_write_tools import RWD, preview_apply

RW = {"mcp_enable_writes": True}
NODE_PW = "Fake-Node-Pw9"


def export_with_secrets() -> str:
    """The captured export plus a pyATS password, a node-file password and a lab secret value."""
    lines = (FIXTURES / "lab_export.yaml").read_text().split("\n")
    assert lines[26].strip() == "password: null" and lines[13].strip() == "end"
    lines[26] = "      password: fake-pyats-pw"
    lines[13] = (
        "          snmp-server community fake-ro-community RO\n"
        "          username ops secret Fake-Cli-Pw9\n"
        "          end"
    )
    assert lines[59].strip() == "- name: ios_config.txt"
    lines[59] = (
        "      - name: user-data\n        content: |-\n          #cloud-config\n"
        f"          password: {NODE_PW}\n"
        "      - name: network-config\n        content: |-\n          version: 2\n"
        "      - name: ios_config.txt"
    )
    return "\n".join(lines)


@pytest.fixture
def archive_api(lab_api: respx.MockRouter) -> respx.MockRouter:
    lab_api.get(f"/labs/{LID}/download").mock(return_value=httpx.Response(200, text=export_with_secrets()))
    for nid in (R1, R2):
        lab_api.put(f"/labs/{LID}/nodes/{nid}/extract_configuration").mock(
            return_value=httpx.Response(200, json=nid)
        )
    return lab_api


async def test_archive_writes_layout_masked_and_private(
    archive_api: respx.MockRouter, tmp_path: Path
) -> None:
    preview, applied = await preview_apply(
        "cml_archive_lab", {"lab": LID, "purpose": "probe lab"}, **RW, archive_dir=str(tmp_path)
    )
    assert preview["status"] == "preview", preview
    assert preview["preview"]["extract_configs"] == ["r1", "r2"]
    assert preview["preview"]["directory"] == "mcp-test-probe-<UTC time>"
    assert preview["blast_radius"] == 2
    res = applied["result"]
    folder = Path(res["path"])
    assert folder.parent == tmp_path and folder.name.startswith("mcp-test-probe-20")
    assert archive_api.routes  # extract on both booted nodes, in order
    extracts = [c.request.url.path for c in archive_api.calls if c.request.method == "PUT"]
    assert [p.split("/")[-2] for p in extracts] == [R1, R2]
    assert sorted(p.name for p in folder.iterdir()) == [
        "README.md",
        "archive.json",
        "configs",
        "topology.yaml",
    ]
    assert sorted(p.name for p in (folder / "configs").iterdir()) == [
        "r1.txt",
        "r2--ios_config.txt",
        "r2--network-config.txt",
        "r2--user-data.txt",
    ]
    for p in [*folder.rglob("*")]:
        mode = os.stat(p).st_mode & 0o777
        assert mode == (0o700 if p.is_dir() else 0o600), p
    topo = (folder / "topology.yaml").read_text()
    assert "fake-pyats-pw" not in topo and NODE_PW not in topo and "Fake-Cli-Pw9" not in topo
    assert "'********'" in topo and "${LAB_NODE_PASSWORD}" in topo and "${LAB_CLI_PASSWORD}" in topo
    assert yaml.safe_load(topo)["nodes"][0]["label"] == "r1"  # still valid, re-importable YAML
    r1 = (folder / "configs" / "r1.txt").read_text()
    assert r1.startswith("hostname r1") and "${LAB_CLI_PASSWORD}" in r1
    assert "${LAB_NODE_PASSWORD}" in (folder / "configs" / "r2--user-data.txt").read_text()
    readme = (folder / "README.md").read_text()
    assert (
        "Purpose: probe lab" in readme
        and "cml_import_lab" in readme
        and "| r1 | iol-xe | BOOTED | extracted |" in readme
    )
    manifest = json.loads((folder / "archive.json").read_text())
    assert manifest["lab_id"] == LID and manifest["lab_modified"] == LAB["modified"]
    assert res["extracted"] == ["r1", "r2"] and "not_extracted" not in res
    assert "hostname" not in json.dumps(applied)  # paths and checksums only


async def test_archive_without_extract_changes_nothing(archive_api: respx.MockRouter, tmp_path: Path) -> None:
    preview, applied = await preview_apply(
        "cml_archive_lab", {"lab": LID, "extract": False}, **RW, archive_dir=str(tmp_path)
    )
    assert preview["preview"]["extract_configs"] == []
    assert preview["preview"]["stored_config_only"] == ["r1", "r2"]
    assert not [c for c in archive_api.calls if c.request.method == "PUT"]
    assert "stored config only" in (Path(applied["result"]["path"]) / "README.md").read_text()


async def test_archive_reports_a_failed_extract_and_keeps_going(
    archive_api: respx.MockRouter, tmp_path: Path
) -> None:
    archive_api.put(f"/labs/{LID}/nodes/{R2}/extract_configuration").mock(
        return_value=httpx.Response(500, json={"description": "console busy"})
    )
    _, applied = await preview_apply("cml_archive_lab", {"lab": LID}, **RW, archive_dir=str(tmp_path))
    res = applied["result"]
    assert res["extracted"] == ["r1"] and "r2" in res["not_extracted"]
    assert "not extracted" in (Path(res["path"]) / "README.md").read_text()


async def test_archive_needs_archive_dir(archive_api: respx.MockRouter) -> None:
    from fastmcp import Client

    from cml_mcp.server import create_server

    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool("cml_archive_lab", {"lab": LID}, raise_on_error=False)
    assert res.is_error and "CML_ARCHIVE_DIR" in res.content[0].text  # type: ignore[union-attr]


async def test_protected_lab_blocks_extract(archive_api: respx.MockRouter, tmp_path: Path) -> None:
    preview, _ = await preview_apply(
        "cml_archive_lab", {"lab": LID}, **RW, archive_dir=str(tmp_path), protected_labs="mcp-test-*"
    )
    assert preview["status"] == "blocked" and "protected" in preview["blockers"][0]


def test_never_overwrites_and_stays_inside(tmp_path: Path) -> None:
    now = datetime(2026, 10, 28, 1, 2, 3, tzinfo=UTC)
    a = write_archive(tmp_path, "lab", "id1", "x", [], "r", {"lab_id": "id1"}, now)
    b = write_archive(tmp_path, "lab", "id1", "y", [], "r", {"lab_id": "id1"}, now)
    assert a.name == "lab-20261028T010203Z" and b.name == "lab-20261028T010203Z-2"
    assert (a / "topology.yaml").read_text() == "x"
    # a title that would escape becomes one safe component
    c = write_archive(tmp_path, "../../etc", "id1", "z", [], "r", {"lab_id": "id1"}, now)
    assert c.parent == tmp_path and c.name.startswith("etc-")
    # a symlink planted where the archive goes is refused, not followed
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "evil-20261028T010203Z").symlink_to(outside)
    for n in range(2, 100):
        (tmp_path / f"evil-20261028T010203Z-{n}").symlink_to(outside)
    with pytest.raises(InvalidRequest):
        write_archive(tmp_path, "evil", "id1", "z", [], "r", {"lab_id": "id1"}, now)
    assert not list(outside.iterdir())


def test_node_files_shapes() -> None:
    assert node_files({"label": "r1", "configuration": "hostname r1"}) == [("r1.txt", "hostname r1")]
    assert node_files({"label": "r1", "configuration": None}) == []
    assert node_files({"label": "a/../b", "configuration": [{"name": "x", "content": "c"}]}) == [
        ("a_.._b.txt", "c")
    ]


# --- delete / wipe previews -------------------------------------------------------------------------


async def preview_only(name: str, args: dict[str, Any], **settings: Any) -> dict[str, Any]:
    from fastmcp import Client

    from cml_mcp.server import create_server

    async with Client(create_server(make_settings(**settings))) as c:
        res = (await c.call_tool(name, args)).structured_content
    assert res is not None
    return res


def _manifest(root: Path, name: str, lab_id: str, at: str, modified: str | None) -> None:
    d = root / name
    d.mkdir()
    (d / "archive.json").write_text(
        json.dumps({"lab_id": lab_id, "archived_at": at, "lab_modified": modified})
    )


def test_archive_check_paths(tmp_path: Path) -> None:
    lab: dict[str, Any] = {"id": "L1", "modified": "2026-10-20T10:00:00+00:00", "state": "STOPPED"}
    _, warn = archive_check(None, lab)
    assert warn and "CML_ARCHIVE_DIR is not set" in warn
    details, warn = archive_check(str(tmp_path), lab)
    assert details["latest"] is None and warn and "never been archived" in warn
    _manifest(tmp_path, "other", "L2", "2026-10-21T00:00:00+00:00", None)  # another lab's archive
    assert archive_check(str(tmp_path), lab)[1] is not None
    _manifest(tmp_path, "old", "L1", "2026-10-19T00:00:00+00:00", "2026-10-18T00:00:00+00:00")
    details, warn = archive_check(str(tmp_path), lab)
    assert warn and "older than the lab's last change" in warn and details["latest"].startswith("2026-10-19")
    _manifest(tmp_path, "new", "L1", "2026-10-21T00:00:00+00:00", lab["modified"])
    details, warn = archive_check(str(tmp_path), lab)
    assert warn is None and details["path"].endswith("new")
    assert latest_archive(tmp_path, lab)["archived_at"].startswith("2026-10-21")  # type: ignore[index]
    # the lab changed while the archive ran (extract): its recorded 'modified' still matches
    _manifest(tmp_path, "same", "L3", "2026-10-20T09:59:00+00:00", "2026-10-20T10:00:00+00:00")
    assert archive_check(str(tmp_path), {"id": "L3", "modified": "2026-10-20T10:00:00+00:00"})[1] is None
    # running: no warning, but a note that live configs may have moved on
    details, warn = archive_check(str(tmp_path), {**lab, "state": "STARTED"})
    assert warn is None and "running" in details["note"]


async def test_delete_preview_warns_without_archive(lab_api: respx.MockRouter, tmp_path: Path) -> None:
    preview = await preview_only(
        "cml_delete_lab", {"lab": LID, "force": True}, **RWD, archive_dir=str(tmp_path)
    )
    assert preview["preview"]["archive"]["latest"] is None
    assert any("never been archived" in s for s in preview["side_effects"])


async def test_wipe_preview_shows_fresh_archive(archive_api: respx.MockRouter, tmp_path: Path) -> None:
    await preview_apply("cml_archive_lab", {"lab": LID}, **RW, archive_dir=str(tmp_path))
    preview = await preview_only(
        "cml_wipe_lab", {"lab": LID, "force": True}, **RWD, archive_dir=str(tmp_path)
    )
    assert preview["preview"]["archive"]["latest"]
    assert not any("WARNING" in s for s in preview["side_effects"])


async def test_wipe_preview_warns_when_archive_is_stale(lab_api: respx.MockRouter, tmp_path: Path) -> None:
    _manifest(tmp_path, "stale", LID, "2026-10-01T00:00:00+00:00", "2026-09-30T00:00:00+00:00")
    preview = await preview_only(
        "cml_wipe_lab", {"lab": LID, "force": True}, **RWD, archive_dir=str(tmp_path)
    )
    assert any("older than the lab's last change" in s for s in preview["side_effects"])
