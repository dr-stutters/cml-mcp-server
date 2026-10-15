"""L19: image upload (allow-listed directory, streamed multipart), image definitions."""

import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from stutters_mcp_core import InvalidRequest

from cml_mcp.images import check_name, list_image_files, multipart, resolve_image_file
from cml_mcp.server import create_server

from .conftest import make_settings

RWD = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}


@pytest.fixture
def image_dir(tmp_path: Path) -> Path:
    d = tmp_path / "images"
    d.mkdir()
    (d / "tiny.qcow2").write_bytes(b"QFI\xfb" + b"x" * 3000)
    (d / "notes.txt").write_text("not an image")
    (tmp_path / "outside.qcow2").write_bytes(b"secret")
    (d / "escape.qcow2").symlink_to(tmp_path / "outside.qcow2")
    return d


def test_resolve_refuses_outside_and_symlink_escape(image_dir: Path) -> None:
    assert resolve_image_file(str(image_dir), "tiny.qcow2").name == "tiny.qcow2"
    for bad in ("../outside.qcow2", "escape.qcow2", "/etc/passwd", "missing.qcow2"):
        with pytest.raises(InvalidRequest):
            resolve_image_file(str(image_dir), bad)
    with pytest.raises(InvalidRequest, match="CML_IMAGE_DIR"):
        resolve_image_file(None, "tiny.qcow2")


def test_list_only_images_inside(image_dir: Path) -> None:
    assert [f["file"] for f in list_image_files(str(image_dir))] == ["tiny.qcow2"]


@pytest.mark.parametrize("name", ["a/b.qcow2", "x.exe", "../x.qcow2", "", "has space.iso"])
def test_bad_names(name: str) -> None:
    with pytest.raises(InvalidRequest):
        check_name(name)


async def test_multipart_body_is_exact(image_dir: Path) -> None:
    path = image_dir / "tiny.qcow2"
    ctype, length, body = multipart(path, "tiny.qcow2")
    data = b"".join([chunk async for chunk in body])
    assert len(data) == length
    boundary = ctype.split("boundary=")[1]
    assert data.startswith(f"--{boundary}\r\n".encode()) and data.endswith(f"\r\n--{boundary}--\r\n".encode())
    assert b'name="field0"; filename="tiny.qcow2"' in data and path.read_bytes() in data


def _cml(api: respx.MockRouter, drop: list[str]) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def upload(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["body"] = request.read()
        drop.append(request.headers["X-Original-File-Name"])
        return httpx.Response(200, json="Success")

    api.get("/list_image_definition_drop_folder").mock(
        side_effect=lambda r: httpx.Response(200, json=list(drop))
    )
    api.get("/system_stats").mock(
        return_value=httpx.Response(
            200, json={"computes": {"c": {"is_controller": True, "stats": {"disk": {"free": 100 * 2**30}}}}}
        )
    )
    api.post("/images/upload").mock(side_effect=upload)
    return seen


async def test_upload_preview_then_stream(api: respx.MockRouter, image_dir: Path) -> None:
    seen = _cml(api, [])
    s = make_settings(**RWD, image_dir=str(image_dir))
    digest = hashlib.sha256((image_dir / "tiny.qcow2").read_bytes()).hexdigest()
    async with Client(create_server(s)) as c:
        bad = (
            await c.call_tool("cml_upload_image", {"file": "tiny.qcow2", "sha256": "0" * 64})
        ).structured_content
        assert bad["status"] == "blocked" and "SHA-256 mismatch" in bad["blockers"][0]
        args = {"file": "tiny.qcow2", "name": "mcp-tiny.qcow2", "sha256": digest}
        preview = (await c.call_tool("cml_upload_image", args)).structured_content
        assert preview["status"] == "preview" and preview["preview"]["sha256"] == digest
        applied = (
            await c.call_tool("cml_upload_image", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied["result"]["in_drop_folder"] is True
    assert seen["headers"]["x-original-file-name"] == "mcp-tiny.qcow2"
    assert seen["headers"]["authorization"].startswith("Bearer ")
    assert int(seen["headers"]["content-length"]) == len(seen["body"])


async def test_upload_refuses_existing_name_and_low_disk(api: respx.MockRouter, image_dir: Path) -> None:
    _cml(api, ["tiny.qcow2"])
    s = make_settings(**RWD, image_dir=str(image_dir))
    async with Client(create_server(s)) as c:
        res = (await c.call_tool("cml_upload_image", {"file": "tiny.qcow2"})).structured_content
    assert res["status"] == "blocked" and "already in the controller's drop folder" in res["blockers"][0]


async def test_upload_is_dangerous_tier_only(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        names = {t.name for t in await c.list_tools()}
    assert "cml_upload_image" not in names and "cml_create_image_definition" in names


async def test_create_and_delete_image_definition(api: respx.MockRouter) -> None:
    api.get("/list_image_definition_drop_folder").mock(return_value=httpx.Response(200, json=["x.qcow2"]))
    api.get("/node_definitions/cat8000v").mock(return_value=httpx.Response(200, json="id: cat8000v\n"))
    defs = [{"id": "ro-img", "node_definition_id": "cat8000v", "read_only": True}]
    api.get("/image_definitions").mock(side_effect=lambda r: httpx.Response(200, json=defs))
    created = api.post("/image_definitions").mock(
        side_effect=lambda r: (
            defs.append({"id": "new-img", "node_definition_id": "cat8000v"})
            or httpx.Response(200, json={"id": "new-img"})
        )
    )
    s = make_settings(**RWD)
    async with Client(create_server(s)) as c:
        args = {"id": "new-img", "node_definition": "cat8000v", "disk_image": "x.qcow2"}
        p = (await c.call_tool("cml_create_image_definition", args)).structured_content
        assert p["status"] == "preview"
        await c.call_tool("cml_create_image_definition", {**args, "confirm": p["confirm"]})
        assert created.called
        missing = (
            await c.call_tool(
                "cml_create_image_definition", {**args, "id": "other", "disk_image": "nope.qcow2"}
            )
        ).structured_content
        assert missing["status"] == "blocked" and "not in the drop folder" in missing["blockers"][0]
        ro = (await c.call_tool("cml_delete_image", {"image_definition": "ro-img"})).structured_content
        assert ro["status"] == "blocked" and "read-only" in ro["blockers"][0]


def test_changed_file_is_refused(image_dir: Path) -> None:
    from cml_mcp.images import file_identity

    path = image_dir / "tiny.qcow2"
    ident = file_identity(path)
    path.write_bytes(b"QFI\xfb" + b"y" * 5000)  # replaced since the preview
    with pytest.raises(InvalidRequest, match="changed since the preview"):
        multipart(path, "tiny.qcow2", ident)
    with pytest.raises(InvalidRequest):
        resolve_image_file(str(image_dir), "bad\0name.qcow2")
