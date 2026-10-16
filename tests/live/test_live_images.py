"""L19 live: upload a real disk image, create an image definition, boot a node from it, clean up.

Needs CML_IMAGE_DIR, CML_LIVE_IMAGE_FILE (a file in it) and CML_LIVE_IMAGE_NODE_DEFINITION (e.g. cat8000v);
skipped otherwise. Uses the admin account in .env (image upload is admin-only in CML).
"""

import os
import time

import pytest
from fastmcp import Client

from cml_mcp._core.testing import call_tool
from cml_mcp.client import CmlApp
from cml_mcp.config import Settings
from cml_mcp.server import create_server

from .labkit import _delete, confirm_call

pytestmark = pytest.mark.live
IMAGE_ID = "mcp-test-upload"
LAB = "mcp-test-live-image"


def _settings(settings: Settings) -> Settings:
    image_dir = os.environ.get("CML_IMAGE_DIR") or settings.image_dir
    if not image_dir or not os.environ.get("CML_LIVE_IMAGE_FILE"):
        pytest.skip("CML_IMAGE_DIR / CML_LIVE_IMAGE_FILE not set")
    return settings.model_copy(
        update={"image_dir": image_dir, "mcp_enable_writes": True, "mcp_enable_dangerous": True}
    )


async def _cleanup(c: Client, settings: Settings, name: str) -> None:
    app = CmlApp(settings)
    try:
        ids = [lab["id"] for lab in await app.list_labs() if lab.get("lab_title") == LAB]
    finally:
        await app.aclose()
    for lab_id in ids:
        await _delete(settings, lab_id)
    files = (await c.call_tool("cml_get_image_files", {})).structured_content or {}
    defs = await call_tool(create_server(settings), "cml_list_image_definitions", {"response_format": "json"})
    if any(d.get("id") == IMAGE_ID for d in defs.get("results", [])):
        await confirm_call(c, "cml_delete_image", {"image_definition": IMAGE_ID})
    files = (await c.call_tool("cml_get_image_files", {})).structured_content or {}
    if name in (files.get("drop_folder") or []):
        await confirm_call(c, "cml_delete_image", {"drop_file": name})


async def test_upload_define_boot_delete(settings: Settings) -> None:
    s = _settings(settings)
    file = os.environ["CML_LIVE_IMAGE_FILE"]
    node_def = os.environ.get("CML_LIVE_IMAGE_NODE_DEFINITION", "cat8000v")
    name = "mcp-test-" + os.path.basename(file)
    async with Client(create_server(s)) as c:
        await _cleanup(c, s, name)
        try:
            listed = (await c.call_tool("cml_get_image_files", {})).structured_content
            assert any(f["file"] == file for f in listed["files"]), listed
            # wrong checksum: blocked, nothing sent
            bad = (
                await c.call_tool("cml_upload_image", {"file": file, "name": name, "sha256": "0" * 64})
            ).structured_content
            assert bad["status"] == "blocked" and "SHA-256 mismatch" in bad["blockers"][0]
            t0 = time.monotonic()
            up = await confirm_call(c, "cml_upload_image", {"file": file, "name": name})
            print(f"uploaded {up['size_bytes'] / 2**20:.0f} MB in {time.monotonic() - t0:.0f}s")
            assert up["in_drop_folder"] is True and len(up["sha256"]) == 64
            # the same name again: blocked
            again = (await c.call_tool("cml_upload_image", {"file": file, "name": name})).structured_content
            assert (
                again["status"] == "blocked"
                and "already in the controller's drop folder" in again["blockers"][0]
            )

            await confirm_call(
                c,
                "cml_create_image_definition",
                {"id": IMAGE_ID, "node_definition": node_def, "disk_image": name, "label": "mcp test upload"},
            )
            built = await confirm_call(
                c,
                "cml_build_lab",
                {
                    "title": LAB,
                    "nodes": [
                        {
                            "label": "r1",
                            "definition": node_def,
                            "image": IMAGE_ID,
                            "config": "hostname r1\nend\n",
                        }
                    ],
                    "start": True,
                    "wait": True,
                    "timeout": 1200,
                },
            )
            assert built["convergence"]["converged"] is True, built
            node = await call_tool(create_server(s), "cml_get_node", {"lab": LAB, "node": "r1"})
            assert node.get("image_definition") == IMAGE_ID, node
            # in use: the image definition can't be deleted
            used = (await c.call_tool("cml_delete_image", {"image_definition": IMAGE_ID})).structured_content
            assert used["status"] == "blocked" and "Nodes use" in used["blockers"][0]
        finally:
            await _cleanup(c, s, name)
        files = (await c.call_tool("cml_get_image_files", {})).structured_content or {}
        assert name not in (files.get("drop_folder") or [])
