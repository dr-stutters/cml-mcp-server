"""Image upload and image definitions (L19): list local image files, upload one (dangerous, admin), create and
delete image definitions."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import re
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, get_client, get_settings

from cml_mcp.client import CmlApp
from cml_mcp.images import (
    check_name,
    disk_free,
    drop_folder,
    extension,
    file_identity,
    list_image_files,
    resolve_image_file,
    sha256_of,
    upload,
)
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import shaped

DEF_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


async def _image_definitions(app: CmlApp) -> list[dict[str, Any]]:
    data = await app.api.get("/image_definitions")
    return data if isinstance(data, list) else []


async def _nodes_using(app: CmlApp, image_id: str) -> list[str]:
    """'lab/node' for every node (in labs this account can see) pinned to the image definition."""
    out = []
    for lab in await app.list_labs():
        for n in await app.list_nodes(str(lab["id"])):
            if n.get("image_definition") == image_id:
                out.append(f"{lab.get('lab_title')}/{n.get('label')}")
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List image files")
    async def cml_get_image_files(ctx: Context) -> ToolResult:
        """Disk images available for upload (files in CML_IMAGE_DIR on the server host, with sizes) and the
        controller's drop folder (uploaded files not yet used by an image definition). Upload one with
        cml_upload_image, then make it usable with cml_create_image_definition."""
        app: CmlApp = get_client(ctx)
        settings = get_settings(ctx)
        return shaped(
            {
                "image_dir": settings.image_dir or "not set (CML_IMAGE_DIR): uploads are off",
                "files": list_image_files(settings.image_dir),
                "drop_folder": await drop_folder(app),
            }
        )

    @reg.dangerous(title="Upload a disk image", idempotent=False, task=True)
    async def cml_upload_image(
        ctx: Context,
        file: Annotated[
            str,
            Field(
                min_length=1,
                max_length=512,
                description="File name inside CML_IMAGE_DIR (see cml_get_image_files)",
            ),
        ],
        name: Annotated[
            str | None,
            Field(description="Name on the controller (default: the file's name); same extension, no path"),
        ] = None,
        sha256: Annotated[
            str | None,
            Field(
                pattern=r"^[0-9a-fA-F]{64}$",
                description="Expected SHA-256 of the file (e.g. from cisco.com); refused on mismatch",
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Upload a disk image (qcow2, iso, tar, ...) from CML_IMAGE_DIR on the server host to the
        controller's drop folder. The file is streamed from disk (never through MCP) and checked first
        (inside CML_IMAGE_DIR, extension, SHA-256, free disk on the controller, name not already in the
        drop folder). Needs a CML admin account. Large images take minutes. Then call
        cml_create_image_definition to use it."""
        app: CmlApp = get_client(ctx)
        path = resolve_image_file(get_settings(ctx).image_dir, file)
        target = name or Path(file).name
        check_name(target)
        if extension(target) != extension(path.name):
            raise InvalidRequest("`name` must keep the file's extension")
        identity = file_identity(path)
        size = identity[2]
        digest = await sha256_of(path)
        blockers: list[str] = []
        if sha256 and sha256.lower() != digest:
            blockers.append(f"SHA-256 mismatch: the file is {digest}, expected {sha256.lower()}")
        existing = await drop_folder(app)
        if target in existing:
            blockers.append(f"{target!r} is already in the controller's drop folder (cml_get_image_files)")
        free = await disk_free(app)
        if free is not None and free < size * 2:
            blockers.append(
                f"Controller disk has {free / 2**30:.1f} GB free; the {size / 2**30:.1f} GB image "
                "needs about twice that"
            )
        plan = Plan(
            f"Upload {path.name} ({size / 2**20:.0f} MB) to the CML drop folder as {target!r}",
            details={
                "file": file,
                "name": target,
                "size_bytes": size,
                "sha256": digest,
                "controller_disk_free_gb": round(free / 2**30, 1) if free is not None else None,
            },
            fingerprint=[*identity, digest],
            blockers=blockers,
            side_effects=["Uses controller disk space until the file is deleted (cml_delete_image)"],
            blast_radius=1,
        )

        async def apply() -> Any:
            # re-check containment and identity (no symlink swap since the preview), then stream from one fd
            again = resolve_image_file(get_settings(ctx).image_dir, file)
            if again != path:
                raise InvalidRequest("The image file changed since the preview; preview again")
            response = await upload(app, path, target, identity)
            listed = target in await drop_folder(app)
            return {
                "uploaded": target,
                "size_bytes": size,
                "sha256": digest,
                "in_drop_folder": listed,
                "response": response,
                "next": "cml_create_image_definition(id=..., node_definition=..., disk_image="
                + repr(target)
                + ")",
            }

        return await preview_or_apply(
            ctx,
            tool="cml_upload_image",
            args={"file": file, "name": name, "sha256": sha256},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Create an image definition")
    async def cml_create_image_definition(
        ctx: Context,
        id: Annotated[
            str,
            Field(pattern=DEF_ID.pattern, description="New image definition id, e.g. 'cat8000v-26-01-01'"),
        ],
        node_definition: Annotated[
            str, Field(min_length=1, description="Node definition it belongs to, e.g. 'cat8000v'")
        ],
        disk_image: Annotated[
            str, Field(min_length=1, description="File in the drop folder (cml_get_image_files)")
        ],
        label: Annotated[
            str | None, Field(max_length=64, description="Display name (default: the id)")
        ] = None,
        description: Annotated[
            str | None, Field(max_length=4096, description="Description shown in CML")
        ] = None,
        ram: Annotated[int | None, Field(ge=64, le=1048576, description="RAM override (MB)")] = None,
        cpus: Annotated[int | None, Field(ge=1, le=128, description="vCPU override")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an uploaded disk image usable: create an image definition for a node definition from a file
        in the controller's drop folder (CML moves the file into the image library). Nodes then pick it with
        `image` in cml_build_lab / cml_add_node. Needs a CML admin account."""
        app: CmlApp = get_client(ctx)
        blockers: list[str] = []
        try:
            await app.api.get(f"/node_definitions/{quote(node_definition, safe='')}")
        except NotFound:
            blockers.append(f"No node definition {node_definition!r} (cml_list_node_definitions)")
        if any(i.get("id") == id for i in await _image_definitions(app)):
            blockers.append(f"Image definition {id!r} already exists")
        if disk_image not in await drop_folder(app):
            blockers.append(f"{disk_image!r} is not in the drop folder; upload it first (cml_upload_image)")
        body: dict[str, Any] = {
            "id": id,
            "node_definition_id": node_definition,
            "label": label or id,
            "disk_image": disk_image,
            "description": description or f"Uploaded by cml-mcp-server ({disk_image})",
            **({"ram": ram} if ram else {}),
            **({"cpus": cpus} if cpus else {}),
        }
        plan = Plan(
            f"Create image definition {id!r} for {node_definition!r} from {disk_image!r}",
            details=body,
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            await app.api.post("/image_definitions", body)
            return {"created": id, "node_definition": node_definition, "disk_image": disk_image}

        return await preview_or_apply(
            ctx,
            tool="cml_create_image_definition",
            args={
                "id": id,
                "node_definition": node_definition,
                "disk_image": disk_image,
                "label": label,
                "description": description,
                "ram": ram,
                "cpus": cpus,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete an image")
    async def cml_delete_image(
        ctx: Context,
        image_definition: Annotated[str | None, Field(description="Image definition id to delete")] = None,
        drop_file: Annotated[
            str | None, Field(description="File to delete from the controller's drop folder")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an image definition (refused while a node uses it, or when it's a read-only reference
        platform image) and/or a file in the controller's drop folder. Needs a CML admin account."""
        if not image_definition and not drop_file:
            raise InvalidRequest("Give image_definition and/or drop_file")
        app: CmlApp = get_client(ctx)
        blockers: list[str] = []
        details: dict[str, Any] = {}
        if image_definition:
            match = [i for i in await _image_definitions(app) if i.get("id") == image_definition]
            if not match:
                blockers.append(f"No image definition {image_definition!r}")
            else:
                details["image_definition"] = {
                    k: match[0].get(k) for k in ("id", "node_definition_id", "disk_image", "read_only")
                }
                if match[0].get("read_only"):
                    blockers.append(f"{image_definition!r} is a read-only reference platform image")
                if users := await _nodes_using(app, image_definition):
                    blockers.append(f"Nodes use {image_definition!r}: {', '.join(users[:10])}")
        if drop_file:
            details["drop_file"] = drop_file
            if drop_file not in await drop_folder(app):
                blockers.append(f"{drop_file!r} is not in the drop folder")
        plan = Plan(
            "Delete "
            + " and ".join(
                x
                for x in (
                    f"image definition {image_definition!r}" if image_definition else "",
                    f"drop-folder file {drop_file!r}" if drop_file else "",
                )
                if x
            ),
            details=details,
            blockers=blockers,
            side_effects=["Irreversible: the image has to be uploaded again"],
            blast_radius=1,
        )

        async def apply() -> Any:
            out: dict[str, Any] = {}
            if image_definition:
                await app.api.delete(f"/image_definitions/{quote(image_definition, safe='')}")
                out["deleted_image_definition"] = image_definition
            if drop_file:
                await app.api.delete(f"/images/manage/{quote(drop_file, safe='')}")
                out["deleted_drop_file"] = drop_file
            out["drop_folder"] = await drop_folder(app)
            return out

        return await preview_or_apply(
            ctx,
            tool="cml_delete_image",
            args={"image_definition": image_definition, "drop_file": drop_file},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
