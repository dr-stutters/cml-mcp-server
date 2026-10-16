"""Node and image definition read tools (what can be put in a lab)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

import yaml
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import ResponseFormat, ToolRegistrar, get_client, list_result
from cml_mcp._core.http import page_of
from cml_mcp.client import CmlApp
from cml_mcp.tools.common import shaped


def definition_row(d: dict[str, Any]) -> dict[str, Any]:
    general = d.get("general") or {}
    ifaces = (d.get("device") or {}).get("interfaces") or {}
    ui = d.get("ui") or {}
    sim = d.get("sim") or {}
    physical = ifaces.get("physical") or []
    return {
        "id": d.get("id"),
        "label": ui.get("label"),
        "description": next(iter(str(general.get("description") or "").strip().splitlines()), None),
        "nature": general.get("nature"),
        "group": ui.get("group"),
        "ram_mb": sim.get("ram"),
        "cpus": sim.get("cpus"),
        "interfaces": f"{ifaces.get('default_count', len(physical))} default / {len(physical)} max",
        "images": len(d.get("image_definitions") or []),
        "config": bool(ui.get("has_configuration")),
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List node definitions")
    async def cml_list_node_definitions(
        ctx: Context,
        search: Annotated[
            str | None, Field(description="Filter: id, label or description contains (e.g. 'switch', 'xr')")
        ] = None,
        nature: Annotated[
            str | None,
            Field(description="Filter by nature: router, switch, server, firewall, host, external_connector"),
        ] = None,
        with_images_only: Annotated[
            bool, Field(description="Hide definitions that have no image installed (they can't boot)")
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The node types this CML can run (node definitions): id (use it as node_definition when adding
        nodes), label, description, nature (router/switch/server/...), default RAM/vCPUs, interface
        counts, how many images are installed, and whether it takes a day-0 config. Docker-based IOL
        (iol-xe, ioll2-xe) boots fastest."""
        app: CmlApp = get_client(ctx)
        defs: list[dict[str, Any]] = await app.api.get("/simplified_node_definitions")
        rows = []
        for d in defs:
            row = definition_row(d)
            bootable = (
                row["images"] or row["nature"] == "external_connector" or row["id"] == "unmanaged_switch"
            )
            if with_images_only and not bootable:
                continue
            if nature and row["nature"] != nature:
                continue
            if search:
                hay = " ".join(str(row[k] or "") for k in ("id", "label", "description")).lower()
                if search.lower() not in hay:
                    continue
            rows.append(row)
        rows.sort(key=lambda r: str(r["id"]))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get node definition")
    async def cml_get_node_definition(
        ctx: Context,
        definition: Annotated[
            str, Field(description="Node definition id, e.g. iol-xe (cml_list_node_definitions)")
        ],
    ) -> ToolResult:
        """One node definition in detail: interface names (loopback/physical, default and max count),
        default RAM/vCPUs, boot timeout and the console line that marks boot complete, pyATS OS,
        the day-0 configuration files and their default content, and the installed images."""
        app: CmlApp = get_client(ctx)
        raw = await app.api.get(f"/node_definitions/{definition}")
        d: dict[str, Any] = yaml.safe_load(raw) if isinstance(raw, str) else raw
        general = d.get("general") or {}
        cfg = d.get("configuration") or {}
        files = (cfg.get("provisioning") or {}).get("files") or []
        images = await app.api.get(f"/node_definitions/{definition}/image_definitions")
        return shaped(
            {
                "id": d.get("id"),
                "label": (d.get("ui") or {}).get("label"),
                "description": general.get("description"),
                "nature": general.get("nature"),
                "interfaces": (d.get("device") or {}).get("interfaces"),
                "sim": d.get("sim"),
                "boot": d.get("boot"),
                "pyats": d.get("pyats"),
                "config_generator": (cfg.get("generator") or {}).get("driver"),
                "config_files": [
                    {"name": f.get("name"), "editable": f.get("editable", True), "default": f.get("content")}
                    for f in files
                    if isinstance(f, dict)
                ],
                "images": [
                    {"id": i.get("id"), "label": i.get("label"), "ram": i.get("ram"), "cpus": i.get("cpus")}
                    for i in images or []
                ],
            }
        )

    @reg.read(title="List image definitions")
    async def cml_list_image_definitions(
        ctx: Context,
        definition: Annotated[
            str | None, Field(description="Only images for this node definition id")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Installed software images: image id (optional image_definition when adding a node; the
        newest is used when omitted), the node definition it belongs to, label/version, and any RAM or
        vCPU override."""
        app: CmlApp = get_client(ctx)
        images: list[dict[str, Any]] = await app.api.get("/image_definitions")
        rows = [
            {
                "id": i.get("id"),
                "definition": i.get("node_definition_id"),
                "label": i.get("label"),
                "description": i.get("description"),
                "ram_mb": i.get("ram"),
                "cpus": i.get("cpus"),
            }
            for i in images
            if not definition or i.get("node_definition_id") == definition
        ]
        rows.sort(key=lambda r: (str(r["definition"]), str(r["id"])))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
