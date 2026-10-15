"""Sample labs shipped with (or synced into) the controller: list and load."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
)
from stutters_mcp_core.http import page_of

from cml_mcp.client import CmlApp, pick_one
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.lab_writes import known_definitions


async def _samples(app: CmlApp) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = await app.api.get("/sample/labs")
    return data


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List sample labs")
    async def cml_list_sample_labs(
        ctx: Context,
        search: Annotated[
            str | None,
            Field(description="Filter: text in the title or description, or a node type (e.g. 'asav')"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the sample labs available on the controller (CML's own and synced lab repositories):
        title, node types used, short description and id. Load one with cml_load_sample_lab to get a
        ready-made topology in one step."""
        app: CmlApp = get_client(ctx)
        rows = []
        for s in await _samples(app):
            types = s.get("node_types") or []
            text = f"{s.get('title')} {s.get('description')} {' '.join(types)}".lower()
            if search and search.lower() not in text:
                continue
            rows.append(
                {
                    "title": s.get("title"),
                    "node_types": types,
                    "description": str(s.get("description") or "").strip()[:200],
                    "repository": s.get("name"),
                    "id": s.get("id"),
                }
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Load sample lab")
    async def cml_load_sample_lab(
        ctx: Context,
        sample: Annotated[str, Field(description="Sample lab title or id (see cml_list_sample_labs)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a new lab from a sample lab (stopped; start it with cml_start_lab). The preview
        names the node types it uses and flags any that this controller has no definition or image
        for, since those nodes would not boot."""
        app: CmlApp = get_client(ctx)
        sample_lab = pick_one(
            await _samples(app), sample, key="title", kind="sample lab", list_tool="cml_list_sample_labs"
        )
        defs = await known_definitions(app)
        types = sample_lab.get("node_types") or []
        missing = [t for t in types if t not in defs]
        no_image = [
            t
            for t in types
            if t in defs
            and not defs[t].get("image_definitions")
            and t not in ("external_connector", "unmanaged_switch")
        ]
        blockers = [f"Node definitions not installed: {', '.join(missing)}"] if missing else []
        plan = Plan(
            f"Create a lab from sample {sample_lab.get('title')!r}",
            details={
                "node_types": types,
                **({"definitions_without_images": no_image} if no_image else {}),
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            res = await app.api.put(f"/sample/labs/{sample_lab['id']}")
            return {"id": res.get("id"), "title": res.get("lab_title"), "next": "cml_start_lab"}

        return await preview_or_apply(
            ctx,
            tool="cml_load_sample_lab",
            args={"sample": sample},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
