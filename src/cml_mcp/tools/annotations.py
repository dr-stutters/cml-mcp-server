"""Topology export (Mermaid / draw.io / JSON) and lab annotations: list and annotate."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import hashlib
import json
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field
from stutters_mcp_core import (
    Confirm,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    preview_or_apply,
)
from stutters_mcp_core.http import page_of

from cml_mcp.client import CmlApp
from cml_mcp.licence import licensed
from cml_mcp.netops import address_commands, console_batch, parse_addresses
from cml_mcp.recipes import recipe_for_lab
from cml_mcp.tools.common import LabRef, config_text, load_topo
from cml_mcp.tools.recipes_tools import recipe_notes
from cml_mcp.topology import (
    MCP_Z,
    address_annotations,
    annotation_row,
    config_addresses,
    is_address_label,
    place_notes,
    to_drawio,
    to_mermaid,
)

AddressSource = Literal["config", "snooped", "cli", "none"]
ADDRESS_SOURCE_HELP = (
    "'config' (default): addresses in each node's day-0 config (works on stopped labs); 'snooped': "
    "what CML learned on external-connector segments; 'cli': ask every booted node over its console "
    "(slow but complete); 'none'"
)


class NoteSpec(BaseModel):
    text: str = Field(min_length=1, max_length=4000, description="Text (multi-line allowed)")
    near: str | None = Field(default=None, description="Place it under this node (label)")
    x: float | None = Field(default=None, ge=-15000, le=15000, description="Canvas x (default: auto)")
    y: float | None = Field(default=None, ge=-15000, le=15000, description="Canvas y (default: auto)")
    bold: bool = False


async def lab_addresses(
    app: CmlApp, lid: str, nodes: list[dict[str, Any]], source: str
) -> dict[str, list[tuple[str, str]]]:
    """node label -> [(interface, address)] from the chosen source."""
    out: dict[str, list[tuple[str, str]]] = {}
    if source == "config":
        for n in nodes:
            rows = config_addresses(str(n.get("node_definition")), config_text(n))
            if rows:
                out[str(n["label"])] = rows
    elif source == "snooped":
        data = await app.api.get(f"/labs/{lid}/layer3_addresses") or {}
        labels = {n["id"]: str(n["label"]) for n in nodes}
        for node_id, entry in data.items():
            name = labels.get(node_id) or str(entry.get("name") or node_id)
            for iface in (entry.get("interfaces") or {}).values():
                for ip in iface.get("ip4") or []:
                    out.setdefault(name, []).append((str(iface.get("label")), str(ip)))
    elif source == "cli":
        booted = [n for n in nodes if licensed(n) and n.get("state") in ("BOOTED", "STARTED")]
        batch = await console_batch(
            app, lid, booted, lambda _n, cred: address_commands(cred.os), timeout=30, purpose="cml_export"
        )
        for res in batch:
            for o in res.get("outputs") or []:
                for row in parse_addresses(o["command"], o.get("output", "")):
                    out.setdefault(res["node"], []).append((row["interface"], row["ipv4"]))
    return out


async def lab_model(app: CmlApp, lab: str, source: str) -> dict[str, Any]:
    info = await app.resolve_lab(lab)
    lid = info["id"]
    nodes: list[dict[str, Any]] = await app.api.get(f"/labs/{lid}/nodes", {"data": "true"})
    topo = await load_topo(app, lid)
    addresses = await lab_addresses(app, lid, nodes, source) if source != "none" else {}
    annotations: list[dict[str, Any]] = await app.api.get(f"/labs/{lid}/annotations") or []
    model_nodes = []
    for n in nodes:
        row: dict[str, Any] = {
            "label": str(n["label"]),
            "definition": str(n.get("node_definition")),
            "state": n.get("state"),
            "x": n.get("x"),
            "y": n.get("y"),
            "tags": n.get("tags") or [],
            "addresses": addresses.get(str(n["label"]), []),
        }
        if n.get("node_definition") == "external_connector":
            row["connector"] = (config_text(n) or "").strip() or None
        model_nodes.append(row)
    links = []
    for lk in topo.links:
        ia, ib = (
            topo.interfaces.get(lk.get("interface_a") or "", {}),
            topo.interfaces.get(lk.get("interface_b") or "", {}),
        )
        links.append(
            {
                "a_node": topo.node_label(ia.get("node")),
                "a_if": str(ia.get("label") or "?"),
                "b_node": topo.node_label(ib.get("node")),
                "b_if": str(ib.get("label") or "?"),
                "state": lk.get("state"),
            }
        )
    return {
        "lab": info.get("lab_title"),
        "lab_id": lid,
        "description": info.get("lab_description"),
        "nodes": model_nodes,
        "links": links,
        "annotations": annotations,
        "address_source": source,
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export topology diagram")
    async def cml_export_topology(
        ctx: Context,
        lab: LabRef,
        format: Annotated[
            Literal["mermaid", "drawio", "json"],
            Field(
                description="'mermaid' (flowchart text for Markdown/GitHub), 'drawio' (diagrams.net XML "
                "at the CML canvas positions, with annotations), 'json' (nodes, links, addresses)"
            ),
        ] = "mermaid",
        addresses: Annotated[AddressSource, Field(description=ADDRESS_SOURCE_HELP)] = "config",
        notes: Annotated[
            bool, Field(description="mermaid: add the lab's text annotations as a notes box")
        ] = True,
    ) -> dict[str, Any]:
        """A diagram of a lab for write-ups and demos: every node (label, definition, interface
        addresses) and every link labelled with both interface names. Addresses come from the
        day-0 configs by default (works on stopped labs), or from CML snooping or the live CLI.
        Returns the diagram text in `content`; for the CML topology YAML itself use cml_export_lab."""
        app: CmlApp = get_client(ctx)
        model = await lab_model(app, lab, addresses)
        if notes:
            model["notes"] = [
                str(a["text_content"]).replace("\n", " | ")[:300]
                for a in model["annotations"]
                if a.get("type") == "text" and a.get("text_content") and not is_address_label(a)
            ]
        if format == "mermaid":
            content: Any = to_mermaid(model)
        elif format == "drawio":
            content = to_drawio(model)
        else:
            content = {
                "lab": model["lab"],
                "nodes": [
                    {**n, "addresses": [{"interface": i, "address": a} for i, a in n["addresses"]]}
                    for n in model["nodes"]
                ],
                "links": model["links"],
                "annotations": [annotation_row(a) for a in model["annotations"]],
            }
        return {
            "lab": model["lab"],
            "format": format,
            "nodes": len(model["nodes"]),
            "links": len(model["links"]),
            "address_source": addresses,
            "content": content,
        }

    @reg.read(title="List annotations")
    async def cml_list_annotations(
        ctx: Context,
        lab: LabRef,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The drawn annotations of a lab (text boxes, rectangles, ellipses, lines): id, type, text,
        position, and `ours` = written by this server (cml_annotate_lab, recipes). Smart annotations
        (tag groups) are not included."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        data: list[dict[str, Any]] = await app.api.get(f"/labs/{info['id']}/annotations") or []
        rows = [annotation_row(a) for a in data]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Annotate lab")
    async def cml_annotate_lab(
        ctx: Context,
        lab: LabRef,
        notes: Annotated[
            list[NoteSpec],
            Field(
                max_length=30,
                description="Text boxes to add: [{text, near?: node label, x?, y?, bold?}]; without "
                "a position they stack left of the lab",
            ),
        ] = [],  # noqa: B006 - FastMCP copies defaults per call
        addresses: Annotated[
            AddressSource,
            Field(
                description="Also label every node with its addresses from this source. "
                + ADDRESS_SOURCE_HELP
            ),
        ] = "none",
        recipe: Annotated[
            bool,
            Field(
                description="If the lab is a recipe's lab, add its purpose, address plan and where its "
                "credentials are kept (references only, never values)"
            ),
        ] = False,
        replace: Annotated[
            bool,
            Field(description="First delete the text boxes this server wrote earlier (not hand-drawn ones)"),
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make a lab self-describing for PoCs and demos: add text boxes (free notes, per-node
        address labels, the recipe's purpose/address plan/credential references). With
        replace=true (default) the boxes this server added before are removed first, so it can be
        re-run; hand-drawn annotations are never touched. Don't put passwords in notes: annotations
        are visible to everyone who can open the lab. addresses='cli' logs in to every booted node at
        preview and again at confirm (read-only show commands); 'config' is instant."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        nodes: list[dict[str, Any]] = await app.api.get(f"/labs/{lid}/nodes", {"data": "true"})
        wanted: list[dict[str, Any]] = [n.model_dump() for n in notes]
        recipe_name = recipe_for_lab(str(info.get("lab_title"))) if recipe else None
        blockers: list[str] = []
        if recipe and recipe_name is None:
            blockers.append(f"Lab {info.get('lab_title')!r} is not a recipe's lab (see cml_list_recipes)")
        if recipe_name:
            wanted = recipe_notes(recipe_name) + wanted
        bodies = place_notes(wanted, nodes)
        if addresses != "none":
            bodies += address_annotations(nodes, await lab_addresses(app, lid, nodes, addresses))
        existing: list[dict[str, Any]] = await app.api.get(f"/labs/{lid}/annotations") or []
        ours = (
            [a for a in existing if a.get("z_index") == MCP_Z and a.get("type") == "text"] if replace else []
        )
        if not bodies and not ours:
            blockers.append("Nothing to add: give notes, addresses or recipe=true")
        plan = Plan(
            f"Add {len(bodies)} text annotation(s) to lab {info.get('lab_title')}"
            + (f", replacing {len(ours)} earlier one(s)" if ours else ""),
            details={"add": [b["text_content"] for b in bodies], "remove": [a.get("id") for a in ours]},
            # what will be written, too: addresses or positions changing after the preview void the token
            fingerprint={
                "remove": sorted(str(a.get("id")) for a in ours),
                "add": hashlib.sha256(json.dumps(bodies, sort_keys=True).encode()).hexdigest(),
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            # new boxes first: a failed POST leaves the old set in place rather than a partial lab
            created = [await app.api.post(f"/labs/{lid}/annotations", b) for b in bodies]
            for a in ours:
                await app.api.delete(f"/labs/{lid}/annotations/{a['id']}")
            return {"added": [c.get("id") for c in created], "removed": len(ours)}

        return await preview_or_apply(
            ctx,
            tool="cml_annotate_lab",
            args={
                "lab": lab,
                "notes": [n.model_dump() for n in notes],
                "addresses": addresses,
                "recipe": recipe,
                "replace": replace,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
