"""cml_archive_lab (L71): a restorable copy of a lab on the server host before it is torn down."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cml_mcp._core import Confirm, Plan, ToolRegistrar, get_client, get_settings, preview_or_apply
from cml_mcp.archive import archive_root, latest_archive, node_files, readme_text, write_archive
from cml_mcp.capture_files import safe_component
from cml_mcp.client import CmlApp
from cml_mcp.extract import extract_error, split_extractable
from cml_mcp.recipes import read_recipe_marker, redact_values, secret_names_by_value
from cml_mcp.safety import guarded_preview_or_apply
from cml_mcp.tools.common import LabRef, parse_topology_yaml
from cml_mcp.tools.lab_writes import lab_fingerprint
from cml_mcp.tools.labs import mask_export


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Archive lab to files")
    async def cml_archive_lab(
        ctx: Context,
        lab: LabRef,
        extract: Annotated[
            bool,
            Field(
                description="Save the running config of every booted node into its stored config first (CML "
                "'extract configuration'), so the archive has what the devices run now. false archives the "
                "stored configs as they are and changes nothing in the lab"
            ),
        ] = True,
        purpose: Annotated[
            str | None,
            Field(max_length=500, description="Why the lab exists / why it is archived (goes in README.md)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Archive a lab before deleting or wiping it: writes CML_ARCHIVE_DIR/<title>-<UTC time>/ on the
        server host with topology.yaml (the CML export with node configs, re-importable with
        cml_import_lab), configs/<node>.txt and README.md (purpose, date, recipe, nodes, restore steps).
        Nothing comes back through MCP but the paths and checksums; no disk images; files are mode 0600 and
        never overwritten. Secrets: pyATS passwords '********', node-file passwords ${LAB_NODE_PASSWORD},
        lab secret values their ${LAB_*} reference (filled in again on import); other device-config secrets
        stay as they are. The preview lists the nodes whose running configs will be extracted (extract=true
        overwrites their stored day-0 configs, like cml_extract_node_configs); booted nodes whose definition
        has no config extraction (alpine and other Linux hosts) are archived with their stored config and
        named under no_config_extraction. cml_delete_lab and
        cml_wipe_lab previews warn when no archive is newer than the lab's last change. Preview-first."""
        settings = get_settings(ctx)
        root = archive_root(settings.archive_dir)
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        title = str(info.get("lab_title") or lid)
        nodes = await app.list_nodes(lid)
        booted = [n for n in nodes if n.get("state") == "BOOTED"] if extract else []
        booted, no_extract = await split_extractable(app, booted)
        stored_only = [str(n.get("label")) for n in nodes if n not in booted]
        previous = await asyncio.to_thread(latest_archive, root, info)
        side_effects = ["Writes one directory of files on the server host (no disk images)"]
        if booted:
            side_effects.append(
                f"Overwrites the stored day-0 config of {len(booted)} node(s) with their running config"
            )
        plan = Plan(
            f"Archive lab {title!r} ({len(nodes)} nodes) to CML_ARCHIVE_DIR"
            + (f", extracting {len(booted)} running config(s) first" if booted else ""),
            details={
                "directory": f"{safe_component(title, lid)}-<UTC time>",
                "archive_dir": str(root),
                "extract_configs": [n.get("label") for n in booted],
                "stored_config_only": stored_only,
                **({"no_config_extraction": no_extract} if no_extract else {}),
                "files": ["topology.yaml", "configs/<node>.txt", "README.md", "archive.json"],
                "previous_archive": previous["archived_at"] if previous else None,
            },
            fingerprint={"lab": lab_fingerprint(info), "nodes": [(n["id"], n.get("state")) for n in nodes]},
            side_effects=side_effects,
            blast_radius=len(booted),
        )

        async def apply() -> Any:
            extracted: list[str] = []
            failed: dict[str, str] = {}
            for n in booted:
                try:
                    await app.api.put(f"/labs/{lid}/nodes/{n['id']}/extract_configuration", timeout=120)
                    extracted.append(str(n.get("label")))
                except Exception as e:  # report per node, keep archiving
                    failed[str(n.get("label"))] = extract_error(e)
            mapping = secret_names_by_value(settings.lab_secrets_file)
            text = await app.api.get(f"/labs/{lid}/download", expect="text")
            text = redact_values(mask_export(text), mapping)
            topo = parse_topology_yaml(text)
            current = await app.api.get(f"/labs/{lid}")  # 'modified' after the extract
            configs: list[tuple[str, str]] = []
            for node in topo.get("nodes") or []:
                configs.extend(node_files(node))
            now = datetime.now(UTC)
            meta = topo.get("lab") or {}
            readme = readme_text(
                title=title,
                lab_id=lid,
                purpose=purpose,
                archived_at=now,
                description=redact_values(str(meta.get("description") or ""), mapping) or None,
                recipe=read_recipe_marker(info.get("lab_notes") or meta.get("notes")),
                nodes=nodes,
                extracted=extracted,
                not_extracted={**no_extract, **failed},
                config_files=[c[0] for c in configs],
            )
            manifest = {
                "lab_id": lid,
                "lab_title": title,
                "lab_modified": (current or {}).get("modified") or info.get("modified"),
                "archived_at": now.isoformat(timespec="seconds"),
                "nodes": len(nodes),
                "extracted": extracted,
                "topology_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "purpose": purpose,
            }
            folder = await asyncio.to_thread(
                write_archive, root, title, lid, text, configs, readme, manifest, now
            )
            result: dict[str, Any] = {
                "lab": title,
                "path": str(folder),
                "files": [
                    "topology.yaml",
                    "README.md",
                    "archive.json",
                    *(f"configs/{c[0]}" for c in configs),
                ],
                "topology_sha256": manifest["topology_sha256"],
                "extracted": extracted,
                "restore": f"cml_import_lab with the contents of {folder}/topology.yaml",
            }
            if failed:
                result["not_extracted"] = failed
            return result

        args = {"lab": lab, "extract": extract, "purpose": purpose}
        if booted:  # changes the lab: the CML rails (protected labs) apply
            return await guarded_preview_or_apply(
                ctx, tool="cml_archive_lab", args=args, confirm=confirm, plan=plan, apply=apply
            )
        return await preview_or_apply(
            ctx, tool="cml_archive_lab", args=args, confirm=confirm, plan=plan, apply=apply
        )
