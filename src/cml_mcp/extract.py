"""Which nodes CML can extract a running config from (L71 follow-up, #108).

CML's PUT /labs/{lab}/nodes/{node}/extract_configuration only works for node definitions with
`pyats.config_extract_command` (iol-xe: 'show run'); for the rest (alpine: `pyats: {os: linux}`) it answers
400 'Configuration Extraction not supported for Node ...'. The previews read each definition once and leave
those nodes out of the extract targets, so the blast radius counts only the nodes that really change.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

import yaml

from cml_mcp._core import UpstreamError
from cml_mcp.client import CmlApp

UNSUPPORTED = "Configuration Extraction not supported"
ERROR_MAX = 500


async def full_definition(app: CmlApp, definition: str) -> dict[str, Any] | None:
    """GET /node_definitions/{id} (CML returns YAML); None when it cannot be read, so no check is made."""
    try:
        raw = await app.api.get(f"/node_definitions/{quote(definition, safe='')}")
    except UpstreamError:
        return None
    d = yaml.safe_load(raw) if isinstance(raw, str) else raw
    return d if isinstance(d, dict) else None


def can_extract(definition: dict[str, Any] | None) -> bool:
    """True when the definition names a config extraction command, or could not be read (CML decides)."""
    if definition is None:
        return True
    pyats = definition.get("pyats")
    return isinstance(pyats, dict) and bool(pyats.get("config_extract_command"))


async def split_extractable(
    app: CmlApp, nodes: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """(nodes CML can extract, {label: reason} for the ones whose definition has no config extraction).
    Each definition is read once, however many nodes use it."""
    ids = sorted({str(n.get("node_definition")) for n in nodes if n.get("node_definition")})
    defs = dict(zip(ids, await asyncio.gather(*(full_definition(app, d) for d in ids)), strict=True))
    targets: list[dict[str, Any]] = []
    skipped: dict[str, str] = {}
    for n in nodes:
        d = n.get("node_definition")
        if d and not can_extract(defs.get(str(d))):
            skipped[str(n.get("label"))] = f"definition {d} has no config extraction"
        else:
            targets.append(n)
    return targets, skipped


def extract_error(e: Exception) -> str:
    """The per-node failure with CML's reason kept: the 400 for an unsupported definition becomes that
    reason; otherwise the request path (two UUIDs long) is dropped before the text is cut."""
    text = str(e)
    if UNSUPPORTED.lower() in text.lower():
        return "CML: configuration extraction not supported for this node's definition"
    head, sep, detail = text.partition("/extract_configuration: ")
    if sep:
        status = head.split(" on ", 1)[0]
        text = f"{status}: {detail}"
    return text[:ERROR_MAX]
