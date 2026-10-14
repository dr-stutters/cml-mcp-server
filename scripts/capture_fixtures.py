"""Capture real (redacted) CML responses into tests/fixtures/ for the unit tests.

    uv run python scripts/capture_fixtures.py <lab title or id>

Reads CML_* from .env. The lab should be started (so operational data, L3 addresses and console
logs exist). Redaction: tokens, product UUIDs and the controller address are replaced; console logs
are trimmed. Review the diff before committing.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

from cml_mcp.client import CmlApp
from cml_mcp.config import Settings

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def redact(data: Any, host: str) -> Any:
    text = json.dumps(data)
    text = text.replace(host, "cml.test")
    text = re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "<jwt>", text)
    obj = json.loads(text)

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {
                k: ("00000000-0000-0000-0000-000000000000" if k == "product_uuid" else walk(x))
                for k, x in v.items()
            }
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(obj)


async def main(lab_ref: str) -> None:
    settings = Settings()  # type: ignore[call-arg]
    host = settings.url.split("://", 1)[1].split("/")[0]
    app = CmlApp(settings)
    api = app.api
    try:
        lab = await app.resolve_lab(lab_ref)
        lid = lab["id"]
        nodes = await app.list_nodes(lid, operational=True)
        links = await app.list_links(lid)
        first = nodes[0]["id"]
        captures: dict[str, Any] = {
            "system_health.json": await api.get("/system_health"),
            "system_stats.json": await api.get("/system_stats"),
            "licensing.json": await api.get("/licensing"),
            "labs.json": await app.list_labs(),
            "lab.json": lab,
            "nodes.json": nodes,
            "node_configs.json": await api.get(f"/labs/{lid}/nodes", {"data": "true"}),
            "interfaces.json": await app.list_interfaces(lid),
            "links.json": links,
            "topology.json": await api.get(f"/labs/{lid}/topology"),
            "layer3_addresses.json": await api.get(f"/labs/{lid}/layer3_addresses"),
            "events.json": (await api.get(f"/labs/{lid}/events"))[:40],
            "simulation_stats.json": await api.get(f"/labs/{lid}/simulation_stats"),
            "element_state.json": await api.get(f"/labs/{lid}/lab_element_state"),
            "console_log.json": await api.get(f"/labs/{lid}/nodes/{first}/consoles/0/log", {"lines": 30}),
            "simplified_node_definitions.json": await api.get("/simplified_node_definitions"),
            "image_definitions.json": await api.get("/image_definitions"),
            "node_definition_iol_xe.json": await api.get("/node_definitions/iol-xe"),
        }
        if links:
            k = links[0]["id"]
            captures["link_condition.json"] = await api.get(f"/labs/{lid}/links/{k}/condition")
            captures["capture_status.json"] = await api.get(f"/labs/{lid}/links/{k}/capture/status")
            try:
                captures["capture_packets.json"] = (await api.get(f"/pcap/{k}/packets"))[:20]
            except Exception as e:  # no capture has run on this link
                print("no packets:", e)
        export = await api.get(f"/labs/{lid}/download", expect="text")
        (OUT / "lab_export.yaml").write_text(export.replace(host, "cml.test"))
        OUT.mkdir(parents=True, exist_ok=True)
        for name, data in captures.items():
            (OUT / name).write_text(json.dumps(redact(data, host), indent=1) + "\n")
            print("wrote", name)
    finally:
        await app.aclose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "mcp-test-probe"))
