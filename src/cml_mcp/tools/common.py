"""Shared parameter types and topology helpers for the tool modules."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Annotated, Any

import yaml
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import InvalidRequest, compact, object_result
from cml_mcp.client import CmlApp

LabRef = Annotated[str, Field(description="Lab title or id (see cml_list_labs)")]
NodeRef = Annotated[str, Field(description="Node label or id within the lab (see cml_list_nodes)")]
LinkRef = Annotated[
    str,
    Field(
        description="Link id, or its endpoints as 'r1<->r2' (add interfaces, 'r1:Ethernet0/0<->r2:"
        "Ethernet0/0', when two nodes share several links). See cml_list_links."
    ),
]

_CONSOLE_PREFIX = re.compile(r"^\|\d+\|", re.MULTILINE)
# Keys that grant access to a node's console/VNC/pcap streams: never shown.
ACCESS_KEYS = frozenset({"console_key", "vnc_key", "link_capture_key", "serial_consoles"})


def strip_console_prefixes(text: str) -> str:
    """Console logs prefix each line with a '|0000012345|' counter; drop it."""
    return _CONSOLE_PREFIX.sub("", text)


def drop_keys(data: Any, keys: frozenset[str] = ACCESS_KEYS) -> Any:
    if isinstance(data, dict):
        return {k: drop_keys(v, keys) for k, v in data.items() if k not in keys}
    if isinstance(data, list):
        return [drop_keys(v, keys) for v in data]
    return data


@dataclass
class Topo:
    """Lookup tables for one lab: nodes, interfaces and links by id, endpoint names."""

    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    interfaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    links: list[dict[str, Any]] = field(default_factory=list)

    def node_label(self, node_id: str | None) -> str:
        if not node_id:
            return "?"
        return str(self.nodes.get(node_id, {}).get("label") or node_id)

    def endpoint(self, iface_id: str | None) -> str:
        """'r1:Ethernet0/0' for an interface id."""
        iface = self.interfaces.get(iface_id or "", {})
        return f"{self.node_label(iface.get('node'))}:{iface.get('label') or iface_id}"

    def peers(self) -> dict[str, tuple[str, str]]:
        """interface id -> (peer endpoint name, link id)."""
        out: dict[str, tuple[str, str]] = {}
        for lk in self.links:
            a, b = lk.get("interface_a"), lk.get("interface_b")
            if a and b:
                out[a] = (self.endpoint(b), lk["id"])
                out[b] = (self.endpoint(a), lk["id"])
        return out

    def link_row(self, lk: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": lk["id"],
            "a": self.endpoint(lk.get("interface_a")),
            "b": self.endpoint(lk.get("interface_b")),
            "state": lk.get("state"),
        }


async def load_topo(app: CmlApp, lab_id: str, *, operational: bool = False) -> Topo:
    nodes, interfaces, links = await asyncio.gather(
        app.list_nodes(lab_id, operational=operational),
        app.list_interfaces(lab_id, operational=operational),
        app.list_links(lab_id),
    )
    return Topo({n["id"]: n for n in nodes}, {i["id"]: i for i in interfaces}, links)


def state_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for it in items:
        s = str(it.get("state"))
        counts[s] = counts.get(s, 0) + 1
    return counts


def config_text(node: dict[str, Any]) -> str | None:
    """The node's main (editable) day-0 configuration as text, if it has one."""
    cfg = node.get("configuration")
    if isinstance(cfg, str):
        return cfg
    if isinstance(cfg, list):
        texts = [c.get("content") for c in cfg if isinstance(c, dict) and c.get("content") is not None]
        if len(texts) == 1:
            return str(texts[0])
        # several files: prefer the non-JSON one (IOL carries a config.json helper file)
        named = [c for c in cfg if isinstance(c, dict) and not str(c.get("name", "")).endswith(".json")]
        if named and named[0].get("content") is not None:
            return str(named[0]["content"])
    if isinstance(cfg, dict):
        return str(cfg.get("content")) if cfg.get("content") is not None else None
    return None


def gib(n: Any) -> float | None:
    return round(n / 2**30, 1) if isinstance(n, int | float) else None


def parse_topology_yaml(text: str) -> dict[str, Any]:
    """Parse CML topology YAML, with a clear error if it isn't one."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InvalidRequest(f"Not valid YAML: {e}") from e
    if not isinstance(data, dict) or "nodes" not in data:
        raise InvalidRequest("Not a CML topology: expected a mapping with 'lab', 'nodes' and 'links'.")
    return data


def shaped(data: Any) -> ToolResult:
    """object_result with secrets masked and empty values dropped, but keeping 'links' keys (the
    core's default compaction drops them as HAL noise; in CML they are real data)."""
    return object_result(compact(data, drop=()), shape=False)
