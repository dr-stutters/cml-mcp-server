"""Compare two CML topologies (parsed export YAML): nodes, interfaces, links and configs."""

from __future__ import annotations

import difflib
from typing import Any

NODE_FIELDS = ("node_definition", "image_definition", "ram", "cpus", "cpu_limit", "boot_disk_size", "tags")
MAX_CONFIG_DIFF_LINES = 80


def _config(node: dict[str, Any]) -> str:
    cfg = node.get("configuration")
    if isinstance(cfg, str):
        return cfg
    if isinstance(cfg, list):
        parts = []
        for f in cfg:
            if isinstance(f, dict) and f.get("content") is not None:
                if len(cfg) > 1:
                    parts.append(f"### {f.get('name')}")
                parts.append(str(f["content"]))
        return "\n".join(parts)
    return ""


def normalise(topology: dict[str, Any]) -> dict[str, Any]:
    """{nodes: {label: node}, links: set of sorted endpoint pairs} from export YAML."""
    nodes: dict[str, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    iface_names: dict[tuple[str, str], str] = {}
    for n in topology.get("nodes") or []:
        label = str(n.get("label") or n.get("id"))
        nodes[label] = n
        by_id[str(n.get("id"))] = n
        for i in n.get("interfaces") or []:
            iface_names[(str(n.get("id")), str(i.get("id")))] = str(i.get("label") or i.get("id"))
    links: set[tuple[str, str]] = set()
    for lk in topology.get("links") or []:
        n1, n2 = str(lk.get("n1")), str(lk.get("n2"))
        a = f"{by_id.get(n1, {}).get('label', n1)}:{iface_names.get((n1, str(lk.get('i1'))), lk.get('i1'))}"
        b = f"{by_id.get(n2, {}).get('label', n2)}:{iface_names.get((n2, str(lk.get('i2'))), lk.get('i2'))}"
        links.add((min(a, b), max(a, b)))
    return {"title": (topology.get("lab") or {}).get("title"), "nodes": nodes, "links": links}


def diff_topologies(
    a: dict[str, Any],
    b: dict[str, Any],
    *,
    include_configs: bool = True,
    a_name: str = "a",
    b_name: str = "b",
) -> dict[str, Any]:
    na, nb = normalise(a), normalise(b)
    out: dict[str, Any] = {"a": na["title"] or a_name, "b": nb["title"] or b_name}
    only_a = sorted(set(na["nodes"]) - set(nb["nodes"]))
    only_b = sorted(set(nb["nodes"]) - set(na["nodes"]))
    changed: dict[str, Any] = {}
    for label in sorted(set(na["nodes"]) & set(nb["nodes"])):
        x, y = na["nodes"][label], nb["nodes"][label]
        delta: dict[str, Any] = {}
        for f in NODE_FIELDS:
            if x.get(f) != y.get(f):
                delta[f] = {"a": x.get(f), "b": y.get(f)}
        ia = {str(i.get("label")) for i in x.get("interfaces") or []}
        ib = {str(i.get("label")) for i in y.get("interfaces") or []}
        if ia != ib:
            delta["interfaces"] = {"only_in_a": sorted(ia - ib), "only_in_b": sorted(ib - ia)}
        if include_configs:
            ca, cb = _config(x), _config(y)
            if ca.strip() != cb.strip():
                lines = list(
                    difflib.unified_diff(
                        ca.splitlines(),
                        cb.splitlines(),
                        f"{label} ({a_name})",
                        f"{label} ({b_name})",
                        lineterm="",
                        n=1,
                    )
                )
                if len(lines) > MAX_CONFIG_DIFF_LINES:
                    lines = lines[:MAX_CONFIG_DIFF_LINES] + [
                        f"... {len(lines) - MAX_CONFIG_DIFF_LINES} more lines"
                    ]
                delta["config_diff"] = "\n".join(lines)
        if delta:
            changed[label] = delta
    out["nodes"] = {"only_in_a": only_a, "only_in_b": only_b, "changed": changed}
    out["links"] = {
        "only_in_a": [f"{x}<->{y}" for x, y in sorted(na["links"] - nb["links"])],
        "only_in_b": [f"{x}<->{y}" for x, y in sorted(nb["links"] - na["links"])],
    }
    out["identical"] = not (
        only_a or only_b or changed or out["links"]["only_in_a"] or out["links"]["only_in_b"]
    )
    return out
