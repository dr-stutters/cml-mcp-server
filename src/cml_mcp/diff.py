"""Compare two CML topologies (parsed export YAML): nodes, interfaces, links and configs."""

from __future__ import annotations

import difflib
import re
from typing import Any

from stutters_mcp_core import InvalidRequest

from cml_mcp.console import mask_secrets

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
            # secrets masked on both sides (day-0 configs hold plain-text passwords)
            ca, cb = normalise_config(_config(x)), normalise_config(_config(y))
            if ca != cb:
                lines = list(
                    difflib.unified_diff(
                        ca,
                        cb,
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


# --- device configuration diffs (L6) -----------------------------------------------------------

# Lines that change on every 'show running-config' without a configuration change.
CONFIG_NOISE = re.compile(
    r"^(?:Building configuration\.\.\.|Current configuration\s*:.*|! Last configuration change at.*"
    r"|! NVRAM config last updated at.*|! No configuration change since last restart|ntp clock-period \d+"
    r"|!Time:.*|!Command: show running-config.*|!Running configuration last done at.*"
    r"|Using \d+ out of \d+ bytes"
    r"|: Saved|:\s*Written by.*|: Serial Number:.*|: Hardware:.*|Cryptochecksum:.*|\s*!\s*|end)$",
    re.IGNORECASE,
)
# A masked secret keeps its keyword but loses the encryption type ('secret 9 ********' and the
# day-0 'secret ********' are the same thing).
MASKED_TYPE = re.compile(r"\b(secret|password|key|key-string|community|pre-shared-key) \d{1,2} (\*{8})", re.I)
BANNER_START = re.compile(r"^banner\s+\S+\s+(\^C|\S)")


def normalise_config(text: str) -> list[str]:
    """Config lines ready for comparison: secrets masked, trailing space and noise lines dropped
    (banner bodies are kept verbatim, '!' and 'end' lines included)."""
    out = []
    delim: str | None = None  # inside a banner until this delimiter shows up again
    for raw in mask_secrets(text.replace("\r", "")).splitlines():
        line = raw.rstrip()
        if delim is not None:
            out.append(line)
            if delim in line:
                delim = None
            continue
        if not line.strip() or CONFIG_NOISE.match(line):
            continue
        if (m := BANNER_START.match(line)) and m.group(1) not in line[m.end(1) :]:
            delim = m.group(1)  # a multi-line banner: keep its body as it is
        out.append(MASKED_TYPE.sub(r"\1 \2", line))
    return out


def diff_configs(
    a: str,
    b: str,
    *,
    a_name: str,
    b_name: str,
    context: int = 2,
    max_lines: int = 200,
    ignore: list[str] | None = None,
) -> dict[str, Any]:
    """A unified diff of two device configurations (secrets masked on both sides) with counts."""
    if len(ignore or []) > 20:
        raise InvalidRequest("ignore: at most 20 patterns")
    patterns = []
    for p in ignore or []:
        try:
            patterns.append(re.compile(p[:300]))
        except re.error as e:
            raise InvalidRequest(f"ignore: bad regular expression {p!r}: {e}") from e

    def keep(lines: list[str]) -> list[str]:
        return [ln for ln in lines if not any(p.search(ln) for p in patterns)]

    la, lb = keep(normalise_config(a)), keep(normalise_config(b))
    lines = list(difflib.unified_diff(la, lb, a_name, b_name, lineterm="", n=context))
    added = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
    out: dict[str, Any] = {
        "identical": not lines,
        "lines_added": added,
        "lines_removed": removed,
        "a_lines": len(la),
        "b_lines": len(lb),
    }
    if lines:
        if len(lines) > max_lines:
            lines = lines[:max_lines] + [f"... {len(lines) - max_lines} more diff lines (raise max_lines)"]
        out["diff"] = "\n".join(lines)
    return out
