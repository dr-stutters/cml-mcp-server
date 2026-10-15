"""Topology export (Mermaid, draw.io, JSON) and lab annotations (text boxes) helpers.

Annotations this server writes carry z_index MCP_Z so that a later cml_annotate_lab(replace=true)
can find and replace its own text boxes without touching ones people drew by hand.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from xml.sax.saxutils import quoteattr

from stutters_mcp_core import InvalidRequest

MCP_Z = 42  # marker z_index of annotations written by cml-mcp-server

# --- annotations --------------------------------------------------------------------------


def text_annotation(
    text: str,
    x: float,
    y: float,
    *,
    size: int = 11,
    bold: bool = False,
    color: str = "#202020",
    border: str = "#00000000",
) -> dict[str, Any]:
    """A CML text annotation (POST /labs/{id}/annotations body, also valid in topology YAML)."""
    return {
        "type": "text",
        "text_content": text[:8192],
        "x1": float(max(-15000, min(15000, x))),
        "y1": float(max(-15000, min(15000, y))),
        "rotation": 0,
        "border_color": border,
        "border_style": "",
        "color": color,
        "thickness": 1,
        "text_bold": bold,
        "text_font": "monospace",
        "text_italic": False,
        "text_size": size,
        "text_unit": "pt",
        "z_index": MCP_Z,
    }


def annotation_row(a: dict[str, Any]) -> dict[str, Any]:
    text = a.get("text_content")
    row: dict[str, Any] = {
        "id": a.get("id"),
        "type": a.get("type"),
        "text": (text[:200] + "...") if isinstance(text, str) and len(text) > 200 else text,
        "x1": a.get("x1"),
        "y1": a.get("y1"),
        "ours": a.get("z_index") == MCP_Z,
    }
    if a.get("x2") is not None:
        row["x2"], row["y2"] = a.get("x2"), a.get("y2")
    return {k: v for k, v in row.items() if v is not None}


def node_box(nodes: list[dict[str, Any]]) -> tuple[float, float, float, float]:
    """(min x, min y, max x, max y) of the node positions (0s for an empty lab)."""
    xs = [float(n.get("x") or 0) for n in nodes] or [0.0]
    ys = [float(n.get("y") or 0) for n in nodes] or [0.0]
    return min(xs), min(ys), max(xs), max(ys)


def address_annotations(
    nodes: list[dict[str, Any]], addresses: dict[str, list[tuple[str, str]]]
) -> list[dict[str, Any]]:
    """One small text box under each node that has addresses ('Gi1 198.18.128.152/18')."""
    out = []
    for n in nodes:
        rows = addresses.get(str(n.get("label")))
        if not rows:
            continue
        text = "\n".join(f"{short_if(i)} {a}" for i, a in rows[:8])
        out.append(text_annotation(text, float(n.get("x") or 0) - 60, float(n.get("y") or 0) + 40, size=9))
    return out


_ADDR_LINE = re.compile(r"^\S+ \d+\.\d+\.\d+\.\d+(?:/\d+)?$")


def is_address_label(a: dict[str, Any]) -> bool:
    """A per-node address label (every line 'Gi1 10.0.0.1/24'): already in the diagram's boxes."""
    lines = str(a.get("text_content") or "").splitlines()
    return bool(lines) and all(_ADDR_LINE.match(x.strip()) for x in lines)


def short_if(name: str) -> str:
    """'GigabitEthernet1/0/1' -> 'Gi1/0/1', 'Ethernet0/0' -> 'E0/0', 'Loopback0' -> 'Lo0'."""
    for long, short in (
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("Ethernet", "E"),
        ("Loopback", "Lo"),
        ("Management", "Mgmt"),
        ("Port-channel", "Po"),
    ):
        if name.startswith(long):
            return short + name[len(long) :]
    return name


NOTE_GAP = 80


def _note_height(text: str) -> float:
    return 20 + 16 * (text.count("\n") + 1)


def place_notes(notes: list[dict[str, Any]], nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """CML text annotations for notes: given x/y, next to a `near` node, or stacked above the lab
    (left-aligned with it, the last box ending NOTE_GAP above the top node)."""
    x0, y0, _, _ = node_box(nodes)
    by_label = {str(n.get("label")): n for n in nodes}
    free = [str(n["text"]) for n in notes if not n.get("near") and (n.get("x") is None or n.get("y") is None)]
    cursor = y0 - NOTE_GAP - sum(_note_height(t) for t in free)
    out = []
    for note in notes:
        text = str(note["text"])
        if note.get("x") is not None and note.get("y") is not None:
            x, y = float(note["x"]), float(note["y"])
        elif note.get("near"):
            n = by_label.get(str(note["near"]))
            if n is None:
                raise InvalidRequest(f"note near={note['near']!r}: no such node in the lab")
            x, y = float(n.get("x") or 0) + 50, float(n.get("y") or 0) - 20
        else:
            x, y = x0 - 100, cursor
            cursor += _note_height(text)
        out.append(text_annotation(text, x, y, bold=bool(note.get("bold")), size=10))
    return out


# --- addresses from day-0 configs -------------------------------------------------------------

_IOS_IF = re.compile(r"^interface\s+(\S+)", re.IGNORECASE)
_IOS_IP = re.compile(r"^\s+ip(?:v4)? address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)")
_LINUX_IP = re.compile(r"ip (?:-4 )?addr(?:ess)? add\s+(\d+\.\d+\.\d+\.\d+/\d+)(?:.*?\bdev\s+(\S+))?")
_NETPLAN = re.compile(r"addresses:\s*\[?\s*['\"]?(\d+\.\d+\.\d+\.\d+/\d+)")


def config_addresses(definition: str, config: str | None) -> list[tuple[str, str]]:
    """[(interface, 'a.b.c.d/len')] configured in a node's day-0 config: IOS/IOS-XE/NX-OS
    'interface X / ip address A M', FTDv day0 JSON (IPv4Addr/IPv4Mask, management), Linux
    'ip addr add A/len dev X' and netplan 'addresses: [A/len]'."""
    if not config:
        return []
    out: list[tuple[str, str]] = []
    text = config.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        if isinstance(data, dict) and data.get("IPv4Addr") and data.get("IPv4Mask"):
            out.append(("Management0/0", _cidr(str(data["IPv4Addr"]), str(data["IPv4Mask"]))))
        return out
    iface: str | None = None
    for line in config.splitlines():
        if m := _IOS_IF.match(line):
            iface = m.group(1)
            continue
        if line and not line[0].isspace() and not line.startswith("!"):
            iface = None
        if iface and (m := _IOS_IP.match(line)):
            out.append((iface, _cidr(m.group(1), m.group(2))))
    for m in _LINUX_IP.finditer(config):
        out.append((m.group(2) or "eth0", m.group(1)))
    if not out and definition in ("ubuntu", "server"):
        out += [("ens2", m.group(1)) for m in _NETPLAN.finditer(config)]
    return out


def _cidr(ip: str, mask: str) -> str:
    try:
        return f"{ip}/{ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen}"
    except ValueError:
        return ip


# --- renderers -------------------------------------------------------------------------------


def _mid(i: int) -> str:
    return f"n{i}"


def _mermaid_text(s: str) -> str:
    """Safe inside a quoted Mermaid label: one line, entity-escaped (# and & first)."""
    s = re.sub(r"[\r\n\t]+", " ", _XML_BAD.sub("", s))
    return (
        s.replace("#", "#35;")
        .replace("&", "#amp;")
        .replace('"', "#quot;")
        .replace("<", "#lt;")
        .replace(">", "#gt;")
    )


def to_mermaid(model: dict[str, Any]) -> str:
    """A Mermaid flowchart: one box per node (label, definition, addresses), one edge per link
    labelled with both interface names. External connectors are circles, switches hexagons."""
    lines = ["graph LR"]
    ids = {n["label"]: _mid(i) for i, n in enumerate(model["nodes"])}
    for n in model["nodes"]:
        parts = [n["label"], n["definition"]]
        if n.get("connector"):
            parts.append(n["connector"])
        parts += [f"{short_if(i)} {a}" for i, a in n.get("addresses") or []]
        label = "<br/>".join(_mermaid_text(p) for p in parts)
        nid = ids[n["label"]]
        if n["definition"] == "external_connector":
            lines.append(f'  {nid}(("{label}"))')
        elif n["definition"] in ("unmanaged_switch", "ioll2-xe", "iosvl2") or "cat9000" in n["definition"]:
            lines.append(f'  {nid}{{{{"{label}"}}}}')
        else:
            lines.append(f'  {nid}["{label}"]')
    for lk in model["links"]:
        a, b = ids.get(lk["a_node"]), ids.get(lk["b_node"])
        if a and b:
            text = _mermaid_text(f"{short_if(lk['a_if'])} - {short_if(lk['b_if'])}")
            lines.append(f'  {a} ---|"{text}"| {b}')
    if model.get("notes"):
        note = "<br/>".join(_mermaid_text(t) for t in model["notes"])
        lines.append(f'  notes["{note}"]')
        lines.append("  style notes fill:#fffbe6,stroke:#999,stroke-dasharray: 3 3")
    return "\n".join(lines) + "\n"


def to_drawio(model: dict[str, Any]) -> str:
    """A draw.io (diagrams.net) file: nodes at their CML canvas positions, links as labelled edges,
    annotations as text cells. Open it in draw.io or embed it in a write-up."""
    nodes = model["nodes"]
    x0, y0, _, _ = node_box(nodes)
    off_x, off_y = 80 - x0, 80 - y0
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    ids = {n["label"]: f"n{i}" for i, n in enumerate(nodes)}
    for n in nodes:
        parts = [f"<b>{_html(n['label'])}</b>", _html(n["definition"])]
        if n.get("connector"):
            parts.append(_html(n["connector"]))
        parts += [_html(f"{short_if(i)} {a}") for i, a in n.get("addresses") or []]
        style = (
            "ellipse;whiteSpace=wrap;html=1;fillColor=#dae8fc;"
            if n["definition"] == "external_connector"
            else "rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;"
        )
        h = 40 + 14 * len(n.get("addresses") or [])
        x = float(n.get("x") or 0) + off_x - 60
        y = float(n.get("y") or 0) + off_y - h / 2
        cells.append(
            f'<mxCell id="{ids[n["label"]]}" value={quoteattr("<br>".join(parts))} style="{style}" '
            f'vertex="1" parent="1"><mxGeometry x="{x:.0f}" y="{y:.0f}" width="150" height="{h}" '
            'as="geometry"/></mxCell>'
        )
    for i, lk in enumerate(model["links"]):
        a, b = ids.get(lk["a_node"]), ids.get(lk["b_node"])
        if not (a and b):
            continue
        label = f"{short_if(lk['a_if'])} - {short_if(lk['b_if'])}"
        cells.append(
            f'<mxCell id="l{i}" value={quoteattr(_html(label))} style="endArrow=none;html=1;fontSize=9;" '
            f'edge="1" parent="1" source="{a}" target="{b}"><mxGeometry relative="1" as="geometry"/>'
            "</mxCell>"
        )
    for i, ann in enumerate(model.get("annotations") or []):
        if ann.get("type") != "text" or not ann.get("text_content"):
            continue
        text = "<br>".join(_html(t) for t in str(ann["text_content"]).splitlines())
        x = float(ann.get("x1") or 0) + off_x
        y = float(ann.get("y1") or 0) + off_y
        cells.append(
            f'<mxCell id="a{i}" value={quoteattr(text)} style="text;html=1;align=left;verticalAlign=top;'
            f'fontFamily=monospace;fontSize=9;" vertex="1" parent="1"><mxGeometry x="{x:.0f}" '
            f'y="{y:.0f}" width="260" height="{16 * (text.count("<br>") + 1)}" as="geometry"/></mxCell>'
        )
    title = quoteattr(_XML_BAD.sub("", str(model.get("lab") or "lab")))
    return (
        '<mxfile host="cml-mcp-server"><diagram name=' + title + ">"
        "<mxGraphModel><root>" + "".join(cells) + "</root></mxGraphModel></diagram></mxfile>\n"
    )


_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _html(s: str) -> str:
    """HTML-escaped text for draw.io html=1 labels (control characters XML forbids removed)."""
    return _XML_BAD.sub("", s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
