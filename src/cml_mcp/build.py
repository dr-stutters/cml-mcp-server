"""Turn a compact lab spec (nodes + 'a b' link strings) into CML topology YAML."""

from __future__ import annotations

import math
from typing import Any

import yaml
from pydantic import BaseModel, Field

# Nodes that never take a node licence (and boot instantly).
UNLICENSED_DEFINITIONS = frozenset({"external_connector", "unmanaged_switch"})


class NodeCredentials(BaseModel):
    username: str | None = Field(default=None, description="Login user (pyATS username)")
    password: str | None = Field(default=None, description="Login password (pyATS password)")
    enable_password: str | None = Field(default=None, description="Enable secret, if different")


class NodeSpec(BaseModel):
    label: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[^\s:]+$",
        description="Node label, e.g. r1 (no spaces or ':')",
    )
    definition: str = Field(description="Node definition id, e.g. iol-xe, ioll2-xe, alpine, unmanaged_switch")
    config: str | None = Field(
        default=None,
        description="Day-0 configuration for the definition's main config file (IOS-XE/NX-OS CLI, FTDv "
        "day0-config JSON, Alpine node.cfg...). For an external_connector: the connector label or bridge "
        "(see cml_list_external_connectors), e.g. 'System Bridge' or 'NAT'",
    )
    files: dict[str, str] = Field(
        default_factory=dict,
        description="Other config files by name, e.g. {'conf/vswitch.xml': ...} on cat9000v or "
        "{'network-config': ...} on ubuntu",
    )
    credentials: NodeCredentials | None = Field(
        default=None,
        description="Login the console tools use (CML pyATS credentials); set it when the day-0 config "
        "changes the definition's default login",
    )
    image: str | None = Field(default=None, description="Image definition id (default: newest)")
    tags: list[str] = Field(default_factory=list, description="Tags")
    ram: int | None = Field(default=None, ge=64, description="RAM in MB")
    cpus: int | None = Field(default=None, ge=1, le=64, description="vCPUs")
    parameters: dict[str, str] = Field(
        default_factory=dict, description="Node parameters (definition-specific)"
    )
    x: int | None = Field(default=None, description="Canvas x position (default: grid layout)")
    y: int | None = Field(default=None, description="Canvas y position (default: grid layout)")


class BuildError(ValueError):
    pass


def parse_link(spec: str) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """'r1 r2', 'r1<->r2', 'r1:Ethernet0/1 r2:Ethernet0/1' -> ((node, iface|None), (node, iface|None))."""
    parts = [p.strip() for p in spec.split("<->")] if "<->" in spec else spec.split()
    if len(parts) != 2 or not all(parts):
        raise BuildError(f"Link {spec!r}: write it as 'r1 r2', 'r1<->r2' or 'r1:Ethernet0/0 r2:Ethernet0/0'")
    out = []
    for p in parts:
        node, _, iface = p.partition(":")
        out.append((node, iface or None))
    return out[0], out[1]


def _layout(i: int, n: int) -> tuple[int, int]:
    cols = max(1, math.ceil(math.sqrt(n)))
    return (i % cols) * 200, (i // cols) * 160


def connector_keys(connectors: list[dict[str, Any]]) -> set[str]:
    """Values an external_connector node's config may name: connector labels, bridge names, tags."""
    keys: set[str] = set()
    for c in connectors:
        for k in ("label", "device_name"):
            if c.get(k):
                keys.add(str(c[k]))
        keys.update(str(t) for t in c.get("tags") or [])
    return keys


def auto_interfaces(names: list[str]) -> list[str]:
    """Interfaces auto-allocation may pick: not FTDv/ASAv's placeholder 'donotuse' slots."""
    return [x for x in names if not x.lower().startswith("donotuse")]


def build_topology(
    title: str,
    nodes: list[NodeSpec],
    links: list[str],
    definitions: dict[str, dict[str, Any]],
    description: str | None = None,
    *,
    connectors: list[dict[str, Any]] | None = None,
    notes: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """(topology dict, human-readable link list). Raises BuildError for anything CML would reject.
    `connectors` (GET /system/external_connectors) lets external_connector configs be checked;
    `notes` collects non-fatal remarks for the preview."""
    problems: list[str] = []
    notes = notes if notes is not None else []
    labels = [n.label for n in nodes]
    dupes = sorted({x for x in labels if labels.count(x) > 1})
    if dupes:
        problems.append(f"Duplicate node labels: {', '.join(dupes)}")
    for n in nodes:
        d = definitions.get(n.definition)
        if d is None:
            problems.append(f"{n.label}: unknown node definition {n.definition!r}")
        elif n.image and n.image not in (d.get("image_definitions") or []):
            problems.append(f"{n.label}: image {n.image!r} does not belong to {n.definition!r}")
        if n.definition == "external_connector" and connectors is not None:
            keys = connector_keys(connectors)
            if n.config is None:
                notes.append(f"{n.label}: no config given, so CML's default ('NAT') is used")
            elif n.config.strip() not in keys:
                problems.append(
                    f"{n.label}: external connector {n.config.strip()!r} does not exist (known: "
                    f"{', '.join(sorted(keys))}; see cml_list_external_connectors)"
                )
    if problems:
        raise BuildError("; ".join(problems))

    by_label = {n.label: n for n in nodes}
    # per node: ordered physical interface names, which are used
    phys: dict[str, list[str]] = {}
    used: dict[str, set[str]] = {n.label: set() for n in nodes}
    for n in nodes:
        ifaces = (definitions[n.definition].get("device") or {}).get("interfaces") or {}
        phys[n.label] = list(ifaces.get("physical") or [])

    def pick(node: str, iface: str | None, link: str) -> str:
        if node not in by_label:
            raise BuildError(f"Link {link!r}: no node labelled {node!r} in the spec")
        names = phys[node]
        if iface:
            if iface not in names:
                hint = ", ".join(names[:4]) + ("..." if len(names) > 4 else "")
                raise BuildError(f"Link {link!r}: {node} has no interface {iface!r} (names: {hint})")
            if iface in used[node]:
                raise BuildError(f"Link {link!r}: {node}:{iface} is used twice")
        else:
            free = [x for x in auto_interfaces(names) if x not in used[node]]
            if not free:
                raise BuildError(
                    f"Link {link!r}: {node} ({by_label[node].definition}) has no free interfaces left"
                )
            iface = free[0]
        used[node].add(iface)
        return iface

    parsed = []
    for spec in links:
        (na, ia), (nb, ib) = parse_link(spec)
        if na == nb:
            raise BuildError(f"Link {spec!r}: both ends are {na}")
        parsed.append((spec, na, ia, nb, ib))
    # explicit interfaces first, so auto-allocation never takes one a later link names
    explicit: dict[tuple[int, int], str] = {}
    for idx, (spec, na, ia, nb, ib) in enumerate(parsed):
        for side, (end, iface) in enumerate(((na, ia), (nb, ib))):
            if iface:
                explicit[(idx, side)] = pick(end, iface, spec)
    resolved: list[tuple[str, str, str, str]] = []
    for idx, (spec, na, _ia, nb, _ib) in enumerate(parsed):
        ea = explicit.get((idx, 0)) or pick(na, None, spec)
        eb = explicit.get((idx, 1)) or pick(nb, None, spec)
        resolved.append((na, ea, nb, eb))

    topo_nodes = []
    iface_ids: dict[tuple[str, str], str] = {}
    for idx, n in enumerate(nodes):
        d = definitions[n.definition]
        dev = (d.get("device") or {}).get("interfaces") or {}
        interfaces: list[dict[str, Any]] = []
        if dev.get("has_loopback_zero"):
            loopback = (dev.get("loopback") or ["Loopback0"])[0]
            interfaces.append({"id": f"i{len(interfaces)}", "label": loopback, "type": "loopback"})
        default_count = int(dev.get("default_count") or 0)
        needed = max([phys[n.label].index(x) + 1 for x in used[n.label]] + [default_count])
        for slot, name in enumerate(phys[n.label][:needed]):
            iid = f"i{len(interfaces)}"
            interfaces.append({"id": iid, "label": name, "type": "physical", "slot": slot})
            iface_ids[(n.label, name)] = iid
        x, y = _layout(idx, len(nodes))
        x = n.x if n.x is not None else x
        y = n.y if n.y is not None else y
        node: dict[str, Any] = {
            "id": f"n{idx}",
            "label": n.label,
            "node_definition": n.definition,
            "x": x,
            "y": y,
            "tags": n.tags,
            "interfaces": interfaces,
        }
        configuration = []
        if n.config is not None:
            # "Main" is CML's alias for the definition's main config file (ios_config.txt, day0-config...)
            content = n.config.strip() if n.definition == "external_connector" else n.config
            configuration.append({"name": "Main", "content": content})
        configuration += [{"name": name, "content": text} for name, text in n.files.items()]
        if configuration:
            node["configuration"] = configuration
        if n.credentials is not None:
            node["pyats"] = {k: v for k, v in n.credentials.model_dump().items() if v is not None}
        if n.parameters:
            node["parameters"] = dict(n.parameters)
        if n.image:
            node["image_definition"] = n.image
        if n.ram:
            node["ram"] = n.ram
        if n.cpus:
            node["cpus"] = n.cpus
        topo_nodes.append(node)
    node_ids = {n.label: f"n{i}" for i, n in enumerate(nodes)}
    topo_links = [
        {
            "id": f"l{i}",
            "n1": node_ids[a],
            "i1": iface_ids[(a, ia)],
            "n2": node_ids[b],
            "i2": iface_ids[(b, ib)],
        }
        for i, (a, ia, b, ib) in enumerate(resolved)
    ]
    topology = {
        "lab": {"title": title, "description": description or "built by cml-mcp-server", "version": "0.3.0"},
        "nodes": topo_nodes,
        "links": topo_links,
    }
    return topology, [f"{a}:{ia}<->{b}:{ib}" for a, ia, b, ib in resolved]


def to_yaml(topology: dict[str, Any]) -> str:
    return yaml.safe_dump(topology, sort_keys=False, default_flow_style=False)
