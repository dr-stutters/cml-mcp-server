"""Site replica planning (L16): map real devices (from Catalyst Center, ISE, FMC) to CML node definitions
within a node/RAM budget and produce a cml_build_lab spec with the gaps listed. Pure functions; the tool
and the cml_replicate_site prompt feed it the product servers' inventory."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

Fidelity = Literal["light", "faithful"]


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern[str]
    kind: str  # router / switch / firewall / wlc / ...
    light: str | None  # node definition at light fidelity (None: not modelled)
    faithful: str | None
    note: str = ""


def _r(rx: str, kind: str, light: str | None, faithful: str | None, note: str = "") -> Rule:
    return Rule(re.compile(rx, re.IGNORECASE), kind, light, faithful, note)


# First match wins. Platform strings as Catalyst Center (platformId/series), ISE and FMC (model) report them.
RULES: tuple[Rule, ...] = (
    _r(
        r"\bFMC|Management Center|\bFS\d{3,4}\b",
        "manager",
        None,
        "fmcv",
        "FMCv needs 32 GB; see recipe 'fmc-local'",
    ),
    _r(
        r"\bISE\b|\bSNS-3|Identity Services Engine",
        "aaa",
        None,
        "ise",
        "ISE in CML is heavy; light fidelity points the replica at the existing ISE instead",
    ),
    _r(
        r"\bC9800|9800-CL|Catalyst 9800|\bAIR-CT|\bWLC\b|Wireless (LAN )?Controller",
        "wlc",
        "cat9800",
        "cat9800",
        "WLAN config only; APs can't join",
    ),
    _r(
        r"\bAIR-(?!CT)|\bC91\d\d|\bCW91\d\d|\bAP\b|Access Point|Unified AP",
        "ap",
        None,
        None,
        "CAPWAP APs aren't modelled in CML (wireless-ap is a hostapd AP, see recipe 'wireless')",
    ),
    _r(r"\bN[3579]K|\bN77-|Nexus ?[3579]", "switch", "nxosv9000", "nxosv9000", "NX-OS 9000v"),
    _r(
        r"\bC9KV|\bC9[2-6]\d\d|Catalyst 9[2-6]|\bC38[05]0|\bC36[05]0|\bWS-C|\bC29[56]0|\bIE-?\d|"
        r"\bC1000\b|\bC1000-|Catalyst 1000|\bCBS\d{3}",
        "switch",
        "ioll2-xe",
        "cat9000v-uadp",
        "IOL-L2 at light fidelity; cat9000v (18 GB) is the faithful Catalyst 9000",
    ),
    _r(
        r"\bASR[- ]?9(?:\d{3}|K)\b|\bNCS[- ]?\d|\bXRv|IOS-XR|\bCisco 8\d{3}\b|^8[1-8]\d\d\b|"
        r"8000 Series Router",
        "router",
        "xrd",
        "iosxrv9000",
        "IOS-XR (XRd at light fidelity)",
    ),
    _r(
        r"\bC8[0-5]\d\d|\bC8000|\bISR|\bASR[- ]?1\d|\bASR[- ]?9[0-3]\d\b|\bCSR1000|\bC11\d\d|Catalyst 8|"
        r"\bCISCO(?:19|29|39)\d\d|\b(?:19|29|39)\d\d\b|\bIR\d{3,4}\b",
        "router",
        "iol-xe",
        "cat8000v",
        "IOL-XE at light fidelity; cat8000v is IOS-XE on the 8000v",
    ),
    _r(
        r"\bFTD|Firepower|\bFPR|Secure Firewall|Threat Defense",
        "firewall",
        "ftdv",
        "ftdv",
        "FTDv (8 GB) at either fidelity; register it to an FMC",
    ),
    _r(r"\bASA", "firewall", "asav", "asav", "ASAv at either fidelity"),
    _r(r"Meraki|\bM[XSRVG]\d{2,3}\b", "other", None, None, "cloud-managed Meraki gear isn't modelled"),
)
RAM_GB = {
    "iol-xe": 1,
    "ioll2-xe": 1,
    "cat9000v-uadp": 18,
    "cat8000v": 4,
    "nxosv9000": 10,
    "xrd": 2,
    "iosxrv9000": 20,
    "ftdv": 8,
    "asav": 2,
    "fmcv": 32,
    "ise": 16,
    "cat9800": 6,
    "alpine": 1,
}
# light vs faithful only differs for IOS/IOS-XE routers and switches and IOS-XR; firewalls, WLCs and NX-OS
# map to the same virtual platform either way (there is no lighter equivalent).


# Catalyst Center 'family' as a fallback when the platform string is unknown
FAMILY_HINTS = (
    ("Wireless Controller", "C9800"),
    ("Unified AP", "AP"),
    ("Switches", "C9300"),
    ("Routers", "C8300"),
    ("Security", "FTD"),
)


def map_platform(platform: str, fidelity: Fidelity, family: str | None = None) -> dict[str, Any]:
    for rule in RULES:
        if rule.pattern.search(platform or ""):
            definition = rule.faithful if fidelity == "faithful" else rule.light
            out: dict[str, Any] = {"kind": rule.kind, "definition": definition}
            if rule.note:
                out["note"] = rule.note
            return out
    for hint, stands_for in FAMILY_HINTS:
        if family and hint.lower() in family.lower():
            out = map_platform(stands_for, fidelity)
            return {**out, "note": f"mapped by family {family!r} (platform {platform!r} unknown)"}
    return {"kind": "unknown", "definition": None, "note": "no CML equivalent known for this platform"}


def _key(name: str) -> str:
    return name.strip().lower()


def _label(name: str, taken: set[str]) -> str:
    ipish = re.fullmatch(r"[\d.:]+", name.strip())
    first = name if ipish else name.split(".")[0]  # IP-named devices keep the whole address
    base = re.sub(r"[^A-Za-z0-9-]+", "-", first).strip("-").lower()[:30] or "node"
    label, n = base, 2
    while label in taken:
        label, n = f"{base}-{n}", n + 1
    taken.add(label)
    return label


def plan_replica(
    devices: list[dict[str, Any]],
    links: list[dict[str, Any]] | None = None,
    *,
    fidelity: Fidelity = "light",
    max_nodes: int | None = None,
    max_ram_gb: float | None = None,
    available: set[str] | None = None,
    priority: tuple[str, ...] = ("firewall", "router", "wlc", "switch", "manager", "aaa"),
) -> dict[str, Any]:
    """Pick CML nodes for `devices` ([{name, platform, role?, management_ip?}]) within the budget.
    Devices are kept by kind priority (firewalls, routers, WLCs, then switches) and then input order; the rest
    are listed under `dropped`. `links` ([{a, b}] by device name) are kept when both ends are kept."""
    taken: set[str] = set()
    mapped: list[tuple[int, dict[str, Any]]] = []
    gaps: list[tuple[int, dict[str, Any]]] = []
    duplicates: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for i, d in enumerate(devices):
        name = str(d.get("name") or d.get("hostname") or f"device-{i + 1}")
        if _key(name) in seen_names:  # e.g. the same firewall in the Catalyst Center and FMC lists
            duplicates.append(
                {"name": name, "platform": d.get("platform"), "why": "duplicate name (kept the first)"}
            )
            continue
        seen_names.add(_key(name))
        m = map_platform(str(d.get("platform") or d.get("model") or ""), fidelity, d.get("family"))
        definition = m["definition"]
        if definition and available is not None and definition not in available:
            m = {**m, "note": f"{definition} isn't installed on this controller", "definition": None}
            definition = None
        row = {"name": name, "platform": d.get("platform") or d.get("model"), **m}
        if d.get("role"):
            row["role"] = d["role"]
        if d.get("management_ip"):
            row["management_ip"] = d["management_ip"]
        (mapped if definition else gaps).append((i, row))
    order = {k: n for n, k in enumerate(priority)}
    mapped.sort(key=lambda t: (order.get(t[1]["kind"], len(order)), t[0]))
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    ram = 0
    for _, row in mapped:
        need = RAM_GB[row["definition"]]
        if (max_nodes is not None and len(kept) >= max_nodes) or (
            max_ram_gb is not None and ram + need > max_ram_gb
        ):
            # keeps going: a smaller, lower-priority device may still fit the RAM budget
            dropped.append({**row, "why": "over the node or RAM budget"})
            continue
        ram += need
        kept.append(row)
    for row in kept:
        row["label"] = _label(row["name"], taken)
    by_key: dict[str, str] = {}
    short: dict[str, list[str]] = {}
    for row in kept:
        by_key[_key(row["name"])] = row["label"]
        short.setdefault(_key(row["name"]).split(".")[0], []).append(row["label"])

    def endpoint(name: str) -> str | None:
        k = _key(name)
        if k in by_key:
            return by_key[k]
        hits = short.get(k.split(".")[0], [])  # 'core1' vs 'core1.site.lab'
        return hits[0] if len(hits) == 1 else None

    nodes = [
        {"label": row["label"], "definition": row["definition"], "tags": [row["kind"], "replica"]}
        for row in kept
    ]
    spec_links: list[str] = []
    unmatched: list[str] = []
    for lk in links or []:
        a, b = str(lk.get("a") or lk.get("source") or ""), str(lk.get("b") or lk.get("target") or "")
        la, lb = endpoint(a), endpoint(b)
        if la and lb and la != lb:
            spec_links.append(f"{la} {lb}")  # parallel links are kept: they are real cables
        else:
            unmatched += [n for n, lbl in ((a, la), (b, lb)) if not lbl]
    return {
        "fidelity": fidelity,
        "nodes": [{**row, "ram_gb": RAM_GB[row["definition"]]} for row in kept],
        "gaps": [row for _, row in gaps],
        "dropped": dropped + duplicates,
        "estimated_ram_gb": ram,
        "licensed_nodes": len(nodes),  # every mapped definition is a licensed node
        "build": {"nodes": nodes, "links": spec_links},  # parallel links are kept: they are real cables
        "links_skipped": len(links or []) - len(spec_links),
        "unmatched_link_ends": sorted(set(unmatched))[:50],  # dropped, gap or unknown devices
    }
