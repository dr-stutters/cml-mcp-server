"""Compare two CML topologies (parsed export YAML): nodes, interfaces, links and configs."""

from __future__ import annotations

import difflib
import re
from typing import Any, Literal

from cml_mcp._core import InvalidRequest
from cml_mcp.console import mask_secrets

NODE_FIELDS = ("node_definition", "image_definition", "ram", "cpus", "cpu_limit", "boot_disk_size", "tags")
MAX_CONFIG_DIFF_LINES = 80
MAX_SECTIONS = 100


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


def only_nodes(topology: dict[str, Any], labels: set[str]) -> dict[str, Any]:
    """`topology` with just the nodes labelled in `labels` and the links between them."""
    kept = [n for n in topology.get("nodes") or [] if str(n.get("label") or n.get("id")) in labels]
    ids = {str(n.get("id")) for n in kept}
    links = [lk for lk in topology.get("links") or [] if {str(lk.get("n1")), str(lk.get("n2"))} <= ids]
    return {**topology, "nodes": kept, "links": links}


def diff_topologies(
    a: dict[str, Any],
    b: dict[str, Any],
    *,
    include_configs: bool = True,
    a_name: str = "a",
    b_name: str = "b",
    semantic: bool = False,
    day0: Literal["a", "b"] | None = None,
    sections: bool = False,
    only: set[str] | None = None,
) -> dict[str, Any]:
    """`semantic`: compare configs by section (config_changes); `day0` names the side that holds
    stored day-0 configs while the other holds running configs (None: both alike, nothing hidden).
    `sections`: by section too, and each changed node gets `config_sections` (structured) instead of
    the `config_diff` text. `only`: compare just these node labels and the links between them."""
    if only is not None:
        a, b = only_nodes(a, only), only_nodes(b, only)
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
        if include_configs and (semantic or sections):
            # running vs stored configs (L27): only real changes, by section
            res = config_changes(
                _config(x),
                _config(y),
                a_name=f"{label} ({a_name})",
                b_name=f"{label} ({b_name})",
                day0=day0,
                max_lines=MAX_CONFIG_DIFF_LINES,
                structured=sections,
            )
            if not res["identical"] and sections:
                delta["config_sections"] = res["sections"]
                if res.get("sections_omitted"):
                    delta["config_sections_omitted"] = res["sections_omitted"]
            elif not res["identical"]:
                delta["config_diff"] = res["diff"]
        elif include_configs:
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
DOUBLE_MASK = re.compile(r"\*{8}(?: \*{8})+")
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
        out.append(DOUBLE_MASK.sub("********", MASKED_TYPE.sub(r"\1 \2", line)))
    return out


def _ignore_patterns(ignore: list[str] | None) -> list[re.Pattern[str]]:
    if len(ignore or []) > 20:
        raise InvalidRequest("ignore: at most 20 patterns")
    patterns = []
    for p in ignore or []:
        try:
            patterns.append(re.compile(p[:300]))
        except re.error as e:
            raise InvalidRequest(f"ignore: bad regular expression {p!r}: {e}") from e
    return patterns


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
    patterns = _ignore_patterns(ignore)

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


# --- section-aware "what changed" (L27) ------------------------------------------------------------
# Sections IOS / IOS-XE / IOL print in every running config by themselves, with the sub-lines they carry
# by default (None: none). Hidden only on the running side of a day-0 comparison, only when every
# sub-line is one of those defaults, and (for one-line sections) only when the day-0 side has no
# section starting with the same two words, so a changed value is always reported.
_DEFAULTS: list[tuple[str, str | None]] = [
    (r"version \S+", None),
    (r"service timestamps (?:debug|log) datetime msec", None),
    (r"boot-(?:start|end)-marker", None),
    (r"no aaa new-model|aaa session-id common", None),
    (r"ip cef|no ipv6 cef|ipv6 nd cache expire refresh", None),
    (r"login on-success log", None),
    (r"memory free low-watermark (?:processor|io) \d+", None),
    (r"spanning-tree mode rapid-pvst|spanning-tree extend system-id", None),
    (r"ip forward-protocol nd", None),
    (r"ip http server|ip http secure-server|ip http authentication local", None),
    (r"ip ssh bulk-mode \d+|no logging btrace", None),
    (r"multilink bundle-name authenticated|diagnostic bootup level minimal", None),
    (r"license udi .+|license boot level .+", None),
    (r"switch \d+ provision \S+|crypto engine compliance shield disable|subscriber templating", None),
    (r"ip dhcp pool webuidhcp|ip tcp mss 1280|ip tcp window-size 212000", None),
    (r"ip (?:tftp|http client) source-interface GigabitEthernet0/0", None),
    (r"control-plane", r"service-policy input system-cpp-policy"),
    (
        r"line (?:con|aux) 0|line vty \d+",
        r"activation-character 13|logging synchronous|stopbits 1|login|transport input ssh",
    ),
    (r"redundancy", r"mode sso"),
    (r"vrf definition Mgmt-vrf", r"address-family ipv[46](?: > exit-address-family)?|exit-address-family"),
    (
        r"crypto pki trustpoint (?:TP-self-signed-\d+|SLA-TrustPoint)",
        r"enrollment (?:selfsigned|pkcs12)|subject-name cn=IOS-Self-Signed-Certificate-\d+"
        r"|revocation-check (?:none|crl)|rsakeypair TP-self-signed-\d+|hash sha\d+",
    ),
    (
        r"crypto pki certificate chain (?:TP-self-signed-\d+|SLA-TrustPoint)",
        r"certificate (?:self-signed|ca) \S+(?: > .*)?|quit",
    ),
    (r"service-template DEFAULT_\S+", r"linksec policy (?:must|should)-secure|voice vlan"),
    (r"class-map match-any (?:system-cpp-\S+|non-client-nrt-class)", r"description .*|match .*"),
    (r"policy-map system-cpp-policy", r"class system-cpp-\S+(?: > .*)?"),
    (
        r"call-home",
        r'contact-email-addr sch-smart-licensing@cisco\.com|profile "CiscoTAC-1"'
        r"(?: > (?:active|destination transport-method http|reporting smart-licensing-data))?",
    ),
    (r"interface GigabitEthernet0/0", r"vrf forwarding Mgmt-vrf|ip address dhcp|negotiation auto"),
]
DEFAULT_SECTIONS = [(re.compile(k), re.compile(c) if c else None) for k, c in _DEFAULTS]
_WILDCARD = re.compile(r"\\[Sd]\+|\.\+")  # a pattern that accepts any value
# A physical interface (or the default Vlan1) left at its defaults; logical interfaces never are
UNUSED_INTERFACE = re.compile(r"^interface (?!(?:Loopback|Tunnel|Port-channel|BDI|Vlan(?!1$)|Virtual)).+")
UNUSED_INTERFACE_CHILDREN = {
    "no ip address",
    "shutdown",
    "negotiation auto",
    "no mop enabled",
    "no mop sysid",
}
# Sub-lines IOS adds to interfaces and lines by itself
INTERFACE_CHILD_DEFAULTS = {"negotiation auto", "no mop enabled", "no mop sysid"}
LINE_CHILD_DEFAULTS = {"stopbits 1", "activation-character 13"}
# Day-0 commands IOS acts on without keeping them (day-0 side only)
CONSUMED_DAY0 = re.compile(r"^(?:crypto key generate rsa.*|ip ssh version 2|vlan \d+(?:[-,]\d+)*|end)$")
CONSUMED_VLAN_CHILD = re.compile(r"^name \S+$")
# Commands IOS stores under another keyword
REWRITES = ((re.compile(r"^aaa accounting dot1x "), "aaa accounting identity "),)
# Sections whose lines are evaluated in order (ACLs, route policy, QoS)
ORDERED = re.compile(
    r"^(?:ip(?:v6)? access-list|access-list|mac access-list|route-map|policy-map|class-map"
    r"|ip(?:v6)? prefix-list|aaa group server|object-group|ip as-path access-list|ip community-list)\b"
)
# Numbered/one-line list entries: grouped into one ordered section per list
LIST_ENTRY = re.compile(
    r"^(access-list \S+|ip(?:v6)? prefix-list \S+|ip as-path access-list \S+"
    r"|ip community-list (?:standard |expanded )?\S+) (.+)$"
)
VTY = re.compile(r"^line vty (\d+)(?: (\d+))?$")


def _sections(lines: list[str]) -> dict[str, list[str]]:
    """{top-level line: its sub-lines as paths ('address-family ipv4 > neighbor x activate'), or a
    banner's body}. Numbered list entries are grouped per list; 'line vty 0 15' becomes one section
    per vty line ('line vty 0' ... 'line vty 15') so differently split ranges compare."""
    out: dict[str, list[str]] = {}
    keys: list[str] = []
    stack: list[tuple[int, str]] = []
    delim: str | None = None
    for line in lines:
        if delim is not None:
            for k in keys:
                out[k].append(line)
            if delim in line:
                delim = None
            continue
        indent = len(line) - len(line.lstrip())
        text = line.strip()
        if indent and keys:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            path = " > ".join([t for _, t in stack] + [text])
            stack.append((indent, text))
            for k in keys:
                out[k].append(path)
            continue
        stack = []
        for rx, repl in REWRITES:
            text = rx.sub(repl, text)
        if m := LIST_ENTRY.match(text):
            out.setdefault(m.group(1), []).append(m.group(2))
            keys = []
            continue
        if m := VTY.match(text):
            first = int(m.group(1))
            last = int(m.group(2) or first)
            keys = [f"line vty {i}" for i in range(first, min(last, first + 2047) + 1)]
        else:
            keys = [text]
        for k in keys:
            out.setdefault(k, [])
        if (b := BANNER_START.match(text)) and b.group(1) not in text[b.end(1) :]:
            delim = b.group(1)
    return out


def _default_section(key: str, children: list[str], day0_keys: dict[str, list[str]]) -> bool:
    """A section only the running side has that IOS printed by itself (see DEFAULT_SECTIONS). For a
    pattern that accepts any value ('license boot level .+'), a day-0 line with the same command but
    another value means the value was changed: not hidden."""
    if UNUSED_INTERFACE.match(key) and set(children) <= UNUSED_INTERFACE_CHILDREN:
        return True
    for rx, child_rx in DEFAULT_SECTIONS:
        if rx.fullmatch(key):
            if child_rx is not None:
                return all(child_rx.fullmatch(c) for c in children)
            if children:
                return False
            if _WILDCARD.search(rx.pattern):
                command = " ".join(key.split()[:3]) + " "
                return not any(k.startswith(command) for k in day0_keys)
            return True
    return False


def _consumed_section(key: str, children: list[str]) -> bool:
    """A section only the day-0 side has because IOS consumed it."""
    if not CONSUMED_DAY0.match(key):
        return False
    return not children or (key.startswith("vlan ") and all(CONSUMED_VLAN_CHILD.match(c) for c in children))


def _quiet_child(key: str, line: str, running_side: bool, both: set[str]) -> bool:
    """A sub-line one side has that isn't a change: IOS defaults on the running side, or day-0 lines
    it doesn't print ('no shutdown' while neither side has 'shutdown', the IBNS default host mode)."""
    if line == "exit-address-family" or line.endswith(" > exit-address-family"):
        return True
    if key.startswith("interface "):
        if running_side:
            return line in INTERFACE_CHILD_DEFAULTS
        return (
            line == "no shutdown" and "shutdown" not in both
        ) or line == "access-session host-mode multi-auth"
    if key.startswith("line ") and running_side:
        return line in LINE_CHILD_DEFAULTS
    return False


def _changed_children(key: str, old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    if ORDERED.match(key):  # order matters: a sequence diff
        added: list[str] = []
        removed: list[str] = []
        sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
        for op, i1, i2, j1, j2 in sm.get_opcodes():
            if op != "equal":
                removed += old[i1:i2]
                added += new[j1:j2]
        return added, removed
    old_s, new_s = set(old), set(new)  # IOS prints sub-lines in its own order
    return [c for c in dict.fromkeys(new) if c not in old_s], [
        c for c in dict.fromkeys(old) if c not in new_s
    ]


def _merge_vty(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Consecutive 'line vty N' entries with the same change become 'line vty A B'."""
    out: list[dict[str, Any]] = []
    run: list[tuple[int, dict[str, Any]]] = []

    def flush() -> None:
        if run:
            first, last = run[0][0], run[-1][0]
            body = {k: v for k, v in run[0][1].items() if k != "section"}
            out.append({"section": f"line vty {first}" + (f" {last}" if last != first else ""), **body})
            run.clear()

    for c in changes:
        m = VTY.match(c["section"])
        if m and m.group(2) is None:
            n = int(m.group(1))
            body = {k: v for k, v in c.items() if k != "section"}
            if (
                run
                and run[-1][0] == n - 1
                and {k: v for k, v in run[-1][1].items() if k != "section"} == body
            ):
                run.append((n, c))
                continue
            flush()
            run.append((n, c))
            continue
        flush()
        out.append(c)
    flush()
    return out


def config_changes(
    a_text: str,
    b_text: str,
    *,
    a_name: str,
    b_name: str,
    day0: Literal["a", "b"] | None = "a",
    ignore: list[str] | None = None,
    max_lines: int = 200,
    structured: bool = False,
) -> dict[str, Any]:
    """What changed between two configurations of a node, by section. Block order is ignored, and
    the order of sub-lines too except in ACLs, route maps, prefix lists and QoS policies. When one
    side is a stored day-0 config (`day0`), sections IOS printed by itself on the other (running)
    side and day-0 commands IOS consumed are hidden and listed in `hidden`. Secrets are masked on
    both sides, so a changed password with the same keyword is not a difference. `structured` adds
    `sections`: [{section, change: added|removed|modified, lines | added/removed}], MAX_SECTIONS at most."""
    patterns = _ignore_patterns(ignore)
    la, lb = normalise_config(a_text), normalise_config(b_text)

    def sections(lines: list[str]) -> dict[str, list[str]]:
        out = {}
        for k, children in _sections(lines).items():
            if not any(p.search(k) for p in patterns):
                out[k] = [c for c in children if not any(p.search(c) for p in patterns)]
        return out

    a, b = sections(la), sections(lb)
    hidden: list[str] = []
    hidden_lines = 0
    changes: list[dict[str, Any]] = []
    for key in [*a, *(k for k in b if k not in a)]:
        old, new = a.get(key), b.get(key)
        if old is None or new is None:  # a whole section on one side only
            side = "b" if old is None else "a"
            lines = (new if old is None else old) or []
            if day0 and (
                (side != day0 and _default_section(key, lines, a if day0 == "a" else b))
                or (side == day0 and _consumed_section(key, lines))
            ):
                hidden.append(key)
                hidden_lines += 1 + len(lines)
                continue
            change = "added" if old is None else "removed"
            changes.append({"section": key, "change": change, **({"lines": lines} if lines else {})})
            continue
        both = set(old) | set(new)
        added, removed = _changed_children(key, old, new)
        if day0:
            quiet_added = [c for c in added if _quiet_child(key, c, day0 == "a", both)]
            quiet_removed = [c for c in removed if _quiet_child(key, c, day0 == "b", both)]
            if quiet_added or quiet_removed:
                hidden_lines += len(quiet_added) + len(quiet_removed)
                hidden.extend(f"{key} > {c}" for c in [*quiet_added, *quiet_removed])
            added = [c for c in added if c not in quiet_added]
            removed = [c for c in removed if c not in quiet_removed]
        if added or removed:
            changes.append(
                {
                    "section": key,
                    "change": "modified",
                    **({"added": added} if added else {}),
                    **({"removed": removed} if removed else {}),
                }
            )
    changes = _merge_vty(changes)
    text: list[str] = []
    for c in changes:
        sign = {"added": "+", "removed": "-"}.get(c["change"], " ")
        text.append(f"{sign}{c['section']}")
        text += [f"{sign} {ln}" for ln in c.get("lines", [])]
        text += [f"+ {ln}" for ln in c.get("added", [])] + [f"- {ln}" for ln in c.get("removed", [])]
    shown_hidden = list(dict.fromkeys(re.sub(r"^line vty \d+", "line vty", h) for h in hidden))
    out: dict[str, Any] = {
        "identical": not changes,
        "lines_added": sum(1 for ln in text if ln.startswith("+")),
        "lines_removed": sum(1 for ln in text if ln.startswith("-")),
        "sections_changed": len(changes),
        "defaults_hidden": hidden_lines,
        "a_lines": len(la),
        "b_lines": len(lb),
    }
    if shown_hidden:
        out["hidden"] = shown_hidden[:12] + (
            [f"... {len(shown_hidden) - 12} more"] if len(shown_hidden) > 12 else []
        )
    if structured and changes:
        out["sections"] = changes[:MAX_SECTIONS]
        if len(changes) > MAX_SECTIONS:
            out["sections_omitted"] = len(changes) - MAX_SECTIONS
    if changes:
        if len(text) > max_lines:
            text = text[:max_lines] + [f"... {len(text) - max_lines} more lines (raise max_lines)"]
        out["diff"] = f"--- {a_name}\n+++ {b_name}\n" + "\n".join(text)
    return out
