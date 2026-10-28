"""cml_snapshot / cml_compare_snapshot (L69): the lab's own leg of a pre/post change check, on the core
snapshot contract (C53, docs/SNAPSHOTS.md in stutters-mcp-core).

Sections, from the REST API:
- `lab`: the lab's state.
- `nodes`: state per node (lab element state), with its boot time where the console tells it.
- `links`: state per link ('r1:Ethernet0/0<->r2:Ethernet0/0') and its conditioning (loss, latency).
- `addresses`: snooped IPv4 addresses of nodes the console pass does not read (hosts behind connectors).

Sections, from one console pass over the booted nodes (the same path as cml_run_commands):
- `addresses`: IPv4 per interface ('show ip interface brief', 'ip -4 -o addr', ...).
- `configs`: a hash of the masked, normalised running configuration (secrets never leave the device text
  unmasked, and lines that change on every read, such as 'ntp clock-period', are dropped first).
- `neighbours`: OSPF, BGP and EIGRP neighbours, one item each, with their state.
- `reachability` (probes='matrix'): the cml_check_reachability matrix, every source node to every target.
- `recipe` (probes='recipe'): the cml_verify_recipe checks of the recipe the lab was built from.

Counters, timers, uptimes and DR/BDR roles are left out, so two snapshots of an unchanged lab compare clean.
"""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import hashlib
import re
import time
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client, object_result
from cml_mcp._core.snapshot import BLOB_DOC, Metric, Snapshot, compare, parse
from cml_mcp.client import CmlApp
from cml_mcp.console import Credentials, read_only_problem
from cml_mcp.diff import normalise_config
from cml_mcp.licence import licensed
from cml_mcp.netops import (
    FTD_OS,
    Command,
    address_commands,
    console_batch,
    parse_addresses,
    ping_command,
    ping_result,
)
from cml_mcp.recipes import read_recipe_marker
from cml_mcp.tools.common import LabRef, Topo
from cml_mcp.tools.network import TARGET
from cml_mcp.verify import verify_recipe

PREFIX = "cml"
SERVER = "cml-mcp-server"
IOS_FAMILY = ("ios", "iosxe", "")
CONFIG_OS = ("ios", "iosxe", "nxos", "asa", "")
MAX_MATRIX = 20  # sources and targets, as cml_check_reachability
PING_COUNT = 3
COMMAND_TIMEOUT = 60.0
RUNNING = "show running-config"
OSPF = ("show ip ospf neighbor", "show ip ospf neighbors")
BGP = "show ip bgp summary"
EIGRP = "show ip eigrp neighbors"
OK_OSPF = ("FULL", "2WAY")
Probes = Literal["auto", "matrix", "recipe", "none"]
# console_batch's error for a node whose OS has no commands here (SD-WAN controllers, os 'sdwan'): not read,
# and not a console failure either
NO_COMMANDS = "no commands for this node type"


def _server_version() -> str | None:
    try:
        return version(SERVER)
    except PackageNotFoundError:  # pragma: no cover - source tree without an install
        return None


# --- parsers ---------------------------------------------------------------------------------------

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
_OSPF_ROW = re.compile(
    rf"^\s*(?P<id>{_IP})\s+\d+\s+(?P<state>[A-Z0-9-]+)(?:/\s*\S*)?\s+\S+\s+(?P<addr>{_IP})\s+(?P<iface>\S+)\s*$",
    re.M,
)
_BGP_ROW = re.compile(
    rf"^\s*(?P<peer>{_IP})\s+4\s+(?P<asn>\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+"
    r"(?P<state>\S+(?: \(Admin\))?)\s*$",
    re.M,
)
_EIGRP_ROW = re.compile(
    rf"^\s*\d+\s+(?P<addr>{_IP})\s+(?P<iface>\S+)\s+\d+\s+\S+\s+\d+\s+\d+\s+\d+\s+\d+\s*$", re.M
)


def ospf_neighbours(output: str) -> list[dict[str, str]]:
    """[{id, state, address, interface}] from IOS 'show ip ospf neighbor' / NX-OS 'show ip ospf
    neighbors'; the state without its DR/BDR role ('FULL/DR' -> 'FULL'), which changes on re-election."""
    return [
        {"id": m["id"], "state": m["state"], "address": m["addr"], "interface": m["iface"]}
        for m in _OSPF_ROW.finditer(output.replace("\r", ""))
    ]


def bgp_neighbours(output: str) -> list[dict[str, str]]:
    """[{peer, asn, state}] from 'show ip bgp summary' (IOS and NX-OS): a number in State/PfxRcd means
    Established."""
    out = []
    for m in _BGP_ROW.finditer(output.replace("\r", "")):
        state = m["state"]
        out.append({"peer": m["peer"], "asn": m["asn"], "state": "Established" if state.isdigit() else state})
    return out


def eigrp_neighbours(output: str) -> list[dict[str, str]]:
    """[{address, interface}] from 'show ip eigrp neighbors' (every listed neighbour is up)."""
    return [
        {"address": m["addr"], "interface": m["iface"]} for m in _EIGRP_ROW.finditer(output.replace("\r", ""))
    ]


_UNITS = {"year": 365 * 86400, "week": 7 * 86400, "day": 86400, "hour": 3600, "minute": 60, "second": 1}
_IOS_UPTIME = re.compile(r"uptime is (?P<text>[^\r\n]+)")
_UNIX_UPTIME = re.compile(
    r"\bup\s+(?:(?P<days>\d+)\s+days?,\s*)?(?:(?P<h>\d+):(?P<m>\d+)|(?P<min>\d+)\s+min)"
)


def uptime_seconds(output: str) -> int | None:
    """Seconds since boot from IOS/NX-OS 'show version' ('uptime is 1 day, 2 hours, 3 minutes') or
    Linux 'uptime' (' 10:01:02 up 3 days,  2:05,  1 user, ...' / 'up 5 min')."""
    if m := _IOS_UPTIME.search(output):
        total = 0
        for n, unit in re.findall(r"(\d+)\s+(year|week|day|hour|minute|second)s?", m["text"]):
            total += int(n) * _UNITS[unit]
        return total if total or "minute" in m["text"] or "second" in m["text"] else None
    if m2 := _UNIX_UPTIME.search(output):
        days = int(m2["days"] or 0)
        minutes = int(m2["min"]) if m2["min"] else int(m2["h"] or 0) * 60 + int(m2["m"] or 0)
        return days * 86400 + minutes * 60
    return None


def config_hash(output: str) -> str | None:
    """Short sha256 of a running configuration after masking secrets and dropping per-read noise."""
    lines = normalise_config(output)
    if len(lines) < 3:  # an error or an empty answer, not a configuration
        return None
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()[:12]


# --- console plan ----------------------------------------------------------------------------------


def node_commands(cred: Credentials) -> list[Command]:
    """What the snapshot runs on one node, by its OS (pyATS testbed)."""
    os_name = (cred.os or "").lower()
    cmds: list[Command] = list(address_commands(os_name))
    if os_name in FTD_OS:
        return cmds
    if os_name == "linux":
        return [*cmds, "uptime"]
    if os_name in ("ios", "iosxe", "nxos", ""):
        cmds.append("show version | include uptime")
    if os_name in CONFIG_OS:
        cmds.append(RUNNING)
    if os_name in IOS_FAMILY:
        cmds += [OSPF[0], BGP, EIGRP]
    elif os_name == "nxos":
        cmds += [OSPF[1], BGP, EIGRP]
    return cmds


def _label(node: dict[str, Any]) -> str:
    return str(node.get("label"))


def _add(sec: Any, key: str, **fields: Any) -> None:
    """Section.item, keeping the first of two rows with the same key (a peer listed twice)."""
    if key[:200] not in sec.items:
        sec.item(key[:200], **fields)


# --- the snapshot ----------------------------------------------------------------------------------


async def take_snapshot(
    app: CmlApp,
    lab: str,
    *,
    probes: Probes = "auto",
    nodes: list[str] | None = None,
    targets: list[str] | None = None,
) -> Snapshot:
    """Build the snapshot of `lab` (see the module docstring). `nodes` narrows the console pass and the
    matrix sources; `targets` are the matrix targets (default: every loopback address the pass finds)."""
    for t in targets or []:
        if not TARGET.fullmatch(t):
            raise InvalidRequest(f"Not an IP address or hostname: {t!r}")
    info = await app.resolve_lab(lab)
    lid = info["id"]
    title = str(info.get("lab_title") or lid)
    notes = (
        info.get("lab_notes") if "lab_notes" in info else (await app.api.get(f"/labs/{lid}")).get("lab_notes")
    )
    marker = read_recipe_marker(notes)

    all_nodes = await app.list_nodes(lid)
    links = await app.list_links(lid)
    interfaces = await app.list_interfaces(lid, operational=False)
    topo = Topo({n["id"]: n for n in all_nodes}, {i["id"]: i for i in interfaces}, links)
    by_label = {_label(n): n for n in all_nodes}
    if nodes:
        unknown = [n for n in nodes if n not in by_label]
        if unknown:
            raise InvalidRequest(f"No node labelled {unknown} in {title!r} (see cml_list_nodes)")

    snap = Snapshot(
        PREFIX,
        SERVER,
        scope={
            "lab": title,
            "probes": probes,
            "nodes": ",".join(nodes or []) or None,
            "targets": ",".join(targets or []) or None,
        },
        server_version=_server_version(),
        instance=urlparse(str(app.settings.url)).hostname,
    )
    lab_sec = snap.section("lab", "Lab")
    node_sec = snap.section(
        "nodes", "Nodes", metrics={"booted_at_min": Metric("lower", tolerance=5)}, max_items=200
    )
    link_sec = snap.section(
        "links",
        "Links",
        metrics={"loss_pct": Metric("lower", limit=5.0), "latency_ms": Metric("lower", tolerance=5)},
        max_items=200,
    )
    addr_sec = snap.section("addresses", "IPv4 addresses", max_items=300)
    cfg_sec = snap.section("configs", "Running configurations", max_items=200)
    nbr_sec = snap.section("neighbours", "Routing neighbours", max_items=300)

    # --- REST: lab, node and link state, conditioning -------------------------------------------
    lab_state = str(info.get("state") or "")
    lab_sec.item("lab", ok=lab_state == "STARTED", state=lab_state, label=title)
    try:
        element = await app.api.get(f"/labs/{lid}/lab_element_state") or {}
    except UpstreamError as e:
        element = {}
        node_sec.fail(f"lab element state: {e}")
        link_sec.fail(f"lab element state: {e}")
    node_states: dict[str, str] = element.get("nodes") or {}
    link_states: dict[str, str] = element.get("links") or {}
    for n in all_nodes:
        n["state"] = node_states.get(n["id"], n.get("state"))
    try:
        topology = await app.api.get(f"/labs/{lid}/topology", {"exclude_configurations": "true"}) or {}
        conditioning = {lk.get("id"): lk.get("conditioning") or {} for lk in topology.get("links") or []}
    except UpstreamError as e:
        conditioning = {}
        link_sec.fail(f"link conditioning: {e}")
    for lk in links:
        state = str(link_states.get(lk["id"], lk.get("state")))
        cond = conditioning.get(lk["id"]) or {}
        on = bool(cond.get("enabled"))
        link_sec.item(
            f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}",
            ok=state == "STARTED" if lab_state == "STARTED" else None,
            state=state,
            loss_pct=float(cond.get("loss") or 0) if on else 0,
            latency_ms=float(cond.get("latency") or 0) if on else 0,
        )

    # --- console pass ----------------------------------------------------------------------------
    wanted = set(nodes) if nodes else None
    console_nodes = [
        n
        for n in all_nodes
        if licensed(n) and n.get("state") == "BOOTED" and (wanted is None or _label(n) in wanted)
    ]
    now = time.time()
    booted_at: dict[str, int] = {}
    loopbacks: list[str] = []
    os_of: dict[str, str] = {}
    read_by_cli: set[str] = set()
    failed: list[str] = []
    batch = (
        await console_batch(
            app,
            lid,
            console_nodes,
            lambda _n, cred: node_commands(cred),
            timeout=COMMAND_TIMEOUT,
            purpose="cml_snapshot",
        )
        if console_nodes
        else []
    )
    for res in batch:
        label = str(res["node"])
        os_of[label] = str(res.get("os") or "")
        if res.get("error"):
            if not str(res["error"]).startswith(NO_COMMANDS):
                failed.append(f"{label}: {res['error'][:120]}")
            continue
        read_by_cli.add(label)
        for o in res.get("outputs") or []:
            cmd, text = o.get("command"), o.get("output")
            if text is None:
                failed.append(f"{label}: {cmd}: {str(o.get('error'))[:80]}")
                continue
            if cmd == RUNNING:
                if (h := config_hash(text)) is not None:
                    _add(cfg_sec, label, sha=h)
            elif cmd in ("show version | include uptime", "uptime"):
                if (up := uptime_seconds(text)) is not None:
                    booted_at[label] = int((now - up) / 60)
            elif cmd in OSPF:
                for r in ospf_neighbours(text):
                    _add(
                        nbr_sec,
                        f"{label}|ospf|{r['id']}|{r['interface']}",
                        ok=r["state"] in OK_OSPF,
                        state=r["state"],
                        address=r["address"],
                    )
            elif cmd == BGP:
                for r in bgp_neighbours(text):
                    _add(
                        nbr_sec,
                        f"{label}|bgp|{r['peer']}",
                        ok=r["state"] == "Established",
                        state=r["state"],
                        asn=r["asn"],
                    )
            elif cmd == EIGRP:
                for r in eigrp_neighbours(text):
                    _add(
                        nbr_sec,
                        f"{label}|eigrp|{r['address']}",
                        ok=True,
                        state="up",
                        interface=r["interface"],
                    )
            elif isinstance(cmd, str):
                for row in parse_addresses(cmd, text):
                    _add(addr_sec, f"{label}:{row['interface']}", state=row["ipv4"])
                    if row["interface"].lower().startswith("loopback"):
                        loopbacks.append(row["ipv4"].split("/")[0])
    if failed:
        # a node the pass could not read would show its neighbours and addresses as gone: say so instead
        why = "console failed on " + "; ".join(failed)
        for sec in (addr_sec, cfg_sec, nbr_sec):
            sec.fail(why)

    for n in all_nodes:
        label = _label(n)
        state = str(n.get("state"))
        node_sec.item(
            label,
            ok=state == "BOOTED" if lab_state == "STARTED" else None,
            state=state,
            definition=str(n.get("node_definition")),
            booted_at_min=booted_at.get(label),
        )

    # snooped addresses of nodes the console did not read (hosts behind external connectors, servers)
    try:
        snooped = await app.api.get(f"/labs/{lid}/layer3_addresses") or {}
    except UpstreamError:
        snooped = {}
    if isinstance(snooped, dict):
        for nid, entry in snooped.items():
            label = str((entry or {}).get("name") or topo.node_label(nid))
            if label in read_by_cli or (wanted is not None and label not in wanted):
                continue
            for iface in ((entry or {}).get("interfaces") or {}).values():
                for ip in iface.get("ip4") or []:
                    _add(addr_sec, f"{label}:{iface.get('label')}", state=str(ip))

    # --- probes ----------------------------------------------------------------------------------
    mode = probes
    if mode == "auto":
        mode = "recipe" if marker else ("matrix" if (targets or loopbacks) else "none")
    if mode == "recipe":
        rec = snap.section("recipe", "Recipe verify checks", max_items=200)
        if not marker:
            rec.fail(f"{title!r} was not built from a recipe (no recipe marker in its notes)")
        else:
            try:
                result = await verify_recipe(app, marker["recipe"], lab=title)
            except (UpstreamError, InvalidRequest) as e:
                rec.fail(f"recipe {marker['recipe']!r}: {e}")
            else:
                for c in result.get("checks") or []:
                    _add(rec, str(c.get("name")), ok=bool(c.get("ok")), state=str(c.get("kind") or ""))
    elif mode == "matrix":
        readable = [n for n in console_nodes if _label(n) in read_by_cli]
        await _matrix(app, lid, snap, readable, os_of, targets, loopbacks)
    return snap


async def _matrix(
    app: CmlApp,
    lid: str,
    snap: Snapshot,
    console_nodes: list[dict[str, Any]],
    os_of: dict[str, str],
    targets: list[str] | None,
    loopbacks: list[str],
) -> None:
    sec = snap.section("reachability", "Reachability (ping matrix)", max_items=400)
    to = list(dict.fromkeys(targets or loopbacks))[:MAX_MATRIX]
    own: dict[str, set[str]] = {}  # a node does not ping its own addresses
    for key, item in snap.sections["addresses"].items.items():
        state = item.get("state")
        if isinstance(state, str):
            own.setdefault(key.partition(":")[0], set()).add(state.split("/")[0])
    sources = [
        n
        for n in console_nodes
        if os_of.get(_label(n), "").lower() != "asa" and set(to) - own.get(_label(n), set())
    ][:MAX_MATRIX]
    if not to or not sources:
        sec.fail("no targets (no loopback addresses found; pass targets) or no booted source nodes")
        return

    def commands(node: dict[str, Any], cred: Credentials) -> list[Command]:
        cmds: list[Command] = []
        mine = own.get(_label(node), set())
        for t in to:
            if t in mine:
                continue
            cmd, interrupt = ping_command(cred.os, t, PING_COUNT)
            if problem := read_only_problem(cmd):  # generated commands must pass the read-tier allow-list
                raise InvalidRequest(f"{cmd!r}: {problem}")
            cmds.append((cmd, interrupt))
        return cmds

    failed: list[str] = []
    batch = await console_batch(
        app, lid, sources, commands, timeout=15 + 3 * PING_COUNT, purpose="cml_snapshot"
    )
    for res in batch:
        label = str(res["node"])
        if res.get("error"):
            failed.append(f"{label}: {res['error'][:120]}")
            continue
        pinged = [t for t in to if t not in own.get(label, set())]
        for target, out in zip(pinged, res.get("outputs") or [], strict=False):
            verdict = ping_result(out["output"]) if "output" in out else {"ok": False}
            sec.item(f"{label}->{target}", ok=bool(verdict.get("ok")))
    if failed:
        sec.fail("console failed on " + "; ".join(failed))


# --- tools -----------------------------------------------------------------------------------------

ProbesArg = Annotated[
    Probes,
    Field(
        description="Reachability to record: 'matrix' (ping every target from every source node, as "
        "cml_check_reachability), 'recipe' (the cml_verify_recipe checks of the recipe the lab was built "
        "from), 'none', or 'auto' (recipe when the lab has one, else a matrix of the loopbacks found)"
    ),
]
NodesArg = Annotated[
    list[str] | None,
    Field(
        max_length=40,
        description="Only these node labels in the console pass and as matrix sources (default: every "
        "booted node)",
    ),
]
TargetsArg = Annotated[
    list[str] | None,
    Field(
        max_length=MAX_MATRIX,
        description="Matrix targets, IP addresses or hostnames (default: the loopback addresses found)",
    ),
]


def _split(value: Any) -> list[str] | None:
    return [v for v in str(value).split(",") if v] if value else None


# TODO(core): suite_change_check has no cml leg yet (CORE-REQUESTS.md, r96 L69); until core adds one, these
# tools run beside the prompt rather than from it.
def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Lab snapshot", idempotent=False, task=True)
    async def cml_snapshot(
        ctx: Context,
        lab: LabRef,
        probes: ProbesArg = "auto",
        nodes: NodesArg = None,
        targets: TargetsArg = None,
    ) -> ToolResult:
        """Take a compact, versioned snapshot of a running lab for a pre/post change check (core snapshot
        contract): node states and boot times, link states and conditioning, IPv4 addresses per
        interface, a hash of each node's masked running configuration, OSPF/BGP/EIGRP neighbours, and
        a reachability matrix or the lab recipe's verify checks. Reads only, through the REST API and
        the node consoles (as cml_run_commands). Returns a JSON blob to keep in the conversation and
        pass, unchanged, to cml_compare_snapshot after the change; nothing is stored on the server.
        Counters, timers and DR/BDR roles are left out, so an unchanged lab compares clean. Across
        products: prompt suite_change_check."""
        app: CmlApp = get_client(ctx)
        snap = await take_snapshot(app, lab, probes=probes, nodes=nodes, targets=targets)
        return object_result(snap.blob(), shape=False)

    @reg.read(title="Compare lab snapshots", idempotent=False, task=True)
    async def cml_compare_snapshot(
        ctx: Context,
        before: Annotated[str | dict[str, Any], Field(description=BLOB_DOC.format(prefix=PREFIX))],
        after: Annotated[
            str | dict[str, Any] | None,
            Field(description=BLOB_DOC.format(prefix=PREFIX) + "; empty = take one now"),
        ] = None,
    ) -> ToolResult:
        """Compare a cml_snapshot blob from before a change with one from after it (or, when `after` is
        empty, a fresh snapshot of the same lab with the same probes, nodes and targets, taken now) and
        name what changed, most severe first: major = got unhealthy (a link or node down, a routing
        neighbour lost or not FULL/Established, a reachability pair failing, a recipe check failing),
        minor = changed but not clearly bad (an address, a running configuration, a reboot), info =
        recovered. Unchanged items are only counted."""
        b = parse(before, prefix=PREFIX, what="before")
        if after in (None, "", {}):
            scope = b.get("scope") or {}
            if not scope.get("lab"):
                raise InvalidRequest("before has no lab in its scope; pass `after` too")
            probes = str(scope.get("probes") or "auto")
            if probes not in ("auto", "matrix", "recipe", "none"):
                raise InvalidRequest(f"before has an unknown probes value {probes!r}")
            app: CmlApp = get_client(ctx)
            a: Any = (
                await take_snapshot(
                    app,
                    str(scope["lab"]),
                    probes=probes,  # type: ignore[arg-type]
                    nodes=_split(scope.get("nodes")),
                    targets=_split(scope.get("targets")),
                )
            ).blob()
        else:
            a = parse(after, prefix=PREFIX, what="after")
        return object_result(compare(b, a, prefix=PREFIX))
