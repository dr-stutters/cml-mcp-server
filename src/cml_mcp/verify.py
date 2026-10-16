"""Recipe verification: run a recipe's `verify:` contract against its running lab.

A contract (in the recipe YAML) lists what a known-good lab looks like:

    verify:
      booted: [sw1, client]              # default: every licensed node in the recipe
      nodes: [sw1]                       # ping sources ...
      targets: [198.18.128.1, ...]       # ... and targets (vrf: optional)
      addresses: {sw1: [198.18.128.154]} # addresses each node must have (from its CLI)
      probes:
        - {name: radius-server-up, node: sw1, command: "show aaa servers", expect: "current UP"}
        - {name: netconf, tcp: "198.18.128.152:830"}
        - {name: snmp, snmp: {host: 198.18.128.152, community: ${LAB_SNMP_RO}}}
        - {name: ise-session, ise_session: {url: https://198.18.134.35, username: ${LAB_ISE_USERNAME},
           password: ${LAB_ISE_PASSWORD}, user: '^mcp-alice$', nas_ip: 198.18.128.194}}

Console probes run commands written in the packaged recipe (never caller input) over the node's
console; tcp, snmp and ise_session probes run from the MCP server's host, like the product server would
(ise_session reads ISE's live sessions from MnT: proof that ISE itself authenticated the user).
Every check is pass/fail with a short detail; nothing in the lab is changed.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from stutters_mcp_core import InvalidRequest, UpstreamError

from cml_mcp.build import VSWITCH_FILE, is_cat9kv, serial_of
from cml_mcp.client import CmlApp
from cml_mcp.console import FORBIDDEN_CHARS, Credentials, mask_secrets, read_only_problem
from cml_mcp.netops import (
    Command,
    address_commands,
    console_batch,
    parse_addresses,
    ping_command,
    ping_result,
)
from cml_mcp.recipes import (
    get_recipe,
    read_recipe_marker,
    redact_values,
    resolve_secrets,
    secret_names_by_value,
    substituted,
)

TCP_TARGET = re.compile(r"^(?P<host>[A-Za-z0-9.:-]+):(?P<port>\d{1,5})$")


class SnmpProbe(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)  # resolved ${LAB_*} values

    host: str
    community: str
    port: int = 161


class IseSessionProbe(BaseModel):
    """A live ISE session (MnT ActiveList) whose user matches `user` (regex), optionally from NAS `nas_ip`
    and with a framed IP matching `framed_ip` (regex)."""

    model_config = ConfigDict(hide_input_in_errors=True)  # resolved ${LAB_*} values

    url: str = Field(description="ISE base URL, https://host[:port]")
    username: str
    password: str = Field(repr=False)
    user: str = Field(description="regex the session's user name must match")
    nas_ip: str | None = None
    framed_ip: str | None = Field(default=None, description="regex the session's framed IP must match")
    verify_tls: bool = True

    @model_validator(mode="after")
    def _check(self) -> IseSessionProbe:
        u = urlsplit(self.url)
        if u.scheme != "https" or not u.hostname or u.path not in ("", "/") or u.query or u.username:
            raise ValueError("ise_session url must be https://host[:port]")
        for rx in (self.user, self.framed_ip):
            if rx:
                re.compile(rx)
        return self

    @property
    def host(self) -> str:
        return str(urlsplit(self.url).hostname)


# Console probes run outside the read-tier allow-list (they come only from packaged recipes), but
# they must still be read-only or one of these known side-effect-free tests.
PROBE_COMMAND_PREFIXES = (
    "test aaa group radius ",  # sends one RADIUS request, changes no config
    "mcp-check ",  # read-only check script a recipe installs on its Linux nodes (ise-fmc-identity)
)


class Probe(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)  # resolved ${LAB_*} values

    name: str
    node: str | None = None
    command: str | None = None
    expect: str | None = Field(default=None, description="regex the console output must match")
    reject: str | None = Field(default=None, description="regex the console output must not match")
    timeout: float = Field(default=60, gt=0, le=600)
    interrupt_after: float | None = None
    tcp: str | None = None
    snmp: SnmpProbe | None = None
    ise_session: IseSessionProbe | None = None

    @model_validator(mode="after")
    def _check(self) -> Probe:
        actions = [a for a in (self.command, self.tcp, self.snmp, self.ise_session) if a]
        if len(actions) != 1:
            raise ValueError(f"probe {self.name!r}: give exactly one of command, tcp, snmp, ise_session")
        if self.command:
            if not self.node:
                raise ValueError(f"probe {self.name!r}: a command needs a node")
            prefixed = self.command.startswith(PROBE_COMMAND_PREFIXES)
            if read_only_problem(self.command) and not prefixed:
                raise ValueError(f"probe {self.name!r}: {self.command!r} is not a read-only command")
            if prefixed and "|" in self.command:
                raise ValueError(f"probe {self.name!r}: no '|' after a probe-only command")
            if any(ch in FORBIDDEN_CHARS for ch in self.command):  # also for the allowed prefixes
                raise ValueError(f"probe {self.name!r}: control or shell characters in {self.command!r}")
        if self.tcp:
            m = TCP_TARGET.fullmatch(self.tcp)
            if not m or not 1 <= int(m["port"]) <= 65535:
                raise ValueError(f"probe {self.name!r}: tcp must be host:port")
        for rx in (self.expect, self.reject):
            if rx:
                try:
                    re.compile(rx)
                except re.error as e:
                    raise ValueError(f"probe {self.name!r}: bad regex {rx!r}: {e}") from e
        return self


class Contract(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)  # resolved ${LAB_*} values

    booted: list[str] | None = None
    nodes: list[str] = []
    targets: list[str] = []
    vrf: str | None = None
    count: int = 3
    addresses: dict[str, list[str]] = {}
    probes: list[Probe] = []


def contract_of(recipe: dict[str, Any]) -> Contract:
    try:
        return Contract.model_validate(recipe.get("verify") or {})
    except ValidationError as e:
        raise ValueError(f"recipe {recipe.get('name')!r}: invalid verify contract: {e}") from e


def check(name: str, kind: str, ok: bool, detail: Any = None) -> dict[str, Any]:
    out: dict[str, Any] = {"check": name, "kind": kind, "ok": ok}
    if detail not in (None, "", [], {}):
        out["detail"] = detail
    return out


# --- probes from the server host ------------------------------------------------------------


async def tcp_probe(target: str, timeout: float = 5.0) -> tuple[bool, str]:  # noqa: ASYNC109
    m = TCP_TARGET.fullmatch(target)
    if not m:
        return False, f"bad tcp target {target!r} (host:port)"
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(m["host"], int(m["port"])), timeout)
    except (OSError, TimeoutError, ValueError) as e:
        return False, f"{target} not reachable: {type(e).__name__} {e}".strip()
    writer.close()
    with contextlib.suppress(OSError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 2)
    return True, f"{target} accepts TCP connections"


def _ber_len(n: int) -> bytes:
    return bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xFF])


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


SYSNAME_OID = bytes([0x2B, 6, 1, 2, 1, 1, 5, 0])  # 1.3.6.1.2.1.1.5.0


SNMP_REQUEST_ID = 0x4D43


def snmp_get_sysname_request(community: str, request_id: int = SNMP_REQUEST_ID) -> bytes:
    varbind = _tlv(0x30, _tlv(0x06, SYSNAME_OID) + b"\x05\x00")
    pdu = _tlv(
        0xA0, _tlv(0x02, request_id.to_bytes(2, "big")) + b"\x02\x01\x00\x02\x01\x00" + _tlv(0x30, varbind)
    )
    return _tlv(0x30, b"\x02\x01\x01" + _tlv(0x04, community.encode()) + pdu)


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """(tag, value, next position) of the BER TLV at `pos`; ValueError if it doesn't fit."""
    if pos + 2 > len(data):
        raise ValueError("truncated")
    tag, ln = data[pos], data[pos + 1]
    pos += 2
    if ln & 0x80:
        nbytes = ln & 0x7F
        if not 1 <= nbytes <= 2 or pos + nbytes > len(data):
            raise ValueError("bad length")
        ln = int.from_bytes(data[pos : pos + nbytes], "big")
        pos += nbytes
    if pos + ln > len(data):
        raise ValueError("value runs past the end")
    return tag, data[pos : pos + ln], pos + ln


def snmp_sysname_from_response(data: bytes, request_id: int = SNMP_REQUEST_ID) -> str | None:
    """The sysName from an SNMPv2c GetResponse to our request, or None if it isn't one (checked:
    SEQUENCE, version, community, GetResponse PDU, request id, error-status 0, the OID, a string)."""
    try:
        tag, msg, _ = _read_tlv(data, 0)
        if tag != 0x30:
            return None
        tag, version, pos = _read_tlv(msg, 0)
        tag2, _community, pos = _read_tlv(msg, pos)
        if tag != 0x02 or version != b"\x01" or tag2 != 0x04:
            return None
        tag, pdu, _ = _read_tlv(msg, pos)
        if tag != 0xA2:
            return None
        tag, rid, pos = _read_tlv(pdu, 0)
        if tag != 0x02 or int.from_bytes(rid, "big") != request_id:
            return None
        tag, err, pos = _read_tlv(pdu, pos)
        if tag != 0x02 or int.from_bytes(err, "big") != 0:
            return None
        _, _, pos = _read_tlv(pdu, pos)  # error-index
        _, varbinds, _ = _read_tlv(pdu, pos)
        _, varbind, _ = _read_tlv(varbinds, 0)
        tag, oid, pos = _read_tlv(varbind, 0)
        if tag != 0x06 or oid != SYSNAME_OID:
            return None
        tag, value, _ = _read_tlv(varbind, pos)
        if tag != 0x04:  # noSuchObject (0x80) etc.
            return None
        return value.decode("utf-8", "replace")
    except ValueError:
        return None


async def snmp_probe(p: SnmpProbe, timeout: float = 4.0) -> tuple[bool, str]:  # noqa: ASYNC109
    loop = asyncio.get_running_loop()
    got: asyncio.Future[bytes] = loop.create_future()

    class Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: Any) -> None:
            if not got.done():
                got.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not got.done():
                got.set_exception(exc)

    try:
        transport, _ = await loop.create_datagram_endpoint(Proto, remote_addr=(p.host, p.port))
    except OSError as e:
        return False, f"snmp {p.host}: {e}"
    try:
        for _ in range(2):  # one retry: UDP
            transport.sendto(snmp_get_sysname_request(p.community))
            try:
                data = await asyncio.wait_for(asyncio.shield(got), timeout / 2)
                name = snmp_sysname_from_response(data)
                return (True, f"sysName {name!r}") if name is not None else (False, "unexpected SNMP reply")
            except TimeoutError:
                continue
            except OSError as e:
                return False, f"snmp {p.host}: {e}"
        return False, f"no SNMP reply from {p.host}:{p.port} (community wrong or agent off)"
    finally:
        transport.close()
        if got.done() and not got.cancelled():
            got.exception()  # retrieved, so asyncio doesn't log it


MNT_ACTIVE_LIST = "/admin/API/mnt/Session/ActiveList"
MAX_MNT_BYTES = 4_000_000


def active_sessions(xml_text: str) -> list[dict[str, str]]:
    """ISE MnT ActiveList XML -> [{user_name, calling_station_id, nas_ip_address, framed_ip_address, ...}]."""
    root = ET.fromstring(xml_text)
    return [
        {child.tag: (child.text or "").strip() for child in s}
        for s in root.iter()
        if s.tag.endswith("activeSession")
    ]


async def ise_session_probe(p: IseSessionProbe, timeout: float = 20.0) -> tuple[bool, Any]:  # noqa: ASYNC109
    try:
        async with (
            httpx.AsyncClient(verify=p.verify_tls, timeout=timeout, follow_redirects=False) as client,
            client.stream(
                "GET",
                p.url.rstrip("/") + MNT_ACTIVE_LIST,
                auth=httpx.BasicAuth(p.username, p.password),
                headers={"Accept": "application/xml"},
            ) as r,
        ):
            if r.status_code in (401, 403):
                return False, f"ISE MnT refused the API login (HTTP {r.status_code})"
            if r.status_code != 200:
                return False, f"ISE MnT answered HTTP {r.status_code}"
            body = bytearray()
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_MNT_BYTES:
                    return False, "ISE MnT active list too large to check"
    except httpx.HTTPError as e:
        return False, f"ISE MnT at {p.host} not reachable: {type(e).__name__}"
    text = body.decode("utf-8", "replace")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:  # MnT never sends them; refuse entity tricks
        return False, "ISE MnT answered XML with a DOCTYPE/ENTITY; not parsed"
    try:
        sessions = active_sessions(text)
    except ET.ParseError:
        return False, "ISE MnT answered something that is not its session XML"
    from_nas = [s for s in sessions if not p.nas_ip or s.get("nas_ip_address") == p.nas_ip]
    users = [s for s in from_nas if re.search(p.user, s.get("user_name", ""))]
    matches = [s for s in users if not p.framed_ip or re.search(p.framed_ip, s.get("framed_ip_address", ""))]

    def row(s: dict[str, str]) -> dict[str, str]:
        keys = ("user_name", "calling_station_id", "framed_ip_address", "nas_ip_address")
        return {k: s[k] for k in keys if s.get(k)}

    if matches:
        return True, {"sessions": [row(s) for s in matches[:5]]}
    where = f" from NAS {p.nas_ip}" if p.nas_ip else ""
    if users:
        return False, {
            "problem": f"session{where} for the user, but its framed IP does not match {p.framed_ip!r} "
            "(no device tracking / accounting yet?)",
            "sessions": [row(s) for s in users[:5]],
        }
    return False, {
        "problem": f"no live ISE session{where} with a user matching {p.user!r}",
        "users_seen": sorted({s.get("user_name", "") for s in from_nas})[:10],
        "active_sessions": len(sessions),
    }


# --- cat9000v serials ----------------------------------------------------------------------------

DEFAULT_CAT9KV_SERIAL = "CMLUADP"  # what conf/vswitch.xml holds unless a recipe or build sets one


async def node_serial(app: CmlApp, lab_id: str, node: dict[str, Any]) -> str:
    full = await app.api.get(f"/labs/{lab_id}/nodes/{node['id']}")
    cfg = full.get("configuration") if isinstance(full, dict) else None
    for f in cfg if isinstance(cfg, list) else []:
        if isinstance(f, dict) and f.get("name") == VSWITCH_FILE:
            return serial_of(str(f.get("content") or "")) or DEFAULT_CAT9KV_SERIAL
    return DEFAULT_CAT9KV_SERIAL


async def cat9kv_serial_checks(app: CmlApp, lab_id: str, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Catalyst Center keys devices by serial: every cat9000v in this lab needs its own, also against the
    cat9000v running in other labs (one CatC may discover them all)."""
    mine = [n for n in nodes if is_cat9kv(str(n.get("node_definition") or ""))]
    if not mine:
        return []
    serials = {str(n.get("label")): await node_serial(app, lab_id, n) for n in mine}
    by_serial: dict[str, list[str]] = {}
    for label, s in serials.items():
        by_serial.setdefault(s, []).append(label)
    problems = [f"{', '.join(labels)} share serial {s}" for s, labels in by_serial.items() if len(labels) > 1]
    elsewhere: list[str] = []
    for lab in await app.list_labs():
        if lab["id"] == lab_id or lab.get("state") in ("STOPPED", "DEFINED_ON_CORE"):
            continue
        for n in await app.list_nodes(str(lab["id"])):
            if is_cat9kv(str(n.get("node_definition") or "")) and n.get("state") in ("BOOTED", "STARTED"):
                s = await node_serial(app, str(lab["id"]), n)
                if s in by_serial:
                    other = f"{lab.get('lab_title')}/{n.get('label')}"
                    elsewhere.append(f"{', '.join(by_serial[s])} share serial {s} with {other}")
    fix = (
        " - Catalyst Center would merge them into one device: rebuild with unique conf/vswitch.xml serials "
        "(cml_build_lab/cml_build_recipe assign them)"
    )
    # duplicates inside the lab fail; another lab's switch with the same serial only matters when one Catalyst
    # Center discovers both, so it is reported as a warning
    detail: Any = "; ".join(problems) + fix if problems else serials
    out = [check("cat9000v serials unique in the lab (Catalyst Center)", "serial", not problems, detail)]
    if elsewhere:
        out[0]["warning"] = "; ".join(elsewhere) + " (only matters if one Catalyst Center discovers both)"
    return out


# --- the whole contract -----------------------------------------------------------------------


def title_of(name: str) -> str:
    return str(get_recipe(name)["build"]["title"])


async def verify_recipe(
    app: CmlApp, name: str, *, lab: str | None = None, substitute: dict[str, str] | None = None
) -> dict[str, Any]:
    """Run recipe `name`'s verify contract (see _verify_recipe); results and errors never carry the
    resolved lab secrets."""
    mapping = secret_names_by_value(app.settings.lab_secrets_file)
    try:
        return dict(redact_values(await _verify_recipe(app, name, lab=lab, substitute=substitute), mapping))
    except UpstreamError as e:
        raise UpstreamError(redact_values(str(e), mapping), e.status_code) from None
    except InvalidRequest as e:
        raise InvalidRequest(redact_values(str(e), mapping)) from None


async def _verify_recipe(
    app: CmlApp, name: str, *, lab: str | None = None, substitute: dict[str, str] | None = None
) -> dict[str, Any]:
    """Run recipe `name`'s verify contract against its lab, or against `lab` (a copy built with
    cml_build_recipe(title=..., substitute=...)), with the same substitutions applied."""
    title = lab or get_recipe(name)["build"]["title"]
    started = time.monotonic()
    checks: list[dict[str, Any]] = []
    out: dict[str, Any] = {"recipe": name, "lab": title}
    labs = [lab for lab in await app.list_labs() if lab.get("lab_title") == title]
    if len(labs) != 1:
        problem = (
            f"no lab titled {title!r}; build it first"
            if not labs
            else f"{len(labs)} labs are titled {title!r}"
        )
        checks.append(check("lab exists", "lab", False, problem))
        return {**out, "passed": False, "summary": "0/1 checks passed", "seconds": 0.0, "checks": checks}
    lab_info = labs[0]
    lid = lab_info["id"]
    # L25: a copy records its recipe and substitutions in the lab notes; without them the checks would
    # probe the recipe's own addresses (another lab's devices)
    # CML returns a lab's notes as `lab_notes` (`notes` in topology YAML)
    if "lab_notes" in lab_info:
        notes = lab_info.get("lab_notes")
    else:
        notes = (await app.api.get(f"/labs/{lid}")).get("lab_notes")
    marker = read_recipe_marker(notes)
    if marker and marker["recipe"] != name:
        checks.append(
            check(
                "lab built from this recipe", "lab", False, f"{title!r} was built from {marker['recipe']!r}"
            )
        )
        return {**out, "passed": False, "summary": "0/1 checks passed", "seconds": 0.0, "checks": checks}
    from_notes = False
    if substitute is None and marker:
        substitute = marker["substitute"] or None
        if substitute:
            out["substitute"] = substitute
            from_notes = True
    elif substitute is None and lab and lab != title_of(name):
        out["warning"] = (
            f"{title!r} has no recorded recipe substitutions (built before v0.9.0 or by hand): the "
            f"checks use recipe {name!r}'s own addresses. Pass `substitute` if the copy was built with one."
        )
    recipe = substituted(get_recipe(name), substitute)
    # probes may carry ${LAB_*} references (SNMP communities): filled here, never echoed in results
    verify = resolve_secrets(
        recipe.get("verify") or {}, app.settings.lab_secrets_file, what=f"recipe {name!r}"
    )
    contract = contract_of({"verify": verify})
    nodes = {str(n.get("label")): n for n in await app.list_nodes(lid)}
    expected = contract.booted or [
        str(n.get("label"))
        for n in recipe["build"].get("nodes") or []
        if n.get("definition") not in ("external_connector", "unmanaged_switch")
    ]
    for label in expected:
        state = (nodes.get(label) or {}).get("state", "missing")
        ok = state == "BOOTED"
        checks.append(check(f"{label} booted", "state", ok, None if ok else f"state {state}"))
    checks += await cat9kv_serial_checks(app, lid, list(nodes.values()))
    console_nodes = sorted(
        set(contract.nodes)
        | set(contract.addresses)
        | {p.node for p in contract.probes if p.node and p.command}
    )
    plans: dict[str, list[tuple[str, Any]]] = {}  # node -> [(purpose, item)] in command order

    def commands_for(node: dict[str, Any], cred: Credentials) -> list[Command]:
        label = str(node.get("label"))
        plan: list[tuple[str, Any]] = []
        cmds: list[Command] = []
        if label in contract.addresses:
            for c in address_commands(cred.os):
                plan.append(("address", c))
                cmds.append(c)
        if label in contract.nodes:
            for t in contract.targets:
                cmd, interrupt = ping_command(cred.os, t, contract.count, contract.vrf)
                plan.append(("ping", t))
                cmds.append((cmd, interrupt))
        for p in contract.probes:
            if p.node == label and p.command:
                plan.append(("probe", p))
                cmds.append((p.command, p.interrupt_after))
        plans[label] = plan
        return cmds

    targets = [nodes[n] for n in console_nodes if n in nodes and nodes[n].get("state") == "BOOTED"]
    for n in console_nodes:
        if n not in nodes or nodes[n].get("state") != "BOOTED":
            checks.append(check(f"{n} console checks", "console", False, "node not BOOTED; skipped"))
    per_command = max([60.0, *(p.timeout for p in contract.probes if p.command)])
    batch = (
        await console_batch(app, lid, targets, commands_for, timeout=per_command, purpose="cml_verify_recipe")
        if targets
        else []
    )
    for res in batch:
        label = str(res["node"])
        plan = plans.get(label, [])
        outputs = res.get("outputs") or []
        if res.get("error") or len(outputs) != len(plan):
            # every planned check fails, by name, with the console error
            why = res.get("error") or f"got {len(outputs)} outputs for {len(plan)} commands"
            checks.append(check(f"{label} console", "console", False, why))
            for purpose, item in plan:
                if purpose == "ping":
                    checks.append(check(f"{label} -> {item}", "ping", False, "console failed"))
                elif purpose == "probe":
                    checks.append(check(item.name, "console", False, "console failed"))
            for ip in contract.addresses.get(label, []):
                checks.append(check(f"{label} has {ip}", "address", False, "console failed"))
            continue
        found: set[str] = set()
        address_errors: list[str] = []
        for (purpose, item), o in zip(plan, outputs, strict=True):
            text = o.get("output", "")
            if purpose == "address":
                if "error" in o:
                    address_errors.append(f"{item}: {o['error']}")
                found |= {r["ipv4"].split("/")[0] for r in parse_addresses(item, text)}
            elif purpose == "ping":
                verdict = ping_result(text) if "error" not in o else {"ok": False, "error": o["error"]}
                checks.append(check(f"{label} -> {item}", "ping", bool(verdict.get("ok")), verdict))
            else:
                p: Probe = item
                if "error" in o:
                    checks.append(check(p.name, "console", False, o["error"]))
                    continue
                ok = (not p.expect or bool(re.search(p.expect, text))) and not (
                    p.reject and re.search(p.reject, text)
                )
                tail = mask_secrets(text.strip())[-300:]
                checks.append(check(p.name, "console", ok, tail[-160:] if ok else tail))
        for ip in contract.addresses.get(label, []):
            checks.append(
                check(
                    f"{label} has {ip}",
                    "address",
                    ip in found,
                    None
                    if ip in found
                    else {"found": sorted(found), **({"errors": address_errors} if address_errors else {})},
                )
            )
    # Notes are writable by any lab editor: substitutions read from them never redirect a network
    # probe (an SNMP probe sends the real community) to another host; the caller can pass them explicitly.
    # Probes are compared by position with the packaged recipe (a substitution can rename a probe, never
    # add or drop one); a network probe whose target differs, or that has no packaged twin, is skipped.
    packaged = contract_of(get_recipe(name)).probes if from_notes else None
    skipped: list[str] = []
    for i, p in enumerate(contract.probes):
        if packaged is not None and (p.tcp or p.snmp or p.ise_session):
            was = packaged[i] if i < len(packaged) else None
            if (
                was is None
                or p.tcp != was.tcp
                or (p.snmp is None) != (was.snmp is None)
                or (p.snmp and was.snmp and (p.snmp.host, p.snmp.port) != (was.snmp.host, was.snmp.port))
                or (p.ise_session is None) != (was.ise_session is None)
                or (p.ise_session and was.ise_session and p.ise_session.url != was.ise_session.url)
            ):
                skipped.append(p.name)
                continue
        if p.tcp:
            ok, detail = await tcp_probe(p.tcp)
            checks.append(check(p.name, "tcp", ok, detail))
        elif p.snmp:
            ok, detail = await snmp_probe(p.snmp)
            checks.append(check(p.name, "snmp", ok, detail))
        elif p.ise_session:
            ok, detail = await ise_session_probe(p.ise_session)
            checks.append(check(p.name, "ise_session", ok, detail))
    if skipped:
        out["skipped"] = {
            "checks": skipped,
            "why": "network probes to substituted hosts don't run on substitutions read from the lab notes; "
            "pass the same `substitute` explicitly to run them",
        }
    passed = bool(checks) and all(c["ok"] for c in checks)
    return {
        **out,
        "lab_state": lab_info.get("state"),
        "passed": passed,
        "summary": f"{sum(c['ok'] for c in checks)}/{len(checks)} checks passed",
        "seconds": round(time.monotonic() - started, 1),
        "checks": checks,
    }
