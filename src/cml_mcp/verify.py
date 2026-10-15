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
        - {name: snmp, snmp: {host: 198.18.128.152, community: mcp-ro}}

Console probes run commands written in the packaged recipe (never caller input) over the node's
console; tcp and snmp probes run from the MCP server's host, like the product server would.
Every check is pass/fail with a short detail; nothing in the lab is changed.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from typing import Any

from pydantic import BaseModel, Field, ValidationError, model_validator

from cml_mcp.client import CmlApp
from cml_mcp.console import Credentials, mask_secrets, read_only_problem
from cml_mcp.netops import (
    Command,
    address_commands,
    console_batch,
    parse_addresses,
    ping_command,
    ping_result,
)
from cml_mcp.recipes import get_recipe

TCP_TARGET = re.compile(r"^(?P<host>[A-Za-z0-9.:-]+):(?P<port>\d{1,5})$")


class SnmpProbe(BaseModel):
    host: str
    community: str
    port: int = 161


# Console probes run outside the read-tier allow-list (they come only from packaged recipes), but
# they must still be read-only or one of these known side-effect-free tests.
PROBE_COMMAND_PREFIXES = ("test aaa group radius ",)  # sends one RADIUS request, changes no config


class Probe(BaseModel):
    name: str
    node: str | None = None
    command: str | None = None
    expect: str | None = Field(default=None, description="regex the console output must match")
    reject: str | None = Field(default=None, description="regex the console output must not match")
    timeout: float = Field(default=60, gt=0, le=600)
    interrupt_after: float | None = None
    tcp: str | None = None
    snmp: SnmpProbe | None = None

    @model_validator(mode="after")
    def _check(self) -> Probe:
        actions = [a for a in (self.command, self.tcp, self.snmp) if a]
        if len(actions) != 1:
            raise ValueError(f"probe {self.name!r}: give exactly one of command, tcp, snmp")
        if self.command:
            if not self.node:
                raise ValueError(f"probe {self.name!r}: a command needs a node")
            if read_only_problem(self.command) and not self.command.startswith(PROBE_COMMAND_PREFIXES):
                raise ValueError(f"probe {self.name!r}: {self.command!r} is not a read-only command")
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


# --- the whole contract -----------------------------------------------------------------------


async def verify_recipe(app: CmlApp, name: str) -> dict[str, Any]:
    recipe = get_recipe(name)
    contract = contract_of(recipe)
    title = recipe["build"]["title"]
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
    lab = labs[0]
    lid = lab["id"]
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
    for p in contract.probes:
        if p.tcp:
            ok, detail = await tcp_probe(p.tcp)
            checks.append(check(p.name, "tcp", ok, detail))
        elif p.snmp:
            ok, detail = await snmp_probe(p.snmp)
            checks.append(check(p.name, "snmp", ok, detail))
    passed = bool(checks) and all(c["ok"] for c in checks)
    return {
        **out,
        "lab_state": lab.get("state"),
        "passed": passed,
        "summary": f"{sum(c['ok'] for c in checks)}/{len(checks)} checks passed",
        "seconds": round(time.monotonic() - started, 1),
        "checks": checks,
    }
