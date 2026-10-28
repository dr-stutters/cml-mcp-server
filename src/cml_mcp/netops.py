"""Console-driven helpers shared by the CLI tools: run commands on many nodes, discover IPv4
addresses from CLI output, and ping with the right syntax per OS."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from collections.abc import Callable, Sequence
from typing import Any

from cml_mcp._core import InvalidRequest, UpstreamError, UpstreamTimeout
from cml_mcp.client import CmlApp
from cml_mcp.console import ConsoleSession, Credentials, mask_secrets, testbed_credentials

PARALLEL_NODES = 4
FTD_OS = ("fxos", "ftd")


async def lab_credentials(app: CmlApp, lab_id: str) -> dict[str, Credentials]:
    try:
        text = await app.api.get(f"/labs/{lab_id}/pyats_testbed", expect="text")
    except UpstreamError:
        return {}
    return testbed_credentials(text)


async def prepare(session: ConsoleSession) -> None:
    """Disable paging on Cisco-style CLIs (best effort). FTD's CLISH has no 'terminal length';
    its '--More--' pager is answered while reading."""
    if (session.creds.os or "").lower() in FTD_OS:
        return
    if session.prompt.endswith(("#", ">")):
        with contextlib.suppress(UpstreamError):
            await session.run("terminal length 0", timeout=10)


# A command, or (command, interrupt_after seconds) for commands that never end by themselves.
Command = str | tuple[str, float | None]
CommandsFor = Callable[[dict[str, Any], Credentials], Sequence[Command]]


async def console_batch(
    app: CmlApp,
    lab_id: str,
    nodes: list[dict[str, Any]],
    commands_for: CommandsFor,
    *,
    timeout: float,  # noqa: ASYNC109 - per-command timeout
    purpose: str = "a console call",
) -> list[dict[str, Any]]:
    """Run commands on several booted nodes in parallel (4 at a time), one console session each.
    Per node: {node, os, prompt, outputs: [{command, output}]} or {node, error}; never raises for
    one node's failure."""
    creds = await lab_credentials(app, lab_id)
    sem = asyncio.Semaphore(PARALLEL_NODES)

    async def one(node: dict[str, Any]) -> dict[str, Any]:
        label = str(node.get("label"))
        cred = creds.get(label, Credentials())
        out: dict[str, Any] = {"node": label}
        if cred.os:
            out["os"] = cred.os
        if node.get("state") != "BOOTED":
            out["error"] = f"node is {node.get('state')}, not BOOTED (cml_wait_for_converged)"
            return out
        commands = commands_for(node, cred)
        if not commands:
            out["error"] = f"no commands for this node type ({node.get('node_definition')})"
            return out
        try:
            # claim the node first: a busy node must not hold one of the batch's parallel slots
            async with (
                app.console.claim(node["id"], label, purpose),
                sem,
                app.console.open(lab_id, node["id"], cred) as session,
            ):
                await prepare(session)
                out["prompt"] = session.prompt
                out["outputs"] = []
                for item in commands:
                    cmd, interrupt = item if isinstance(item, tuple) else (item, None)
                    try:
                        text = await session.run(cmd, timeout=timeout, interrupt_after=interrupt)
                    except UpstreamTimeout as e:  # run() sent Ctrl-C; go on with the next one
                        out["outputs"].append({"command": cmd, "error": session.safe(str(e))[:300]})
                        await session.drain(limit=5.0)
                        continue
                    out["outputs"].append({"command": cmd, "output": mask_secrets(text)})
                if session.notes:
                    out["notes"] = list(session.notes)
        except Exception as e:  # report per node; never lose the other nodes' results
            out["error"] = mask_secrets(str(e))[:500] or type(e).__name__
        return out

    return list(await asyncio.gather(*(one(n) for n in nodes)))


# --- address discovery ------------------------------------------------------------------------

IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"


def address_commands(os_name: str | None) -> list[str]:
    os_name = (os_name or "").lower()
    if os_name in FTD_OS:
        return ["show network", "show interface ip brief"]
    if os_name == "asa":
        return ["show interface ip brief"]
    if os_name == "nxos":
        return ["show ip interface brief vrf all"]
    if os_name == "linux":
        return ["ip -4 -o addr"]
    if os_name in ("ios", "iosxe", "iosxr", ""):
        return ["show ip interface brief"]
    return []


def _valid(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_unspecified or addr.is_link_local)


def parse_addresses(command: str, output: str) -> list[dict[str, str]]:
    """[{interface, ipv4}] from 'show ip interface brief' (IOS/NX-OS/ASA/FTD), FTD 'show network'
    and Linux 'ip -4 -o addr'."""
    rows: list[dict[str, str]] = []
    if command.startswith("ip "):
        for m in re.finditer(r"^\d+:\s+(\S+)\s+inet\s+" + IPV4 + r"/(\d+)", output, re.MULTILINE):
            if _valid(m.group(2)):
                rows.append({"interface": m.group(1), "ipv4": f"{m.group(2)}/{m.group(3)}"})
        return rows
    if command == "show network":
        iface = "management"
        for line in output.splitlines():
            head = re.search(r"=+\[\s*(\S+)\s*\]=+", line)
            if head:
                iface = head.group(1)
            hit = re.match(r"\s*Address\s*:\s*" + IPV4, line)
            if hit and _valid(hit.group(1)):
                rows.append({"interface": iface, "ipv4": hit.group(1)})
        return rows
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(IPV4, parts[1]) and _valid(parts[1]):
            rows.append({"interface": parts[0], "ipv4": parts[1]})
    return rows


# --- ping -------------------------------------------------------------------------------------


def ping_command(
    os_name: str | None, target: str, count: int, vrf: str | None = None
) -> tuple[str, float | None]:
    """(command, interrupt_after seconds or None) for pinging `target` `count` times."""
    os_name = (os_name or "").lower()
    if os_name == "linux":
        return f"ping -c {count} -W 2 {target}", None
    if os_name == "nxos":
        return f"ping {target} count {count}" + (f" vrf {vrf}" if vrf else ""), None
    if os_name in FTD_OS:
        # 'ping system' uses the management interface (where FMC registration traffic goes) and
        # runs until Ctrl-C; the data-plane 'ping' sends 5 like ASA/IOS.
        if vrf == "management":
            return f"ping system {target}", count + 1.5
        if vrf:
            raise InvalidRequest("On FTD, vrf may only be 'management' (ping system); data pings use no vrf")
        return f"ping {target}", None
    vrf_part = f" vrf {vrf}" if vrf else ""
    return f"ping{vrf_part} {target} repeat {count} timeout 2", None


# IOS 'round-trip min/avg/max = 1/2/3 ms', Linux 'rtt min/avg/max/mdev = 0.1/0.2/...', NX-OS
# 'round-trip min/avg/max = 1.2/1.5/2.0 ms': the second number is the average.
RTT = re.compile(r"(?:round-trip|rtt) min/avg/max(?:/mdev)? = [\d.]+/([\d.]+)/")


def ping_result(output: str) -> dict[str, Any]:
    """{success_percent, ok} (ok = at least one reply: the first echo is often lost to ARP) from
    IOS ('Success rate is 100 percent (5/5)') or Linux/NX-OS
    ('3 packets transmitted, 3 received, 0% packet loss') ping output."""
    rtt = RTT.search(output)
    extra: dict[str, Any] = {"rtt_avg_ms": float(rtt.group(1))} if rtt else {}
    m = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", output)
    if m:
        pct = int(m.group(1))
        return {
            "success_percent": pct,
            "received": int(m.group(2)),
            "sent": int(m.group(3)),
            "ok": pct > 0,
            **extra,
        }
    m2 = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
    if m2:
        sent, got = int(m2.group(1)), int(m2.group(2))
        pct = round(100 * got / sent) if sent else 0
        return {"success_percent": pct, "received": got, "sent": sent, "ok": got > 0, **extra}
    return {"ok": False, "unparsed": output.strip()[-300:]}
