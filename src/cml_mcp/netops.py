"""Console-driven helpers shared by the CLI tools: run commands on many nodes, discover IPv4
addresses from CLI output, and ping with the right syntax per OS."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal

from cml_mcp._core import InvalidRequest, UpstreamError, UpstreamTimeout
from cml_mcp.client import CmlApp
from cml_mcp.console import (
    ConsoleFlooded,
    ConsoleSession,
    ConsoleSilent,
    Credentials,
    LoginLoop,
    mask_secrets,
    testbed_credentials,
)
from cml_mcp.topology import config_addresses

PARALLEL_NODES = 4
FTD_OS = ("fxos", "ftd")
Transport = Literal["auto", "console", "ssh"]
MGMT_IFACE = re.compile(r"mgmt|management", re.IGNORECASE)


def console_state(e: BaseException) -> str | None:
    """'silent' / 'flooded' / 'login-looping' for the console failures L41 names, else None."""
    if isinstance(e, ConsoleSilent):
        return "silent"
    if isinstance(e, ConsoleFlooded):
        return "flooded"
    if isinstance(e, LoginLoop):
        return "login-looping"
    return None


# --- management addresses (cml_configure_nodes {mgmt_ip}, the SSH transport) ----------------------


async def snooped_ipv4s(app: CmlApp, lab_id: str) -> dict[str, list[str]]:
    """{node id: [IPv4 without prefix]} that CML snooped on the lab's nodes (external connector
    interfaces, learnt from DHCP/ARP); {} when the controller doesn't answer."""
    try:
        data = await app.api.get(f"/labs/{lab_id}/layer3_addresses") or {}
    except UpstreamError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(nid): [
            str(ip).split("/")[0]
            for iface in ((entry or {}).get("interfaces") or {}).values()
            for ip in (iface.get("ip4") or [])
        ]
        for nid, entry in data.items()
    }


async def day0_ipv4s(app: CmlApp, lab_id: str, node: dict[str, Any]) -> list[tuple[str, str]]:
    """[(interface, IPv4 without prefix)] from the node's day-0 configuration."""
    from cml_mcp.tools.common import config_text  # tools.common imports this module's neighbours

    full = await app.api.get(f"/labs/{lab_id}/nodes/{node['id']}")
    rows = config_addresses(str(node.get("node_definition")), config_text(full))
    return [(i, a.split("/")[0]) for i, a in rows]


def pick_management(snooped: list[str], rows: list[tuple[str, str]]) -> str | None:
    """The node's management IPv4: the first snooped address, else the day-0 address of an interface
    named like a management port, else its only day-0 address outside loopbacks."""
    if snooped:
        return snooped[0]
    mgmt = [a for i, a in rows if MGMT_IFACE.search(i)]
    others = [a for i, a in rows if not i.lower().startswith("loopback")]
    if mgmt or len(others) == 1:
        return (mgmt or others)[0]
    return None


async def management_address(app: CmlApp, lab_id: str, node: dict[str, Any]) -> str | None:
    """The node's management IPv4 (pick_management), or None."""
    mine = (await snooped_ipv4s(app, lab_id)).get(str(node["id"]), [])
    return pick_management(mine, [] if mine else await day0_ipv4s(app, lab_id, node))


async def check_ssh_hosts(
    app: CmlApp, lab_id: str, nodes: list[dict[str, Any]], given: dict[str, str]
) -> list[str]:
    """Why the caller's SSH hosts ({label: address}) can't be used. Each must be one of the node's own
    addresses (snooped by CML or set by its day-0 config): the node's pyATS password is sent to it, so
    it never goes to an arbitrary host."""
    if not given:
        return []
    snooped = await snooped_ipv4s(app, lab_id)
    problems: list[str] = []
    for n in nodes:
        label = str(n.get("label"))
        if (host := given.get(label)) is None:
            continue
        known = list(
            dict.fromkeys([*snooped.get(str(n["id"]), []), *(a for _, a in await day0_ipv4s(app, lab_id, n))])
        )
        if host not in known:
            problems.append(
                f"ssh_host {host!r} is not one of {label}'s own addresses "
                f"({', '.join(known) or 'none known'}): "
                "the node's pyATS credentials are only sent to an address CML snooped on it or its day-0 "
                "config sets"
            )
    return problems


def ssh_host_map(
    ssh_host: str | dict[str, str] | None, nodes: list[dict[str, Any]], refs: list[str]
) -> dict[str, str]:
    """The caller's ssh_host (one address for a single node, or {node label or id: address}) by label."""
    if ssh_host is None:
        return {}
    if isinstance(ssh_host, str):
        if len(nodes) != 1:
            raise InvalidRequest(
                "ssh_host as one address needs exactly one node; pass {node: address} for several"
            )
        return {str(nodes[0].get("label")): ssh_host}
    out: dict[str, str] = {}
    for key, host in ssh_host.items():
        hit = [n for ref, n in zip(refs, nodes, strict=True) if key in (ref, n["id"], n.get("label"))]
        if not hit:
            raise InvalidRequest(f"ssh_host names {key!r}, which is not one of the nodes")
        out[str(hit[0].get("label"))] = host
    return out


async def open_session(
    stack: contextlib.AsyncExitStack,
    app: CmlApp,
    lab_id: str,
    node: dict[str, Any],
    cred: Credentials,
    *,
    transport: Transport = "console",
    ssh_host: str | None = None,
    find_host: Callable[[], Awaitable[str | None]] | None = None,
    timeout: float | None = None,  # noqa: ASYNC109 - the session's wake/login timeout
) -> tuple[ConsoleSession, str, str | None]:
    """(session, transport used, note) for one node, entered on `stack`. 'console': the CML console
    server; 'ssh': an SSH shell on `ssh_host`; 'auto': the console, then SSH to `ssh_host` (or the
    address `find_host` returns) only when the console is silent or sends nothing but syslog. The
    fallback happens before any command is sent, so nothing ever runs twice."""
    if transport == "ssh":
        if not ssh_host:
            raise InvalidRequest(
                f"transport='ssh' needs an address for {node.get('label')!r}: pass ssh_host (no management "
                "address is known for the node)"
            )
        return await stack.enter_async_context(app.console.ssh(ssh_host, cred, timeout=timeout)), "ssh", None
    try:
        opened = (
            app.console.open(lab_id, node["id"], cred)
            if timeout is None
            else app.console.open(lab_id, node["id"], cred, timeout=timeout)
        )
        session = await stack.enter_async_context(opened)
        return session, "console", None
    except (ConsoleSilent, ConsoleFlooded) as e:
        if transport != "auto":
            raise
        host = ssh_host or (await find_host() if find_host else None)
        state = console_state(e)
        if not host:
            raise type(e)(
                f"{e} No SSH fallback: pass ssh_host= with the node's management address (none is known)."
            ) from None
        try:
            session = await stack.enter_async_context(app.console.ssh(host, cred, timeout=timeout))
        except UpstreamError as ssh_error:  # keep the console's state: that is what failed first
            raise type(e)(f"{e} The SSH fallback to {host} failed too: {ssh_error}") from None
        return session, "ssh", f"The console is {state}; used SSH to {host} instead."


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
    transport: Transport = "console",
    hosts: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Run commands on several booted nodes in parallel (4 at a time), one console session each.
    Per node: {node, os, prompt, outputs: [{command, output}]} or {node, error, console?}; never raises
    for one node's failure. `console` names a silent / flooded / login-looping console (L41).
    `transport` and `hosts` ({label: SSH address}) pick the session per node (open_session)."""
    creds = await lab_credentials(app, lab_id)
    sem = asyncio.Semaphore(PARALLEL_NODES)
    hosts = hosts or {}

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
            async with contextlib.AsyncExitStack() as stack:
                await stack.enter_async_context(app.console.claim(node["id"], label, purpose))
                await stack.enter_async_context(sem)
                session, used, note = await open_session(
                    stack,
                    app,
                    lab_id,
                    node,
                    cred,
                    transport=transport,
                    ssh_host=hosts.get(label),
                    find_host=lambda: management_address(app, lab_id, node),
                )
                if transport != "console":
                    out["transport"] = used
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
                notes = ([note] if note else []) + list(session.notes)
                if notes:
                    out["notes"] = notes
        except Exception as e:  # report per node; never lose the other nodes' results
            out["error"] = mask_secrets(str(e))[:500] or type(e).__name__
            if state := console_state(e):
                out["console"] = state
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
