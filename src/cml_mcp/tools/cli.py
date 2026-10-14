"""CLI on lab nodes through the CML console server: show commands (read) and config (write)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
import contextlib
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)

from cml_mcp.client import CmlApp
from cml_mcp.console import ConsoleSession, Credentials, mask_secrets, read_only_problem, testbed_credentials
from cml_mcp.tools.common import LabRef, NodeRef, shaped

PARALLEL_NODES = 4
IOS_ERROR_MARKERS = (
    "% Invalid",
    "% Incomplete",
    "% Ambiguous",
    "% Unknown",
    "% Bad",
    "% Access",
    "%Error",
    "% Error",
    "Invalid input detected",
    "Invalid command",
)


async def lab_credentials(app: CmlApp, lab_id: str) -> dict[str, Credentials]:
    try:
        text = await app.api.get(f"/labs/{lab_id}/pyats_testbed", expect="text")
    except UpstreamError:
        return {}
    return testbed_credentials(text)


async def prepare(session: ConsoleSession) -> None:
    """Disable paging on Cisco-style CLIs (best effort)."""
    if session.prompt.endswith(("#", ">")):
        with contextlib.suppress(UpstreamError):
            await session.run("terminal length 0", timeout=10)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Run show commands", idempotent=False)
    async def cml_run_commands(
        ctx: Context,
        lab: LabRef,
        nodes: Annotated[list[str], Field(min_length=1, max_length=20, description="Node labels or ids")],
        commands: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=20,
                description="Read-only commands, e.g. 'show ip interface brief', 'ping 10.0.0.2', 'ip addr'",
            ),
        ],
        command_timeout: Annotated[
            float, Field(ge=5, le=300, description="Seconds to wait for each command's output")
        ] = 30,
    ) -> ToolResult:
        """Run read-only CLI commands (show, ping, traceroute, dir; ip/ifconfig/route on Linux nodes)
        on one or more booted nodes through the CML console server and return the raw output per node
        and command. Works without any IP reachability to the devices; logs in with the credentials
        from the lab's pyATS testbed and turns off paging. Nodes run in parallel (4 at a time). For
        configuration changes use cml_configure_node."""
        problems = {c: p for c in commands if (p := read_only_problem(c))}
        if problems:
            raise InvalidRequest(
                "Not allowed in the read tier: " + "; ".join(f"{c!r}: {p}" for c, p in problems.items())
            )
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        targets = [await app.resolve_node(lid, n) for n in nodes]
        creds = await lab_credentials(app, lid)
        sem = asyncio.Semaphore(PARALLEL_NODES)

        async def one(node: dict[str, Any]) -> dict[str, Any]:
            label = str(node.get("label"))
            out: dict[str, Any] = {"node": label}
            if node.get("state") != "BOOTED":
                out["error"] = f"node is {node.get('state')}, not BOOTED (cml_wait_for_converged)"
                return out
            async with sem, app.console.lock(node["id"]):
                try:
                    async with app.console.open(lid, node["id"], creds.get(label, Credentials())) as session:
                        await prepare(session)
                        out["prompt"] = session.prompt
                        out["outputs"] = []
                        for cmd in commands:
                            text = await session.run(cmd, timeout=command_timeout)
                            out["outputs"].append({"command": cmd, "output": mask_secrets(text)})
                except Exception as e:  # report per node; never lose the other nodes' results
                    out["error"] = str(e)[:500] or type(e).__name__
            return out

        results = await asyncio.gather(*(one(n) for n in targets))
        return shaped({"lab": info.get("lab_title"), "results": list(results)})

    @reg.write(title="Configure node via CLI")
    async def cml_configure_node(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        lines: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=500,
                description="Configuration lines, as typed in 'configure terminal'",
            ),
        ],
        save: Annotated[bool, Field(description="Run 'write memory' afterwards")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply configuration lines to a running Cisco-style device (IOS/IOS-XE/NX-OS) through its
        console: 'configure terminal', the lines, 'end', optionally 'write memory'. Lines the device
        rejects (% Invalid input...) are reported. The change is live immediately; it survives a
        restart only if saved, and survives a wipe only after cml_extract_node_configs."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        blockers = []
        if n.get("state") != "BOOTED":
            blockers.append(f"Node is {n.get('state')}; it must be BOOTED")
        if any("\n" in line for line in lines):
            blockers.append("One configuration line per list entry (no embedded newlines)")
        plan = Plan(
            f"Configure {n.get('label')!r} via its console ({len(lines)} lines)"
            + (" and save" if save else ""),
            details={"lines": lines, "save": save},
            fingerprint=n.get("state"),
            blockers=blockers,
        )

        async def apply() -> Any:
            creds = (await lab_credentials(app, lid)).get(str(n.get("label")), Credentials())
            async with app.console.lock(n["id"]), app.console.open(lid, n["id"], creds) as session:
                if not session.prompt.endswith("#"):
                    raise InvalidRequest(
                        f"Expected a privileged Cisco prompt ending in '#', got {session.prompt!r}"
                    )
                await prepare(session)
                await session.run("configure terminal")
                if "(config" not in session.last_prompt:
                    raise InvalidRequest(
                        f"The device did not enter configuration mode (prompt {session.last_prompt!r}); "
                        "cml_configure_node supports Cisco IOS/IOS-XE/NX-OS style CLIs"
                    )
                rejected = []
                try:
                    for line in lines:
                        output = await session.run(line)
                        if any(marker in output for marker in IOS_ERROR_MARKERS):
                            rejected.append({"line": line, "error": output.strip()[:300]})
                finally:
                    await session.run("end")
                result: dict[str, Any] = {"applied": len(lines) - len(rejected)}
                if rejected:
                    result["rejected"] = rejected
                if save:
                    out = await session.run("write memory", timeout=60)
                    result["saved"] = "[OK]" in out or "Copy complete" in out
            return result

        return await preview_or_apply(
            ctx,
            tool="cml_configure_node",
            args={"lab": lab, "node": node, "lines": lines, "save": save},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
