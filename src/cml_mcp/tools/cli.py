"""CLI on lab nodes through the CML console server: show commands (read) and config (write)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import contextlib
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    get_settings,
)
from cml_mcp.client import CmlApp
from cml_mcp.console import Credentials, mask_secrets, read_only_problem, strip_route_legend
from cml_mcp.netops import console_batch, lab_credentials, prepare
from cml_mcp.safety import denied_lines
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import LabRef, NodeRef, shaped

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
    "Syntax error",  # FTD CLISH
    "ERROR:",
)


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
        configuration changes use cml_configure_node. On Linux nodes give ping a count
        ('ping -c 3 x'), or it runs until the timeout. Secrets in output (passwords, community
        strings) are masked. A console left at IOS XE's 'Uncommitted changes found, commit them?' is
        answered 'no' (the changes are discarded) and reported in the node's notes."""
        problems = {c: p for c in commands if (p := read_only_problem(c))}
        if problems:
            raise InvalidRequest(
                "Not allowed in the read tier: " + "; ".join(f"{c!r}: {p}" for c, p in problems.items())
            )
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        targets = [await app.resolve_node(lid, n) for n in nodes]
        results = await console_batch(
            app, lid, targets, lambda _n, _c: commands, timeout=command_timeout, purpose="cml_run_commands"
        )
        for res in results:  # the IOS route-code legend is noise in a model's context (L32)
            for o in res.get("outputs") or []:
                if isinstance(o.get("output"), str):
                    o["output"] = strip_route_legend(o["output"])
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
        save: Annotated[bool, Field(description="Run 'write memory' afterwards (config mode only)")] = False,
        mode: Annotated[
            Literal["config", "exec"],
            Field(
                description="'config' (default): wrap the lines in 'configure terminal' ... 'end' "
                "(IOS/IOS-XE/NX-OS). 'exec': send each line as-is at the top-level prompt, e.g. FTD "
                "'configure manager add 198.18.134.76 <reg-key>' or IOS 'clear ip ospf process'"
            ),
        ] = "config",
        answer_questions: Annotated[
            bool,
            Field(
                description="Answer prompts such as '[confirm]', '[yes/no]:' or 'Do you want to "
                "continue?' affirmatively; when false such a prompt aborts with an error. IOS XE's "
                "'Uncommitted changes found, commit them?' is always answered 'no' (send 'commit' "
                "yourself) and reported in notes"
            ),
        ] = False,
        line_timeout: Annotated[
            float, Field(ge=5, le=600, description="Seconds to wait for each line to finish")
        ] = 30,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply configuration to a running device through its serial console. mode='config' (IOS/
        IOS-XE/NX-OS): 'configure terminal', the lines, 'end', optionally 'write memory'. mode='exec':
        each line is run at the top-level prompt, for CLIs without a config mode (FTD CLISH:
        'configure manager add ...', 'configure network ipv4 manual ...') or exec actions. Lines the
        device rejects ('% Invalid input', FTD 'Syntax error'/'ERROR:') are reported. The change is
        live immediately; on IOS it survives a restart only if saved, and a wipe only after
        cml_extract_node_configs."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        blockers = []
        if save and mode == "exec":
            blockers.append("save only applies to mode='config' (FTD saves its configuration itself)")
        if n.get("state") != "BOOTED":
            blockers.append(f"Node is {n.get('state')}; it must be BOOTED")
        if any(ch < " " and ch != "\t" for line in lines for ch in line):
            blockers.append("One configuration line per list entry (no newlines or other control characters)")
        if denied := denied_lines(lines, get_settings(ctx)):
            blockers.append(
                f"Destructive device command(s) on the deny-list: {denied}. This server doesn't erase, "
                "reload, format or delete on devices (CML_CONFIG_DENY_DEFAULTS / CML_CONFIG_DENY); use the "
                "CML UI or cml_set_node_state / cml_wipe_node instead."
            )
        plan = Plan(
            f"Configure {n.get('label')!r} via its console ({len(lines)} {mode} lines)"
            + (" and save" if save and mode == "config" else ""),
            details={
                "lines": [mask_secrets(line) for line in lines],
                "save": save,
                "mode": mode,
                "answer_questions": answer_questions,
            },
            fingerprint=n.get("state"),
            blockers=blockers,
        )

        async def apply() -> Any:
            creds = (await lab_credentials(app, lid)).get(str(n.get("label")), Credentials())
            async with (
                app.console.claim(n["id"], str(n.get("label")), "cml_configure_node"),
                app.console.open(lid, n["id"], creds) as session,
            ):
                await prepare(session)
                rejected: list[dict[str, str]] = []
                outputs: list[dict[str, str]] = []

                async def send(line: str) -> None:
                    output = await session.run(line, timeout=line_timeout, answer_questions=answer_questions)
                    if any(marker in output for marker in IOS_ERROR_MARKERS):
                        rejected.append({"line": line, "error": mask_secrets(output.strip())[:300]})
                    elif mode == "exec" and output.strip():
                        outputs.append({"line": line, "output": mask_secrets(output.strip())[-1500:]})

                if mode == "exec":
                    for line in lines:
                        await send(line)
                else:
                    if not session.prompt.endswith("#"):
                        raise InvalidRequest(
                            f"Expected a privileged Cisco prompt ending in '#', got {session.prompt!r}. "
                            "For CLIs without 'configure terminal' (FTD) use mode='exec'."
                        )
                    await session.run("configure terminal")
                    if "(config" not in session.last_prompt:
                        raise InvalidRequest(
                            f"The device did not enter configuration mode (prompt {session.last_prompt!r}); "
                            "use mode='exec' for CLIs without 'configure terminal'"
                        )
                    try:
                        for line in lines:
                            await send(line)
                    finally:
                        with contextlib.suppress(UpstreamError):
                            await session.run("end")
                result: dict[str, Any] = {"applied": len(lines) - len(rejected)}
                if rejected:
                    result["rejected"] = rejected
                if outputs:
                    result["outputs"] = outputs
                if save and mode == "config":
                    out = await session.run("write memory", timeout=120, answer_questions=True)
                    result["saved"] = "[OK]" in out or "Copy complete" in out
                if session.notes:
                    result["notes"] = list(session.notes)
            return result

        return await preview_or_apply(
            ctx,
            tool="cml_configure_node",
            args={
                "lab": lab,
                "node": node,
                "lines": lines,
                "save": save,
                "mode": mode,
                "answer_questions": answer_questions,
                "line_timeout": line_timeout,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
