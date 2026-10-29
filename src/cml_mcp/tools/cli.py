"""CLI on lab nodes through the CML console server: show commands (read) and config (write)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
import contextlib
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import (
    AuthError,
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    get_settings,
)
from cml_mcp.client import CmlApp
from cml_mcp.console import SILENT_HINT, Credentials, mask_secrets, read_only_problem, strip_route_legend
from cml_mcp.netops import (
    PARALLEL_NODES,
    Transport,
    check_ssh_hosts,
    console_batch,
    console_state,
    day0_ipv4s,
    lab_credentials,
    management_address,
    open_session,
    pick_management,
    prepare,
    snooped_ipv4s,
    ssh_host_map,
)
from cml_mcp.safety import denied_lines
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.templating import BUILTINS, LAB_REF, placeholders, render, vars_problems
from cml_mcp.tools.common import LabRef, NodeRef, shaped
from cml_mcp.undo import cli_back_out

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


def line_blockers(lines: list[str], *, mode: str, save: bool, settings: Any) -> list[str]:
    """Why these configuration lines can't be sent (save in exec mode, control characters, deny-list)."""
    blockers = []
    if save and mode == "exec":
        blockers.append("save only applies to mode='config' (FTD saves its configuration itself)")
    if any(ch < " " and ch != "\t" for line in lines for ch in line):
        blockers.append("One configuration line per list entry (no newlines or other control characters)")
    if denied := denied_lines(lines, settings):
        blockers.append(
            f"Destructive device command(s) on the deny-list: {denied}. This server doesn't erase, "
            "reload, format or delete on devices (CML_CONFIG_DENY_DEFAULTS / CML_CONFIG_DENY); use the "
            "CML UI or cml_set_node_state / cml_wipe_node instead."
        )
    return blockers


async def push_lines(
    app: CmlApp,
    lab_id: str,
    node: dict[str, Any],
    creds: Credentials,
    lines: list[str],
    *,
    mode: str,
    save: bool,
    answer_questions: bool,
    line_timeout: float,
    purpose: str,
    slot: asyncio.Semaphore | None = None,
    transport: Transport = "console",
    ssh_host: str | None = None,
) -> dict[str, Any]:
    """Send `lines` to one booted node over its console (config mode: 'configure terminal' ... 'end',
    optionally 'write memory'; exec mode: each line at the top-level prompt). Returns {applied,
    rejected?, outputs?, saved?, notes?, transport?}. `slot` limits how many nodes a batch configures at
    once; the node's console is claimed before waiting for a slot, so a busy node never holds one.
    `transport`/`ssh_host`: see netops.open_session (the SSH fallback happens before any line is sent)."""
    label = str(node.get("label"))
    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(app.console.claim(node["id"], label, purpose))
        if slot is not None:
            await stack.enter_async_context(slot)
        session, used, note = await open_session(
            stack, app, lab_id, node, creds, transport=transport, ssh_host=ssh_host
        )
        await prepare(session)
        rejected: list[dict[str, str]] = []
        outputs: list[dict[str, str]] = []

        async def send(line: str) -> None:
            output = await session.run(line, timeout=line_timeout, answer_questions=answer_questions)
            if any(marker in output for marker in IOS_ERROR_MARKERS):
                rejected.append({"line": mask_secrets(line), "error": mask_secrets(output.strip())[:300]})
            elif mode == "exec" and output.strip():
                outputs.append({"line": mask_secrets(line), "output": mask_secrets(output.strip())[-1500:]})

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
        if transport != "console":
            result["transport"] = used
        notes = ([note] if note else []) + list(session.notes)
        if notes:
            result["notes"] = notes
    return result


async def mgmt_addresses(app: CmlApp, lab_id: str, nodes: list[dict[str, Any]]) -> dict[str, str]:
    """{node label: management IPv4} for `{mgmt_ip}` (netops.pick_management)."""
    snooped = await snooped_ipv4s(app, lab_id)
    out: dict[str, str] = {}
    for n in nodes:
        mine = snooped.get(str(n["id"]), [])
        if pick := pick_management(mine, [] if mine else await day0_ipv4s(app, lab_id, n)):
            out[str(n.get("label"))] = pick
    return out


TransportArg = Annotated[
    Transport,
    Field(
        description="'auto' (default): the CML console, and only if it is silent or sends nothing but "
        "syslog, SSH to ssh_host (else the node's management address). 'console': the console only. "
        "'ssh': SSH to the device itself (needs a reachable management address and SSH enabled)"
    ),
]
SshHostArg = Annotated[
    str | dict[str, str] | None,
    Field(
        description="The node's management address for transport='ssh'/'auto' (one node), or {node: "
        "address}. Must be one of the node's own addresses (CML-snooped or in its day-0 config); the "
        "node's pyATS credentials are sent to it"
    ),
]


async def console_health(
    app: CmlApp,
    lab_id: str,
    node: dict[str, Any],
    creds: Credentials,
    *,
    timeout: float,  # noqa: ASYNC109 - the login wait
    slot: asyncio.Semaphore,
) -> dict[str, Any]:
    """One node's console: prompt (reachable), flooded, silent, login-looping, no-credentials or
    unavailable. Logs in like cml_run_commands and runs no command."""
    label = str(node.get("label"))
    out: dict[str, Any] = {"node": label}
    if creds.os:
        out["os"] = creds.os
    if node.get("state") != "BOOTED":
        out["state"] = "not-booted"
        out["detail"] = f"node is {node.get('state')}"
        return out
    try:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(app.console.claim(node["id"], label, "cml_console_health"))
            await stack.enter_async_context(slot)
            session = await stack.enter_async_context(
                app.console.open(lab_id, node["id"], creds, timeout=timeout)
            )
            out["state"] = "flooded" if session.flooded else "prompt"
            out["prompt"] = session.prompt
            if session.syslog_seen:
                out["syslog_messages"] = session.syslog_seen
            if session.flooded:
                out["hint"] = (
                    "Commands still work (output is read without syslog). 'no logging console' quiets it: "
                    "a configuration change (cml_configure_node)."
                )
    except Exception as e:  # report per node
        state = console_state(e)
        out["state"] = state or ("no-credentials" if isinstance(e, AuthError) else "unavailable")
        out["detail"] = mask_secrets(str(e))[:400] or type(e).__name__
        if state == "silent":
            out["hint"] = SILENT_HINT
        elif state == "flooded":
            out["hint"] = (
                "No prompt came through the syslog: try transport='ssh', or quiet it with "
                "'no logging console'."
            )
        elif state == "login-looping" or isinstance(e, AuthError):
            out["hint"] = "Check the node's pyATS username/password in CML (cml_get_pyats_testbed)."
    return out


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
        transport: TransportArg = "auto",
        ssh_host: SshHostArg = None,
    ) -> ToolResult:
        """Run read-only CLI commands (show, ping, traceroute, dir; ip/ifconfig/route on Linux nodes)
        on one or more booted nodes through the CML console server and return the raw output per node
        and command. Works without any IP reachability to the devices; logs in with the credentials
        from the lab's pyATS testbed and turns off paging. Nodes run in parallel (4 at a time). For
        configuration changes use cml_configure_node. On Linux nodes give ping a count
        ('ping -c 3 x'), or it runs until the timeout. Secrets in output (passwords, community
        strings) are masked. A console left at IOS XE's 'Uncommitted changes found, commit them?' is
        answered 'no' (the changes are discarded) and reported in the node's notes. A console flooded
        with syslog still works (the messages are left out of the output, see notes); a silent one
        (L41, cml_console_health) falls back to SSH on the node's management address with
        transport='auto', or fails with `console: silent` when none is known."""
        problems = {c: p for c in commands if (p := read_only_problem(c))}
        if problems:
            raise InvalidRequest(
                "Not allowed in the read tier: " + "; ".join(f"{c!r}: {p}" for c, p in problems.items())
            )
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        targets = [await app.resolve_node(lid, n) for n in nodes]
        hosts = ssh_host_map(ssh_host, targets, nodes)
        if bad := await check_ssh_hosts(app, lid, targets, hosts):
            raise InvalidRequest("; ".join(bad))
        if transport == "ssh":
            for n in targets:
                label = str(n.get("label"))
                if label not in hosts and (found := await management_address(app, lid, n)):
                    hosts[label] = found
        results = await console_batch(
            app,
            lid,
            targets,
            lambda _n, _c: commands,
            timeout=command_timeout,
            purpose="cml_run_commands",
            transport=transport,
            hosts=hosts,
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
        transport: TransportArg = "auto",
        ssh_host: Annotated[
            str | None,
            Field(
                description="The node's management address for transport='ssh'/'auto' (default: the one "
                "CML snooped or its day-0 config sets). Must be one of the node's own addresses"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply configuration to a running device through its serial console. mode='config' (IOS/
        IOS-XE/NX-OS): 'configure terminal', the lines, 'end', optionally 'write memory'. mode='exec':
        each line is run at the top-level prompt, for CLIs without a config mode (FTD CLISH:
        'configure manager add ...', 'configure network ipv4 manual ...') or exec actions. Lines the
        device rejects ('% Invalid input', FTD 'Syntax error'/'ERROR:') are reported. The change is
        live immediately; on IOS it survives a restart only if saved, and a wipe only after
        cml_extract_node_configs. transport='auto' (default) uses SSH to the node's management
        address only when the console is silent or sends nothing but syslog, before any line is sent
        (L41); the preview names the address."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        blockers = line_blockers(lines, mode=mode, save=save, settings=get_settings(ctx))
        if n.get("state") != "BOOTED":
            at = 1 if save and mode == "exec" else 0
            blockers.insert(at, f"Node is {n.get('state')}; it must be BOOTED")
        host = ssh_host
        if transport != "console":
            if host is not None:
                blockers += await check_ssh_hosts(app, lid, [n], {str(n.get("label")): host})
            else:
                host = await management_address(app, lid, n)
            if transport == "ssh" and not host:
                blockers.append("transport='ssh' needs ssh_host: no management address is known for the node")
        plan = Plan(
            f"Configure {n.get('label')!r} via its console ({len(lines)} {mode} lines)"
            + (" and save" if save and mode == "config" else ""),
            details={
                "lines": [mask_secrets(line) for line in lines],
                "save": save,
                "mode": mode,
                "answer_questions": answer_questions,
                "transport": transport,
                **({"ssh_host": host} if transport != "console" else {}),
            },
            fingerprint=n.get("state"),
            blockers=blockers,
            undo=cli_back_out(repr(n.get("label")), mode, save),
        )

        async def apply() -> Any:
            creds = (await lab_credentials(app, lid)).get(str(n.get("label")), Credentials())
            return await push_lines(
                app,
                lid,
                n,
                creds,
                lines,
                mode=mode,
                save=save,
                answer_questions=answer_questions,
                line_timeout=line_timeout,
                purpose="cml_configure_node",
                transport=transport,
                ssh_host=host,
            )

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
                "transport": transport,
                "ssh_host": ssh_host,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="Check node consoles")
    async def cml_console_health(
        ctx: Context,
        lab: LabRef,
        nodes: Annotated[
            list[str] | None,
            Field(max_length=50, description="Node labels or ids (default: every node with a console)"),
        ] = None,
        wait: Annotated[
            float,
            Field(
                ge=4,
                le=120,
                description="Seconds to wait for a prompt; a console with no output at all is called "
                "silent after 1.5x this (two RETURNs)",
            ),
        ] = 10,
    ) -> ToolResult:
        """Is each node's serial console usable? Per node: 'prompt' (a CLI prompt answered), 'flooded'
        (a prompt answered through a stream of console syslog: commands still work, the output is read
        without it), 'silent' (nothing at all after two RETURNs: CML Docker nodes such as iol-xe
        sometimes have a dead console while the node forwards; use transport='ssh' or a neighbour's
        ping), 'login-looping' (the login comes back after the pyATS credentials), 'no-credentials',
        'unavailable' (the console server could not open it) or 'not-booted'. Logs in like
        cml_run_commands and runs no command: nothing on the device changes. Run it before
        cml_run_commands / cml_verify_recipe on a lab whose consoles misbehave; 4 nodes at a time."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        if nodes:
            targets = [await app.resolve_node(lid, ref) for ref in nodes]
        else:
            targets = [
                n
                for n in await app.list_nodes(lid)
                if n.get("node_definition") not in ("external_connector", "unmanaged_switch")
            ]
        creds = await lab_credentials(app, lid)
        slot = asyncio.Semaphore(PARALLEL_NODES)
        rows = list(
            await asyncio.gather(
                *(
                    console_health(
                        app, lid, n, creds.get(str(n.get("label")), Credentials()), timeout=wait, slot=slot
                    )
                    for n in targets
                )
            )
        )
        summary: dict[str, int] = {}
        for r in rows:
            summary[r["state"]] = summary.get(r["state"], 0) + 1
        return shaped(
            {
                "lab": info.get("lab_title"),
                "summary": summary,
                "usable": [r["node"] for r in rows if r["state"] in ("prompt", "flooded")],
                "nodes": rows,
            }
        )

    @reg.write(title="Configure several nodes via CLI")
    async def cml_configure_nodes(
        ctx: Context,
        lab: LabRef,
        nodes: Annotated[
            list[str], Field(min_length=1, max_length=20, description="Node labels or ids (booted)")
        ],
        lines: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=500,
                description="Configuration line templates, as typed in 'configure terminal'. "
                "Placeholders: {label} (the node's label), {mgmt_ip} (its management IPv4) and any "
                "name in `vars`; '{{' and '}}' are literal braces",
            ),
        ],
        vars: Annotated[  # noqa: A002 - the issue's (and the caller's) name for it
            dict[str, dict[str, str | int]] | None,
            Field(
                description="Per-node values: {node label: {name: value}}, e.g. {'spoke1': {'tunnel_ip': "
                "'192.0.2.11'}}. A 'mgmt_ip' entry overrides the discovered address. Plain single-line "
                "values; ${LAB_*} lab-secret references are refused"
            ),
        ] = None,
        save: Annotated[bool, Field(description="Run 'write memory' afterwards (config mode only)")] = False,
        mode: Annotated[
            Literal["config", "exec"],
            Field(
                description="'config' (default): 'configure terminal' ... 'end' on each node (IOS/IOS-XE/"
                "NX-OS). 'exec': each line as-is at the top-level prompt (FTD CLISH, exec actions)"
            ),
        ] = "config",
        answer_questions: Annotated[
            bool,
            Field(
                description="Answer '[confirm]' / '[yes/no]:' prompts with yes (as cml_configure_node); "
                "'Uncommitted changes found, commit them?' is always answered 'no' and reported in notes"
            ),
        ] = False,
        line_timeout: Annotated[
            float, Field(ge=5, le=600, description="Seconds to wait for each line to finish")
        ] = 30,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push the same configuration, templated per node, to several running devices in one preview
        and one confirm (carriers with identical config, the same overlay lines on four spokes, AAA/
        NTP/syslog on unmanaged lab routers). Each line is a template: {label}, {mgmt_ip} (the
        address CML snooped on the node, else its day-0 management address; override with
        vars[node].mgmt_ip) and caller variables from vars[node]. The preview shows the rendered lines
        per node and blast_radius = the number of nodes; the deny-list (write erase, reload, ...) is
        checked on every rendered line. Nodes are configured 4 at a time through their consoles, the
        same way as cml_configure_node; a node that fails is reported and the others carry on.
        Check the result with cml_diff_lab(against='day0', view='sections', nodes=[...])."""
        app: CmlApp = get_client(ctx)
        settings = get_settings(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        targets = [await app.resolve_node(lid, ref, exact=True) for ref in nodes]
        labels = [str(n.get("label")) for n in targets]
        if dupes := sorted({x for x in labels if labels.count(x) > 1}):
            raise InvalidRequest(f"Each node only once: {dupes}")
        given = vars or {}
        by_ref = {ref: str(n.get("label")) for ref, n in zip(nodes, targets, strict=True)}
        node_vars: dict[str, dict[str, str]] = {label: {} for label in labels}
        blockers: list[str] = []
        for key, given_values in given.items():
            label = by_ref.get(key) or (key if key in node_vars else None)
            if label is None:
                blockers.append(f"vars names {key!r}, which is not one of the nodes being configured")
                continue
            blockers += vars_problems(label, given_values)
            node_vars[label].update({k: str(v) for k, v in given_values.items()})
        if bad := [ln for ln in lines if LAB_REF.search(ln)]:
            blockers.append(
                f"Lines with ${{LAB_*}} lab-secret references: {[mask_secrets(x) for x in bad]}. This tool "
                "does not fill in lab secrets; put them in a recipe or lab file (cml_build_recipe)"
            )
        if shadowed := sorted({k for v in node_vars.values() for k in v if k == "label"}):
            blockers.append(f"vars can't override the built-in {shadowed}")
        used = placeholders(lines)
        mgmt: dict[str, str] = {}
        need = [n for n in targets if "mgmt_ip" not in node_vars[str(n["label"])]]
        if "mgmt_ip" in used and need:
            mgmt = await mgmt_addresses(app, lid, need)
        rendered: dict[str, list[str]] = {}
        for n in targets:
            label = str(n.get("label"))
            values: dict[str, str] = {"label": label, **({"mgmt_ip": mgmt[label]} if label in mgmt else {})}
            values.update(node_vars[label])
            out, missing = render(lines, values)
            if missing:
                hint = (
                    " (no management address found: pass vars[node].mgmt_ip)" if "mgmt_ip" in missing else ""
                )
                blockers.append(f"{label}: no value for {missing}{hint}")
            if n.get("state") != "BOOTED":
                blockers.append(f"{label} is {n.get('state')}; it must be BOOTED")
            rendered[label] = out
        unused = sorted({k for v in node_vars.values() for k in v} - used - set(BUILTINS))
        all_lines = [line for out in rendered.values() for line in out]
        for b in line_blockers(all_lines, mode=mode, save=save, settings=settings):
            if b not in blockers:
                blockers.append(b)
        plan = Plan(
            f"Configure {len(targets)} node(s) in {info.get('lab_title')!r} via their consoles "
            f"({len(lines)} {mode} lines each)" + (" and save" if save and mode == "config" else ""),
            details={
                "nodes": {label: [mask_secrets(x) for x in out] for label, out in rendered.items()},
                "save": save,
                "mode": mode,
                "answer_questions": answer_questions,
                **({"unused_vars": unused} if unused else {}),
            },
            fingerprint={label: n.get("state") for label, n in zip(labels, targets, strict=True)},
            blockers=blockers,
            blast_radius=len(targets),
            undo=cli_back_out(f"each of the {len(targets)} node(s)", mode, save),
        )

        async def apply() -> Any:
            creds = await lab_credentials(app, lid)
            slot = asyncio.Semaphore(PARALLEL_NODES)

            async def one(n: dict[str, Any]) -> dict[str, Any]:
                label = str(n.get("label"))
                try:
                    res = await push_lines(
                        app,
                        lid,
                        n,
                        creds.get(label, Credentials()),
                        rendered[label],
                        mode=mode,
                        save=save,
                        answer_questions=answer_questions,
                        line_timeout=line_timeout,
                        purpose="cml_configure_nodes",
                        slot=slot,
                    )
                except Exception as e:  # report per node; the others carry on
                    return {"node": label, "error": mask_secrets(str(e))[:500] or type(e).__name__}
                return {"node": label, **res}

            results = list(await asyncio.gather(*(one(n) for n in targets)))
            failed = [r["node"] for r in results if r.get("error") or r.get("rejected")]
            return {
                "results": results,
                "nodes_ok": len(results) - len(failed),
                **({"nodes_with_problems": failed} if failed else {}),
            }

        return await preview_or_apply(
            ctx,
            tool="cml_configure_nodes",
            args={
                "lab": lab,
                "nodes": nodes,
                "lines": lines,
                "vars": vars,
                "save": save,
                "mode": mode,
                "answer_questions": answer_questions,
                "line_timeout": line_timeout,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
