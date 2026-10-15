"""Device configuration diffs through the console (read tier: 'show running-config')."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import InvalidRequest, ToolRegistrar, get_client

from cml_mcp.client import CmlApp
from cml_mcp.console import Credentials
from cml_mcp.diff import diff_configs, normalise_config
from cml_mcp.netops import console_batch
from cml_mcp.tools.common import LabRef, NodeRef, config_text, shaped

# OSes whose CLI has 'show running-config' / 'show startup-config'.
NO_RUNNING_CONFIG = frozenset({"linux"})
SAVED_UNSUPPORTED = frozenset({"fxos", "ftd", "linux"})


async def device_configs(
    app: CmlApp,
    lab_id: str,
    nodes: list[dict[str, Any]],
    *,
    which: str = "running",
    purpose: str,
    strict: bool = True,
) -> dict[str, str]:
    """{node label: config text (secrets masked)} read from each booted node's console. With
    strict, raises InvalidRequest naming the nodes that failed; otherwise they are left out."""

    def commands(_n: dict[str, Any], cred: Credentials) -> list[str]:
        os_name = (cred.os or "").lower()
        if os_name in NO_RUNNING_CONFIG or (which == "startup" and os_name in SAVED_UNSUPPORTED):
            return []
        return [f"show {which}-config"]

    results = await console_batch(app, lab_id, nodes, commands, timeout=120, purpose=purpose)
    out: dict[str, str] = {}
    problems = []
    for r in results:
        outputs = r.get("outputs") or []
        if r.get("error") or not outputs or outputs[0].get("error"):
            problems.append(f"{r['node']}: {r.get('error') or (outputs[0].get('error') if outputs else '?')}")
            continue
        text = str(outputs[0].get("output") or "")
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        if first.startswith(("%", "Invalid", "ERROR")):
            problems.append(f"{r['node']}: {first[:200]}")
            continue
        out[str(r["node"])] = text
    if problems and strict:
        raise InvalidRequest(f"Could not read the {which} configuration: " + "; ".join(problems))
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Diff a node's configuration", idempotent=False)
    async def cml_diff_node_config(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        against: Annotated[
            Literal["day0", "saved", "node", "text"],
            Field(
                description="Compare the running config with: 'day0' = the node's configuration stored "
                "in CML (what it booted with, or the last cml_extract_node_configs); 'saved' = the "
                "device's startup-config; 'node' = another node's running config (other_node, "
                "optionally in other_lab); 'text' = baseline_text, e.g. an earlier output of this tool"
            ),
        ] = "day0",
        other_node: Annotated[str | None, Field(description="With against='node': the other node")] = None,
        other_lab: Annotated[
            str | None, Field(description="With against='node': the other node's lab (default: same lab)")
        ] = None,
        baseline_text: Annotated[
            str | None, Field(description="With against='text': the configuration to compare with")
        ] = None,
        context: Annotated[int, Field(ge=0, le=10, description="Unchanged lines around each change")] = 2,
        max_lines: Annotated[int, Field(ge=10, le=2000, description="Cap on diff lines returned")] = 200,
        ignore: Annotated[
            list[str] | None,
            Field(description="Regular expressions; matching lines are left out on both sides"),
        ] = None,
        include_running: Annotated[
            bool, Field(description="Also return the (masked) running config, e.g. as a later baseline")
        ] = False,
    ) -> ToolResult:
        """What changed on a lab device? Reads the node's running configuration over its console
        ('show running-config', no IP reachability needed) and returns a unified diff against its
        CML day-0 config, its startup-config, another node, or a saved baseline. Secrets
        (passwords, keys, communities) are masked on both sides and volatile lines (timestamps,
        'Building configuration') are ignored. Use it as the test oracle for changes another
        server pushed (a Catalyst Center template, an ISE AAA change): take a baseline with
        include_running=true, make the change, then diff with against='text'. IOS/IOS-XE, NX-OS,
        ASA and FTD ('saved' isn't available on FTD); not Linux nodes. Because secrets are masked,
        a changed password or key with the same keyword does not show up as a difference."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        n = await app.resolve_node(lid, node)
        label = str(n.get("label"))
        if n.get("state") != "BOOTED":
            raise InvalidRequest(f"{label!r} is {n.get('state')}; its console needs a BOOTED node")
        if against == "node" and not other_node:
            raise InvalidRequest("against='node' needs other_node")
        if against == "text" and baseline_text is None:
            raise InvalidRequest("against='text' needs baseline_text")
        running = (await device_configs(app, lid, [n], purpose="cml_diff_node_config"))[label]
        if against == "day0":
            full = await app.api.get(f"/labs/{lid}/nodes/{n['id']}")
            other, other_name = config_text(full) or "", f"{label} (day-0 in CML)"
        elif against == "saved":
            saved = await device_configs(app, lid, [n], which="startup", purpose="cml_diff_node_config")
            other, other_name = saved[label], f"{label} (startup-config)"
            if "not present" in other[:200].lower() and len(other) < 200:
                raise InvalidRequest(
                    f"{label!r} has no saved startup-config ({other.strip()!r}); compare with 'day0' instead"
                )
        elif against == "node":
            olab = await app.resolve_lab(other_lab) if other_lab else info
            on = await app.resolve_node(olab["id"], str(other_node))
            if on.get("state") != "BOOTED":
                raise InvalidRequest(f"{on.get('label')!r} is {on.get('state')}; it must be BOOTED")
            got = await device_configs(app, olab["id"], [on], purpose="cml_diff_node_config")
            other, other_name = got[str(on.get("label"))], f"{on.get('label')} (running)"
        else:
            other, other_name = baseline_text or "", "baseline"
        result: dict[str, Any] = {
            "lab": info.get("lab_title"),
            "node": label,
            "against": against,
            **diff_configs(
                other,
                running,
                a_name=other_name,
                b_name=f"{label} (running)",
                context=context,
                max_lines=max_lines,
                ignore=ignore,
            ),
        }
        if include_running:  # normalised: masked, without volatile lines (a clean next baseline)
            result["running_config"] = "\n".join(normalise_config(running))
        return shaped(result)
