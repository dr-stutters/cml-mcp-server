"""Recipes and licence planning (read tools)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import NotFound, ToolRegistrar, get_client

from cml_mcp.client import CmlApp
from cml_mcp.licence import (
    RUNNING_STATES,
    licence_usage,
    licensed,
    nodes_ram_mb,
    plan_stops,
    plan_text,
    ram_check,
    ram_headroom,
    stop_candidates,
)
from cml_mcp.recipes import get_recipe, recipe_licensed_nodes, recipe_names
from cml_mcp.tools.common import shaped
from cml_mcp.verify import verify_recipe


async def plan_for(app: CmlApp, target: str) -> dict[str, Any]:
    """Licence plan for a recipe name or a lab title/id (shared by the tool and scripts/recipes.py)."""
    target = target.strip()
    recipe = get_recipe(target) if target in recipe_names() else None
    title = recipe["build"]["title"] if recipe else target
    lab: dict[str, Any] | None
    try:
        lab = await app.resolve_lab(title, exact=True)
    except NotFound:
        if not recipe:
            raise
        lab = None
    from cml_mcp.tools.lab_writes import known_definitions  # tools import each other lazily

    defs = await known_definitions(app)
    if lab:
        nodes = await app.list_nodes(lab["id"])
        needed = sum(1 for n in nodes if licensed(n) and n.get("state") not in RUNNING_STATES)
        total = sum(1 for n in nodes if licensed(n))
        ram_mb = nodes_ram_mb([n for n in nodes if n.get("state") not in RUNNING_STATES], defs)
    else:
        needed = total = recipe_licensed_nodes(recipe) if recipe else 0
        ram_mb = nodes_ram_mb(recipe["build"].get("nodes") or [], defs) if recipe else 0
    usage = await licence_usage(app)
    memory = ram_check(await ram_headroom(app), ram_mb)
    out: dict[str, Any] = {
        "target": target,
        **({"recipe": target} if recipe else {}),
        "lab": {"title": lab.get("lab_title"), "id": lab["id"], "state": lab.get("state")}
        if lab
        else {"title": title, "exists": False},
        "licensed_nodes": total,
        "needed_to_start": needed,
        "licences": {
            k: usage[k]
            for k in (
                "limit",
                "limit_source",
                "running_licensed_nodes",
                "free",
                "by_lab",
                "scope",
                "resource_pool",
            )
            if k in usage
        },
    }
    if "limit" not in usage:
        out["plan"] = {
            "feasible": None,
            "summary": f"The licence limit is unknown ({usage.get('limit_source')}); CML will refuse "
            "starts beyond it with '<n> of <n> node licenses are in use'.",
        }
        return out
    if total > usage["limit"]:
        out["plan"] = {"feasible": False, "stop": None, "summary": plan_text(None)}
        return out
    stops = plan_stops(stop_candidates(usage), needed, usage["free"], exclude=lab["id"] if lab else None)
    out["plan"] = {
        "feasible": stops is not None,
        "stop": [{"title": s["title"], "id": s["id"], "running": s["running"]} for s in stops or []],
        "summary": plan_text(stops),
    }
    if memory:
        out["ram"] = memory
        if not memory["ok"]:
            out["plan"]["summary"] += " " + memory["warning"]
    if stops:
        out["next"] = "cml_stop_lab on each lab in plan.stop, then " + (
            "cml_start_lab" if lab else "cml_build_lab with the recipe's build section"
        )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Plan node licences")
    async def cml_plan_licences(
        ctx: Context,
        target: Annotated[
            str,
            Field(description="A recipe name (e.g. 'ise-access') or a lab title/id to start"),
        ],
    ) -> ToolResult:
        """Can this lab or recipe start now, and if not, which labs should stop? Returns the licensed
        nodes running per lab, what the target still needs, and the smallest set of labs to stop
        (fewest labs, preferring test labs: recipes and mcp-* titles). The limit is read from the
        licensing API (base licence plus expansion nodes; 5 in evaluation mode) unless
        CML_NODE_LICENSE_LIMIT overrides it, or from the account's resource pool when that is tighter
        (or when a non-admin account can't read the licence); external connectors and unmanaged
        switches don't count. A non-admin account only sees its own and shared labs (`scope`).
        `ram` compares the RAM the target needs with the controller's free memory (with 70 licences,
        RAM is usually the real limit). Changes nothing: stop the listed labs with cml_stop_lab or
        cml_stop_labs."""
        return shaped(await plan_for(get_client(ctx), target))

    @reg.read(title="Verify a lab recipe", idempotent=False, task=True)
    async def cml_verify_recipe(
        ctx: Context,
        recipe: Annotated[
            str, Field(description="Recipe name, e.g. 'ftd-fmc', 'ftd-ha', 'catc-routers', 'ise-access'")
        ],
        lab: Annotated[
            str | None,
            Field(description="Verify this lab (a copy of the recipe) instead of the recipe's own"),
        ] = None,
        substitute: Annotated[
            dict[str, str] | None,
            Field(
                max_length=20,
                description="The substitutions the copy was built with (default: read from the lab's notes)",
            ),
        ] = None,
    ) -> ToolResult:
        """Check that a recipe's running lab is known-good before another server's tests rely on
        it. Runs the recipe's verify contract and returns pass/fail per check: nodes BOOTED,
        expected addresses on each node (from its CLI), a ping matrix to the appliances, and
        product probes - FTD 'show managers' points at FMC, IOS-XE SSH/NETCONF/SNMP answer from
        this server, the switch's RADIUS server is UP and answers 'test aaa'. Changes no
        configuration (console probes come only from the packaged recipe and must be read-only),
        but the RADIUS test leaves a failed authentication for user 'mcp-test-probe' in ISE's logs,
        so it isn't idempotent. Start the lab first (cml_plan_licences, then cml_start_lab). For a
        copy built with cml_build_recipe(title=...), pass `lab`: the substitutions it was built with
        are read from the lab's notes (pass `substitute` only for copies built before v0.9.0)."""
        return shaped(await verify_recipe(get_client(ctx), recipe, lab=lab, substitute=substitute))
