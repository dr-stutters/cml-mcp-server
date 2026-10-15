"""Recipes and licence planning (read tools)."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import NotFound, ToolRegistrar, get_client

from cml_mcp.client import CmlApp
from cml_mcp.licence import RUNNING_STATES, licence_usage, licensed, plan_stops, plan_text
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
    if lab:
        nodes = await app.list_nodes(lab["id"])
        needed = sum(1 for n in nodes if licensed(n) and n.get("state") not in RUNNING_STATES)
        total = sum(1 for n in nodes if licensed(n))
    else:
        needed = total = recipe_licensed_nodes(recipe) if recipe else 0
    usage = await licence_usage(app)
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
            for k in ("limit", "limit_source", "running_licensed_nodes", "free", "by_lab")
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
    stops = plan_stops(usage["labs"], needed, usage["free"], exclude=lab["id"] if lab else None)
    out["plan"] = {
        "feasible": stops is not None,
        "stop": [{"title": s["title"], "id": s["id"], "running": s["running"]} for s in stops or []],
        "summary": plan_text(stops),
    }
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
        CML_NODE_LICENSE_LIMIT overrides it; external connectors and unmanaged switches don't count.
        Changes nothing: stop the listed labs with cml_stop_lab."""
        return shaped(await plan_for(get_client(ctx), target))

    @reg.read(title="Verify a lab recipe", idempotent=False)
    async def cml_verify_recipe(
        ctx: Context,
        recipe: Annotated[
            str, Field(description="Recipe name, e.g. 'ftd-fmc', 'ftd-ha', 'catc-routers', 'ise-access'")
        ],
    ) -> ToolResult:
        """Check that a recipe's running lab is known-good before another server's tests rely on
        it. Runs the recipe's verify contract and returns pass/fail per check: nodes BOOTED,
        expected addresses on each node (from its CLI), a ping matrix to the appliances, and
        product probes - FTD 'show managers' points at FMC, IOS-XE SSH/NETCONF/SNMP answer from
        this server, the switch's RADIUS server is UP and answers 'test aaa'. Changes no
        configuration (console probes come only from the packaged recipe and must be read-only),
        but the RADIUS test leaves a failed authentication for user 'mcp-test-probe' in ISE's logs,
        so it isn't idempotent. Start the lab first (cml_plan_licences, then cml_start_lab)."""
        return shaped(await verify_recipe(get_client(ctx), recipe))
