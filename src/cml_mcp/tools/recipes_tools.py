"""Lab recipes as tools: list/describe them (read), build one (write), and the cml_build_test_lab prompt."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import re
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import Confirm, ResponseFormat, Tier, ToolRegistrar, get_client, list_result, tool_ref
from stutters_mcp_core.http import page_of

from cml_mcp.build import NodeSpec
from cml_mcp.client import CmlApp
from cml_mcp.console import mask_secrets
from cml_mcp.recipes import get_recipe, recipe_licensed_nodes, recipe_names
from cml_mcp.tools.build_tool import build_lab_flow
from cml_mcp.tools.common import shaped
from cml_mcp.tools.lab_writes import Wait
from cml_mcp.tools.smart import Timeout
from cml_mcp.topology import address_annotations, config_addresses, place_notes

RecipeName = Annotated[str, Field(description="Recipe name (see cml_list_recipes), e.g. 'ise-access'")]
# Fields that describe the product side of a recipe (what the fmc/catc/ise server must configure).
PRODUCT_SIDE = re.compile(r"(?:_side|_discovery)$")
SECRET_IN_TEXT = re.compile(
    r"(?i)(?:secret|password|passwd|key|community|regkey|adminpassword|psk)[\"'\s:=]+(?:\d\s+)?([^\s\"',}]+)"
)


def recipe_secrets(recipe: dict[str, Any]) -> set[str]:
    """Every credential-looking value in a recipe: node logins and secrets in configs/descriptions."""
    found: set[str] = set()
    for node in recipe["build"].get("nodes") or []:
        for k, v in (node.get("credentials") or {}).items():
            if "password" in k and v:
                found.add(str(v))
        for text in (node.get("config"), *(f.get("content") for f in node.get("files") or [])):
            if text:
                found.update(SECRET_IN_TEXT.findall(str(text)))
    for key in ("credentials", "fmc_side", "ise_side", "catalyst_center_discovery"):
        found.update(SECRET_IN_TEXT.findall(str(recipe.get(key) or "")))
    for text in re.findall(
        r"(?i)\b(?:\w+\s*/\s*)(\S+?)(?:\s*/\s*(\S+?))?(?=[\s,)]|$)", str(recipe.get("credentials"))
    ):
        found.update(t for t in text if t)
    return {s for s in found if len(s) >= 4 and s.lower() not in {"none", "same", "true", "false"}}


def scrub(value: Any, secrets: set[str]) -> Any:
    """`value` with every known secret replaced and config-style secrets masked."""
    if isinstance(value, dict):
        return {k: scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    for s in sorted(secrets, key=len, reverse=True):
        value = value.replace(s, "********")
    return mask_secrets(value)


def recipe_detail(name: str) -> Any:
    r = get_recipe(name)
    secrets = recipe_secrets(r)
    product = {k: v for k, v in r.items() if PRODUCT_SIDE.search(k)}
    verify = r.get("verify") or {}
    return scrub(
        {
            "name": name,
            "lab": r["build"]["title"],
            "summary": r.get("summary"),
            "licensed_nodes": recipe_licensed_nodes(r),
            "boot_minutes": r.get("boot_minutes"),
            "address_plan": r.get("address_plan"),
            "product_side": product,
            "credentials": {
                "where": f"cml_mcp/recipes/{name}.yaml on the cml-mcp-server host, section 'credentials' "
                "(lab-only values; never returned by tools)",
                "keys": sorted((r.get("credentials") or {}).keys()),
            },
            "verify": {
                "pings": f"{verify.get('nodes', [])} -> {verify.get('targets', [])}",
                "addresses": verify.get("addresses", {}),
                "probes": [p.get("name") for p in verify.get("probes") or []],
            },
            "nodes": [
                {"label": n["label"], "definition": n["definition"]} for n in r["build"].get("nodes") or []
            ],
            "links": r["build"].get("links") or [],
        },
        secrets,
    )


def recipe_notes(recipe_name: str) -> list[dict[str, Any]]:
    """Purpose, address plan and credential *references* of a recipe (no secret values)."""
    r = get_recipe(recipe_name)
    secrets = recipe_secrets(r)
    plan = r.get("address_plan") or {}
    purpose = "\n".join(
        [
            f"cml-mcp-server recipe: {recipe_name}",
            str(r.get("summary") or ""),
            "Verify: cml_verify_recipe(recipe='" + recipe_name + "')",
        ]
    )
    addr = "Address plan\n" + "\n".join(f"{k}: {v}" for k, v in plan.items()) if plan else ""
    creds = (
        "Credentials: not shown here. See cml_list_recipes(recipe='"
        + recipe_name
        + "') -> credentials.where"
        + (
            f" (keys: {', '.join(sorted((r.get('credentials') or {}).keys()))})"
            if r.get("credentials")
            else ""
        )
    )
    return [{"text": scrub(t, secrets), "bold": i == 0} for i, t in enumerate([purpose, addr, creds]) if t]


def recipe_annotations(name: str) -> list[dict[str, Any]]:
    """Text annotations a recipe's lab is built with: purpose/address plan/credential references
    left of the lab and each node's day-0 addresses under it."""
    nodes = [
        {"label": n["label"], "x": n.get("x", 0), "y": n.get("y", 0)}
        for n in get_recipe(name)["build"]["nodes"]
    ]
    addresses = {
        n["label"]: rows
        for n in get_recipe(name)["build"]["nodes"]
        if (rows := config_addresses(n["definition"], n.get("config")))
    }
    return place_notes(recipe_notes(name), nodes) + address_annotations(nodes, addresses)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List lab recipes")
    async def cml_list_recipes(
        ctx: Context,
        recipe: Annotated[
            str | None, Field(description="Describe this recipe in full (default: list all recipes)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Ready-made test labs for the other suite servers (FTDv for FMC, IOS-XE routers for Catalyst
        Center, a Cat9kv 802.1X switch for ISE). Without `recipe`: name, lab title, current lab state,
        licensed nodes and boot time for each. With `recipe`: its address plan, what to configure on
        the product side (FMC registration, ISE NAD, CatC discovery), nodes, links and the verify
        checks. Credentials are never returned, only where they are kept. Build one with
        cml_build_recipe, check it with cml_verify_recipe."""
        app: CmlApp = get_client(ctx)
        states = {lab.get("lab_title"): lab.get("state") for lab in await app.list_labs()}
        if recipe:
            detail = recipe_detail(recipe)
            detail["lab_state"] = states.get(detail["lab"], "not built")
            return shaped(detail)
        rows = []
        for name in recipe_names():
            r = get_recipe(name)
            rows.append(
                {
                    "name": name,
                    "lab": r["build"]["title"],
                    "lab_state": states.get(r["build"]["title"], "not built"),
                    "licensed_nodes": recipe_licensed_nodes(r),
                    "boot_minutes": r.get("boot_minutes"),
                    "summary": scrub(r.get("summary"), recipe_secrets(r)),
                }
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Build a lab recipe")
    async def cml_build_recipe(
        ctx: Context,
        recipe: RecipeName,
        title: Annotated[
            str | None,
            Field(
                min_length=1,
                max_length=64,
                description="Build it under another lab title (a copy next to the recipe's own lab, e.g. "
                "for trying changes); default: the recipe's title",
            ),
        ] = None,
        start: Annotated[bool, Field(description="Start the lab after building it")] = True,
        wait: Wait = False,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build a recipe's lab (see cml_list_recipes) exactly as packaged - nodes, day-0 configs with
        their lab credentials, links, and text annotations with the recipe's purpose, address plan and
        where the credentials are kept (never the values) - and by default start it without waiting
        (FTDv and cat9000v take 10-30 minutes: follow up with cml_wait_for_converged, then
        cml_verify_recipe). Refuses if the lab already exists: start that one with cml_start_lab
        instead, or pass `title` to build a copy. Preview-first; the preview shows wiring and licence
        use."""
        r = get_recipe(recipe)
        b = r["build"]
        nodes = [NodeSpec.model_validate(n) for n in b.get("nodes") or []]
        return await build_lab_flow(
            ctx,
            tool="cml_build_recipe",
            tool_args={"recipe": recipe, "title": title, "start": start, "wait": wait, "timeout": timeout},
            title=title or b["title"],
            annotations=recipe_annotations(recipe),
            nodes=nodes,
            links=list(b.get("links") or []),
            description=b.get("description"),
            start=start,
            wait=wait,
            timeout=timeout,
            confirm=confirm,
        )

    @reg.prompt(title="Build a test lab from a recipe", uses=["cml"], tier=Tier.WRITE)
    def cml_build_test_lab(
        recipe: Annotated[
            str,
            Field(
                description="Recipe name: ftd-fmc (for FMC), catc-routers (Catalyst Center), ise-access (ISE)"
            ),
        ],
        reuse: Annotated[
            bool, Field(description="Reuse the recipe's lab if it already exists (default true)")
        ] = True,
    ) -> str:
        """Get a working, verified lab device for testing another suite server: picks the recipe,
        frees node licences if needed, builds or starts its lab, waits for the boot, verifies it
        (addresses, reachability, product probes) and ends with a hand-off block for the FMC,
        Catalyst Center or ISE server (addresses, what to configure there, where the credentials
        are kept)."""
        rebuild = (
            "" if reuse else "reuse=false was given, so ask whether to delete and rebuild it; otherwise "
        )
        return f"""Bring up the CML test lab for recipe '{recipe}' and hand it over to the product server.

1. Call {tool_ref("cml_list_recipes")} with recipe="{recipe}" to read its lab title, nodes, address plan,
   product-side steps and boot time. If the recipe doesn't exist, list recipes and ask which one to use.
2. Call {tool_ref("cml_plan_licences")} with target="{recipe}". If plan.stop lists labs, show the plan and
   ask before stopping anything: those labs may belong to someone else's session. Stop only the
   approved ones with {tool_ref("cml_stop_lab")}.
3. Bring the lab up:
   - lab_state 'not built': {tool_ref("cml_build_recipe")} with recipe="{recipe}" (start=true, wait=false).
   - lab exists but not STARTED: {rebuild}{tool_ref("cml_start_lab")} with the lab title and wait=false.
   - already STARTED: {"go straight to step 4." if reuse else "ask whether to reuse it as it is."}
   Every write is preview-first: show the preview and wait for the user's approval before confirming.
4. Call {tool_ref("cml_wait_for_converged")} on the lab (timeout up to 2400 s for FTDv; report progress).
   Mention any hint it returns (cat9000v forwards 2-3 minutes after BOOTED).
5. Call {tool_ref("cml_verify_recipe")} with recipe="{recipe}". If a check fails, wait a few minutes and
   verify again once (slow data planes); if it still fails, show the failing checks and use
   {tool_ref("cml_run_commands")} / {tool_ref("cml_get_node_console_log")} to find out why before going on.
6. Finish with a hand-off block for the product server's builder, from the recipe details:
   - lab title and node addresses (address_plan), and the verify result (passed n/m);
   - what to configure on the product side (product_side: FMC registration / ISE network device /
     Catalyst Center discovery), with secrets left as references;
   - where the credentials are kept (credentials.where) - never print passwords, keys or communities;
   - how to stop the lab afterwards ({tool_ref("cml_stop_lab")}) to free licences."""
