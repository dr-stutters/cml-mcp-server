"""Lab recipes as tools: list/describe them (read), build one (write), and the cml_build_test_lab prompt."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import re
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cml_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ResponseFormat,
    Tier,
    ToolRegistrar,
    get_client,
    get_settings,
    list_result,
    tool_ref,
)
from cml_mcp._core.http import page_of
from cml_mcp.build import NodeSpec
from cml_mcp.client import CmlApp
from cml_mcp.console import mask_secrets
from cml_mcp.netops import console_batch
from cml_mcp.recipes import (
    get_recipe,
    placeholders,
    read_recipe_marker,
    recipe_actions,
    recipe_licensed_nodes,
    recipe_marker,
    recipe_names,
    recipe_source,
    resolve_secrets,
    secret_names_by_value,
    skipped_recipe_files,
    substituted,
)
from cml_mcp.safety import guarded_preview_or_apply
from cml_mcp.tools.build_tool import build_lab_flow
from cml_mcp.tools.common import shaped
from cml_mcp.tools.lab_writes import Wait
from cml_mcp.tools.recipe_extend import extend_lab_flow
from cml_mcp.tools.smart import Timeout
from cml_mcp.topology import address_annotations, config_addresses, place_notes

Substitute = Annotated[
    dict[str, str] | None,
    Field(
        max_length=20,
        description="Text replacements applied to the whole recipe (configs, addresses, verify "
        "contract), e.g. {'198.18.128.154': '198.18.128.194'} for a copy on another address",
    ),
]
BOOT_NOTE = re.compile(r"\s*[(;]|\.\s")  # where the boot time's explanation starts
RecipeName = Annotated[str, Field(description="Recipe name (see cml_list_recipes), e.g. 'ise-access'")]
# Fields that describe the product side of a recipe (what the fmc/catc/ise server must configure).
PRODUCT_SIDE = re.compile(r"(?:_side|_discovery)$")
SECRET_IN_TEXT = re.compile(
    r"(?i)(?<![\w.-])(?:secret|password|passwd|key|community|regkey|adminpassword|psk)(?![\w.-])"
    r"[\"'\s:=]+(?:\d\s+)?(?!(?:generate|chain|config-key|zeroize|import|export|label|pair)\b)([^\s\"',;{}()]+)"
)


def recipe_secrets(recipe: dict[str, Any]) -> set[str]:
    """Every credential-looking value in a recipe: node logins and secrets in configs/descriptions."""
    found: set[str] = set()
    for node in recipe["build"].get("nodes") or []:
        for k, v in (node.get("credentials") or {}).items():
            if "password" in k and v:
                found.add(str(v))
        files = node.get("files") or {}
        file_texts = files.values() if isinstance(files, dict) else (f.get("content") for f in files)
        for text in (node.get("config"), *file_texts):
            if text:
                found.update(SECRET_IN_TEXT.findall(str(text)))
    for key in ("credentials", "fmc_side", "ise_side", "catalyst_center_discovery"):
        found.update(SECRET_IN_TEXT.findall(str(recipe.get(key) or "")))
    for text in re.findall(
        # 'user / password' as the credentials section writes it (not paths like /etc/eaptls)
        r"(?i)\b(?:\w+ / )([^\s/'\"{}]+?)(?: / ([^\s/'\"{}]+?))?(?=[\s,);]|$)",
        str(recipe.get("credentials")),
    ):
        found.update(t for t in text if t)
    return {
        s
        for s in found
        if len(s) >= 4
        and s.lower() not in {"none", "same", "true", "false"}
        # ${LAB_*} references (or a regex's cut-off piece of one) and prose like '(the' aren't secrets
        and "${" not in s
        and not s.startswith("(")
    }


def scrub(value: Any, secrets: set[str]) -> Any:
    """`value` with every known secret replaced and config-style secrets masked."""
    if isinstance(value, dict):
        return {k: scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    for s in sorted(secrets, key=len, reverse=True):
        # whole tokens only: a secret 'eaptls' must not garble the node name 'eaptls-client'
        before = r"(?<![\w.-])" if re.match(r"\w", s) else ""
        after = r"(?![\w-])" if re.search(r"\w$", s) else ""
        value = re.sub(before + re.escape(s) + after, "********", value)
    return mask_secrets(value)


def recipe_detail(name: str) -> Any:
    r = get_recipe(name)
    secrets = recipe_secrets(r)
    product = {k: v for k, v in r.items() if PRODUCT_SIDE.search(k)}
    verify = r.get("verify") or {}
    source = recipe_source(name)
    return scrub(
        {
            "name": name,
            **({"source": source} if source != "package" else {}),
            "lab": r["build"]["title"],
            "summary": r.get("summary"),
            "licensed_nodes": recipe_licensed_nodes(r),
            "boot_minutes": r.get("boot_minutes"),
            "address_plan": r.get("address_plan"),
            "product_side": product,
            "credentials": {
                "where": "${LAB_*} references in the recipe, filled at build time from the server's LAB_* "
                "environment variables or the file named by CML_LAB_SECRETS_FILE (never returned by tools)",
                "references": sorted(placeholders(r)),
                "keys": sorted((r.get("credentials") or {}).keys()),
            },
            "actions": {
                k: {"node": a["node"], "description": a["description"]} for k, a in recipe_actions(r).items()
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


def recipe_notes(recipe_name: str, r: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Purpose, address plan and credential *references* of a recipe (no secret values). `r` is a
    substituted copy; secrets are collected from the packaged recipe too."""
    secrets = recipe_secrets(get_recipe(recipe_name))
    r = r or get_recipe(recipe_name)
    secrets |= recipe_secrets(r)
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


def recipe_annotations(name: str, r: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Text annotations a recipe's lab is built with: purpose/address plan/credential references
    left of the lab and each node's day-0 addresses under it."""
    r = r or get_recipe(name)
    spec = r["build"]["nodes"]
    nodes = [{"label": n["label"], "x": n.get("x", 0), "y": n.get("y", 0)} for n in spec]
    addresses = {
        n["label"]: rows for n in spec if (rows := config_addresses(n["definition"], n.get("config")))
    }
    return place_notes(recipe_notes(name, r), nodes) + address_annotations(nodes, addresses)


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
        cml_build_recipe, check it with cml_verify_recipe. Recipes from the server's CML_RECIPE_DIRS
        show their `source` file; files there that are not used are listed under `skipped`, with why."""
        app: CmlApp = get_client(ctx)
        states = {lab.get("lab_title"): lab.get("state") for lab in await app.list_labs()}
        if recipe:
            detail = recipe_detail(recipe)
            detail["lab_state"] = states.get(detail["lab"], "not built")
            return shaped(detail)
        rows = []
        for name in recipe_names():
            r = get_recipe(name)
            source = recipe_source(name)
            rows.append(
                {
                    "name": name,
                    **({"source": source} if source != "package" else {}),
                    "lab": r["build"]["title"],
                    "lab_state": states.get(r["build"]["title"], "not built"),
                    "licensed_nodes": recipe_licensed_nodes(r),
                    # the list shows the number; the notes are in cml_list_recipes(recipe=...) (L32)
                    "boot_minutes": BOOT_NOTE.split(str(r["boot_minutes"]), maxsplit=1)[0]
                    if r.get("boot_minutes") is not None
                    else None,
                    "summary": scrub(r.get("summary"), recipe_secrets(r)),
                }
            )
        skipped = [f"{s['file']}: {s['problem']}" for s in skipped_recipe_files()]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra={"skipped": skipped} if skipped else None,
        )

    @reg.write(title="Build a lab recipe", task=True)
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
        substitute: Substitute = None,
        start: Annotated[
            bool, Field(description="Start the lab after building it (with extend: start the added nodes)")
        ] = True,
        wait: Wait = False,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        extend: Annotated[
            bool,
            Field(
                description="Grow the existing lab of that title into this recipe in place: add only the "
                "nodes, links and notes it lacks (for a superset recipe of the one it was built from)"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build a recipe's lab (see cml_list_recipes) exactly as written - nodes, day-0 configs with
        their lab credentials, links, and text annotations with the recipe's purpose, address plan and
        where the credentials are kept (never the values) - and by default start it without waiting
        (FTDv and cat9000v take 10-30 minutes: follow up with cml_wait_for_converged, then
        cml_verify_recipe). Refuses if the lab already exists: start that one with cml_start_lab
        instead, or pass `title` (and `substitute` for other addresses) to build a copy; the lab's
        notes record the recipe and substitutions, so cml_verify_recipe(recipe, lab=title) needs
        nothing else. extend=true grows that existing lab instead (a superset recipe of the one it
        was built from, e.g. cat-sdwan-secure on a cat-sdwan-fabric lab): it adds only the missing
        nodes, links, interfaces (on wiped nodes) and notes, starts the added nodes, never changes an
        existing node (a node of another definition or a link end in use blocks) and records the new
        recipe in the lab's notes. Preview-first; the preview shows wiring (or the additions) and
        licence use."""
        r = substituted(get_recipe(recipe), substitute)
        b = r["build"]
        # ${LAB_*} secrets are filled only in what goes to CML (configs, files, logins); the preview shows
        # node names and wiring, and the annotations come from the unresolved recipe
        raw_nodes = b.get("nodes") or []
        for n in raw_nodes:  # validation errors can echo input: check the unresolved spec first
            NodeSpec.model_validate(n)
        secrets_file = get_settings(ctx).lab_secrets_file
        resolved = resolve_secrets(raw_nodes, secrets_file, what=f"recipe {recipe!r}")
        nodes = [NodeSpec.model_validate(n) for n in resolved]
        if extend:
            return await extend_lab_flow(
                ctx,
                tool_args={
                    "recipe": recipe,
                    "title": title,
                    "substitute": substitute,
                    "start": start,
                    "wait": wait,
                    "timeout": timeout,
                    "extend": True,
                },
                recipe=recipe,
                title=title or b["title"],
                nodes=nodes,
                links=list(b.get("links") or []),
                annotations=recipe_annotations(recipe, r),
                substitute=substitute,
                start=start,
                wait=wait,
                timeout=timeout,
                confirm=confirm,
                redact=secret_names_by_value(secrets_file),
            )
        return await build_lab_flow(
            ctx,
            tool="cml_build_recipe",
            tool_args={
                "recipe": recipe,
                "title": title,
                "substitute": substitute,
                "start": start,
                "wait": wait,
                "timeout": timeout,
            },
            title=title or b["title"],
            annotations=recipe_annotations(recipe, r),
            nodes=nodes,
            links=list(b.get("links") or []),
            description=b.get("description"),
            start=start,
            wait=wait,
            timeout=timeout,
            confirm=confirm,
            redact=secret_names_by_value(secrets_file),
            lab_notes=recipe_marker(recipe, substitute),
        )

    @reg.write(title="Run a recipe action")
    async def cml_run_recipe_action(
        ctx: Context,
        recipe: RecipeName,
        action: Annotated[
            str,
            Field(
                min_length=1,
                max_length=64,
                description="Action name from cml_list_recipes(recipe=...) -> actions, e.g. 'login-bob'",
            ),
        ],
        lab: Annotated[
            str | None,
            Field(
                description="A copy of the recipe's lab (cml_build_recipe(title=...)); default: its own lab"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Run one of a recipe's actions on its running lab, e.g. ise-fmc-identity 'login-alice' /
        'login-bob' (802.1X log-in on the client as that AD user, so ISE, and through pxGrid FMC, see the
        other user) or 'logoff'. The command comes from the recipe, never from the caller; the result has
        the node's output and whether it matched the action's expected result (ok). Preview-first."""
        app: CmlApp = get_client(ctx)
        r = get_recipe(recipe)
        actions = recipe_actions(r)
        if action not in actions:
            raise InvalidRequest(
                f"Recipe {recipe!r} has no action {action!r}; actions: {', '.join(actions) or 'none'}"
            )
        a = actions[action]
        title = lab or r["build"]["title"]
        info = await app.resolve_lab(title, exact=True)
        marker = read_recipe_marker(
            info.get("lab_notes") or (await app.api.get(f"/labs/{info['id']}")).get("lab_notes")
        )
        nodes = {str(n.get("label")): n for n in await app.list_nodes(str(info["id"]))}
        node = nodes.get(a["node"])
        blockers = []
        if marker and marker["recipe"] != recipe:
            blockers.append(f"Lab {title!r} was built from recipe {marker['recipe']!r}, not {recipe!r}")
        elif not marker and title != r["build"]["title"]:
            blockers.append(
                f"Lab {title!r} has no record of being built from recipe {recipe!r} (cml_build_recipe "
                "writes one); actions only run on the recipe's own lab or its recorded copies"
            )
        if node is None:
            blockers.append(f"Lab {title!r} has no node {a['node']!r}")
        elif node.get("state") != "BOOTED":
            blockers.append(f"Node {a['node']!r} is {node.get('state')}; it must be BOOTED")
        plan = Plan(
            f"Run recipe action {action!r} on {a['node']!r} in lab {title!r}",
            details={"description": a["description"], "node": a["node"], "command": a["command"]},
            fingerprint=(node or {}).get("state"),
            blockers=blockers,
        )

        async def apply() -> Any:
            assert node is not None
            batch = await console_batch(
                app,
                str(info["id"]),
                [node],
                lambda n, cred: [a["command"]],
                timeout=a["timeout"],
                purpose="cml_run_recipe_action",
            )
            res: dict[str, Any] = batch[0] if batch else {"error": "no console result"}
            if res.get("error"):
                return {"action": action, "node": a["node"], "ok": False, "error": res["error"]}
            out: dict[str, Any] = (res.get("outputs") or [{}])[0]
            text = str(out.get("output") or "")
            ok = "error" not in out and (not a["expect"] or bool(re.search(a["expect"], text)))
            result: dict[str, Any] = {
                "action": action,
                "node": a["node"],
                "ok": ok,
                "output": text.strip()[-1500:],
            }
            if "error" in out:
                result["error"] = out["error"]
            return result

        return await guarded_preview_or_apply(
            ctx,
            tool="cml_run_recipe_action",
            args={"recipe": recipe, "action": action, "lab": title, "node": a["node"]},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.prompt(title="Build a test lab from a recipe", uses=["cml"], tier=Tier.WRITE)
    def cml_build_test_lab(
        recipe: Annotated[
            str,
            Field(
                description="Recipe name: ftd-fmc (for FMC), ftd-ha (FMC HA pair), catc-routers (Catalyst "
                "Center), ise-access (ISE), ise-fmc-identity (ISE + FMC user-based firewall)"
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
