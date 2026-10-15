"""Build, start, verify and stop the lab recipes (src/cml_mcp/recipes/*.yaml) through the MCP tools.

    uv run python scripts/recipes.py list
    uv run python scripts/recipes.py build catc-routers [--start] [--no-wait] [--recreate]
    uv run python scripts/recipes.py wait catc-routers            # until every node has booted
    uv run python scripts/recipes.py verify catc-routers          # ping the recipe's targets
    uv run python scripts/recipes.py stop catc-routers            # stop (keep the lab defined)
    uv run python scripts/recipes.py plan ise-access              # which labs would have to stop
    uv run python scripts/recipes.py swap ise-access [--yes]      # stop those (asks first), start/build it

Each recipe's `build:` section is exactly the argument set of the cml_build_lab tool, so a model can
also build it with that one tool call. The script drives the tools the same way a model would
(preview, then confirm), using the controller in .env with writes enabled for this process only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

import yaml
from fastmcp import Client
from stutters_mcp_core.testing import live_settings

from cml_mcp.config import Settings
from cml_mcp.recipes import get_recipe, recipe_names
from cml_mcp.server import create_server


def load(name: str) -> dict[str, Any]:
    if name not in recipe_names():
        sys.exit(f"No recipe {name!r}; have: {', '.join(recipe_names())}")
    return get_recipe(name)


async def call(c: Client, tool: str, args: dict[str, Any], *, write: bool = False) -> Any:
    res = await c.call_tool(tool, args, raise_on_error=False)
    data = res.structured_content if res.structured_content is not None else res.content[0].text
    if res.is_error:
        raise SystemExit(f"{tool} failed: {data}")
    if write and isinstance(data, dict) and data.get("status") == "blocked":
        raise SystemExit(f"{tool} is blocked: {data.get('blockers')}")
    if write and isinstance(data, dict) and data.get("confirm"):
        if data.get("blockers"):
            raise SystemExit(f"{tool} is blocked: {data['blockers']}")
        res = await c.call_tool(tool, {**args, "confirm": data["confirm"]}, raise_on_error=False)
        data = res.structured_content if res.structured_content is not None else res.content[0].text
        if res.is_error:
            raise SystemExit(f"{tool} failed: {data}")
    return data


async def lab_exists(c: Client, title: str) -> bool:
    data = await call(c, "cml_list_labs", {"response_format": "json", "limit": 500})
    return any(row.get("title") == title or row.get("lab_title") == title for row in data.get("results", []))


async def swap(
    c: Client, name: str, recipe: dict[str, Any], *, wait: bool, limit: float, assume_yes: bool
) -> Any:
    """Stop the labs the licence plan names, then start the recipe's lab (building it if missing).

    The labs to stop may belong to someone else's running session: it lists them and asks before
    stopping anything unless --yes is given."""
    title = recipe["build"]["title"]
    plan = await call(c, "cml_plan_licences", {"target": name})
    if plan["plan"].get("feasible") is False:
        raise SystemExit(f"Can't run {name}: {plan['plan']['summary']}")
    if plan["plan"].get("feasible") is None:
        print(
            f"licence limit unknown, starting without stopping anything: {plan['plan']['summary']}",
            file=sys.stderr,
        )
    stopped = []
    to_stop = plan["plan"].get("stop") or []
    if to_stop and not assume_yes:
        names = ", ".join(f"{lab['title']} [{lab['id']}] ({lab['running']} nodes)" for lab in to_stop)
        answer = await asyncio.to_thread(input, f"Stop {names} to free licences? [y/N] ")
        if answer.strip().lower() != "y":
            raise SystemExit("nothing changed")
    for lab in to_stop:
        print(f"stopping {lab['title']!r} ({lab['running']} licensed nodes)", file=sys.stderr)
        await call(c, "cml_stop_lab", {"lab": lab["id"]}, write=True)
        stopped.append(lab["title"])
    if plan["lab"].get("exists") is False:
        print(f"building {title!r}", file=sys.stderr)
        build = {**recipe["build"], "start": True, "wait": wait, "timeout": limit}
        started = await call(c, "cml_build_lab", build, write=True)
    else:
        print(f"starting {title!r}", file=sys.stderr)
        started = await call(c, "cml_start_lab", {"lab": title, "wait": wait, "timeout": limit}, write=True)
    return {"stopped": stopped, "started": title, "result": started}


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "action", choices=["list", "show", "build", "start", "wait", "verify", "stop", "plan", "swap"]
    )
    ap.add_argument("recipe", nargs="?")
    ap.add_argument("--start", action="store_true", help="build: start the lab after building it")
    ap.add_argument("--no-wait", action="store_true", help="build/start: don't wait for the boot")
    ap.add_argument("--recreate", action="store_true", help="build: delete an existing lab first")
    ap.add_argument("--yes", action="store_true", help="swap: stop the planned labs without asking")
    ap.add_argument("--timeout", type=float, default=2400, help="seconds to wait for boots")
    args = ap.parse_args()
    if args.action == "list":
        for name in recipe_names():
            r = get_recipe(name)
            print(f"{name:16} {r['build']['title']:18} {r.get('summary', '')}")
        return
    if not args.recipe:
        sys.exit("give a recipe name (see 'list')")
    recipe = load(args.recipe)
    title = recipe["build"]["title"]
    if args.action == "show":
        print(yaml.safe_dump({k: v for k, v in recipe.items() if k != "build"}, sort_keys=False))
        return
    settings = live_settings(Settings, "CML_", mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(settings), timeout=args.timeout + 120) as c:
        if args.action == "build":
            if await lab_exists(c, title):
                if not args.recreate:
                    sys.exit(f"Lab {title!r} exists; use --recreate to rebuild it, or 'start'")
                await call(c, "cml_delete_lab", {"lab": title, "force": True}, write=True)
            build = {**recipe["build"], "start": args.start, "wait": not args.no_wait}
            build["timeout"] = args.timeout
            out = await call(c, "cml_build_lab", build, write=True)
        elif args.action == "plan":
            out = await call(c, "cml_plan_licences", {"target": args.recipe})
        elif args.action == "swap":
            out = await swap(
                c, args.recipe, recipe, wait=not args.no_wait, limit=args.timeout, assume_yes=args.yes
            )
        elif args.action == "start":
            out = await call(
                c,
                "cml_start_lab",
                {"lab": title, "wait": not args.no_wait, "timeout": args.timeout},
                write=True,
            )
        elif args.action == "wait":
            out = await call(c, "cml_wait_for_converged", {"lab": title, "timeout": args.timeout})
        elif args.action == "verify":
            v = recipe["verify"]
            out = await call(c, "cml_check_reachability", {"lab": title, **v})
            addresses = await call(c, "cml_get_layer3_addresses", {"lab": title, "source": "cli"})
            out = {"reachability": out, "addresses": addresses.get("cli")}
        else:
            out = await call(c, "cml_stop_lab", {"lab": title}, write=True)
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    asyncio.run(main())
