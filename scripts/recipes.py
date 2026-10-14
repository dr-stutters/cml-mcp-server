"""Build, start, verify and stop the reusable lab recipes in recipes/*.yaml through the MCP tools.

    uv run python scripts/recipes.py list
    uv run python scripts/recipes.py build catc-routers [--start] [--no-wait] [--recreate]
    uv run python scripts/recipes.py wait catc-routers            # until every node has booted
    uv run python scripts/recipes.py verify catc-routers          # ping the recipe's targets
    uv run python scripts/recipes.py stop catc-routers            # stop (keep the lab defined)

Each recipe's `build:` section is exactly the argument set of the cml_build_lab tool, so a model can
also build it with that one tool call. The script drives the tools the same way a model would
(preview, then confirm), using the controller in .env with writes enabled for this process only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from fastmcp import Client
from stutters_mcp_core.testing import live_settings

from cml_mcp.config import Settings
from cml_mcp.server import create_server

RECIPES = Path(__file__).resolve().parent.parent / "recipes"


def load(name: str) -> dict[str, Any]:
    path = RECIPES / f"{name}.yaml"
    if not path.exists():
        sys.exit(f"No recipe {name!r}; have: {', '.join(p.stem for p in sorted(RECIPES.glob('*.yaml')))}")
    data: dict[str, Any] = yaml.safe_load(path.read_text())
    return data


async def call(c: Client, tool: str, args: dict[str, Any], *, write: bool = False) -> Any:
    res = await c.call_tool(tool, args, raise_on_error=False)
    data = res.structured_content if res.structured_content is not None else res.content[0].text
    if res.is_error:
        raise SystemExit(f"{tool} failed: {data}")
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


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["list", "show", "build", "start", "wait", "verify", "stop"])
    ap.add_argument("recipe", nargs="?")
    ap.add_argument("--start", action="store_true", help="build: start the lab after building it")
    ap.add_argument("--no-wait", action="store_true", help="build/start: don't wait for the boot")
    ap.add_argument("--recreate", action="store_true", help="build: delete an existing lab first")
    ap.add_argument("--timeout", type=float, default=2400, help="seconds to wait for boots")
    args = ap.parse_args()
    if args.action == "list":
        for p in sorted(RECIPES.glob("*.yaml")):
            r = yaml.safe_load(p.read_text())
            print(f"{p.stem:16} {r['build']['title']:18} {r.get('summary', '')}")
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
