"""Build, start, verify and stop the lab recipes (src/cml_mcp/recipes/*.yaml) through the MCP tools.

    uv run python scripts/recipes.py list
    uv run python scripts/recipes.py build catc-routers [--start] [--no-wait] [--recreate]
    uv run python scripts/recipes.py wait catc-routers            # until every node has booted
    uv run python scripts/recipes.py verify catc-routers [--json]  # run the recipe's verify contract
    uv run python scripts/recipes.py stop catc-routers            # stop (keep the lab defined)
    uv run python scripts/recipes.py plan ise-access              # which labs would have to stop
    uv run python scripts/recipes.py swap ise-access [--yes]      # stop those (asks first), start/build it
    uv run python scripts/recipes.py ci [recipe ...] [--summary FILE] [--build-missing]
                                    # verify each recipe in turn; stops only the labs it started

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
        build = {"recipe": name, "start": True, "wait": wait, "timeout": limit}
        started = await call(c, "cml_build_recipe", build, write=True)
    else:
        print(f"starting {title!r}", file=sys.stderr)
        started = await call(c, "cml_start_lab", {"lab": title, "wait": wait, "timeout": limit}, write=True)
    return {"stopped": stopped, "started": title, "result": started}


async def lab_state(c: Client, title: str) -> str | None:
    data = await call(c, "cml_list_labs", {"response_format": "json", "limit": 500})
    for row in data.get("results", []):
        if title in (row.get("title"), row.get("lab_title")):
            return str(row.get("state"))
    return None


async def ci_one(c: Client, name: str, *, limit: float, build_missing: bool) -> dict[str, Any]:
    """Verify one recipe, leaving the controller as it was: a lab that was already running is verified
    as it is; a stopped one is started, verified and stopped again; a missing one is built (with
    --build-missing), verified, stopped and kept. Never stops another lab to free licences."""
    recipe = load(name)
    title = recipe["build"]["title"]
    row: dict[str, Any] = {
        "recipe": name,
        "lab": title,
        "before": None,
        "action": "",
        "result": "",
        "secs": 0,
    }
    t0 = asyncio.get_running_loop().time()
    started_here = False
    try:
        state = row["before"] = await lab_state(c, title)
        if state != "STARTED":
            plan = await call(c, "cml_plan_licences", {"target": name})
            if plan["plan"].get("stop"):
                row.update(
                    action="skipped", result=f"needs licences held by other labs: {plan['plan']['summary']}"
                )
                return row
            if state is None:
                if not build_missing:
                    row.update(action="skipped", result="lab not built (use --build-missing)")
                    return row
                await call(c, "cml_build_recipe", {"recipe": name, "start": True, "wait": False}, write=True)
                row["action"] = "built+started"
            else:
                await call(c, "cml_start_lab", {"lab": title, "wait": False}, write=True)
                row["action"] = "started"
            started_here = True
            await call(c, "cml_wait_for_converged", {"lab": title, "timeout": limit})
        else:
            row["action"] = "already running"
        out = await call(c, "cml_verify_recipe", {"recipe": name})
        if not out["passed"]:  # slow data planes (cat9000v): one retry after a pause
            await asyncio.sleep(180)
            out = await call(c, "cml_verify_recipe", {"recipe": name})
        failed = [chk["check"] for chk in out["checks"] if not chk["ok"]]
        row["result"] = ("PASS " if out["passed"] else "FAIL ") + out["summary"]
        if failed:
            row["failed"] = failed
    except SystemExit as e:  # a tool error: record it and carry on with the next recipe
        row["result"] = f"ERROR {str(e)[:300]}"
    finally:
        if started_here:
            try:
                await call(c, "cml_stop_lab", {"lab": title}, write=True)
                row["action"] += ", stopped again"
            except SystemExit as e:
                row["action"] += f", STOP FAILED: {str(e)[:200]}"
        row["secs"] = round(asyncio.get_running_loop().time() - t0)
    return row


def append_text(path: Path, text: str) -> None:
    with path.open("a") as fh:
        fh.write(text)


def ci_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "## Recipe verification",
        "",
        "| Recipe | Lab | Before | Action | Result | Seconds |",
        "|---|---|---|---|---|---:|",
    ]
    for r in rows:
        result = r["result"] + (f" (failed: {', '.join(r['failed'])})" if r.get("failed") else "")
        lines.append(
            f"| {r['recipe']} | {r['lab']} | {r['before'] or 'not built'} | {r['action']} | {result} "
            f"| {r['secs']} |"
        )
    return "\n".join(lines) + "\n"


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "action", choices=["list", "show", "build", "start", "wait", "verify", "stop", "plan", "swap", "ci"]
    )
    ap.add_argument("recipe", nargs="*")
    ap.add_argument("--start", action="store_true", help="build: start the lab after building it")
    ap.add_argument("--no-wait", action="store_true", help="build/start: don't wait for the boot")
    ap.add_argument("--recreate", action="store_true", help="build: delete an existing lab first")
    ap.add_argument("--json", action="store_true", help="verify: print the full JSON result")
    ap.add_argument("--yes", action="store_true", help="swap: stop the planned labs without asking")
    ap.add_argument("--timeout", type=float, default=2400, help="seconds to wait for boots")
    ap.add_argument("--summary", help="ci: append the Markdown result table to this file")
    ap.add_argument("--build-missing", action="store_true", help="ci: build recipes whose lab doesn't exist")
    args = ap.parse_args()
    if args.action == "ci":
        names = args.recipe or recipe_names()
        for n in names:
            load(n)
        settings = live_settings(Settings, "CML_", mcp_enable_writes=True)
        rows = []
        async with Client(create_server(settings), timeout=args.timeout + 600) as c:
            for n in names:
                print(f"== {n}", file=sys.stderr)
                rows.append(await ci_one(c, n, limit=args.timeout, build_missing=args.build_missing))
                print(json.dumps(rows[-1]), file=sys.stderr)
        md = ci_markdown(rows)
        print(md)
        if args.summary:
            await asyncio.to_thread(append_text, Path(args.summary), md)
        raise SystemExit(
            0 if all(r["result"].startswith("PASS") or r["action"] == "skipped" for r in rows) else 1
        )
    if len(args.recipe) > 1:
        sys.exit("give one recipe name")
    args.recipe = args.recipe[0] if args.recipe else None
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
            build = {"recipe": args.recipe, "start": args.start, "wait": not args.no_wait}
            build["timeout"] = args.timeout
            out = await call(c, "cml_build_recipe", build, write=True)
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
            out = await call(c, "cml_verify_recipe", {"recipe": args.recipe})
            if not args.json:
                for chk in out["checks"]:
                    mark = "PASS" if chk["ok"] else "FAIL"
                    detail = "" if chk["ok"] else f"  {str(chk.get('detail', ''))[:160]}"
                    print(f"{mark}  {chk['kind']:8} {chk['check']}{detail}")
                print(f"{'PASSED' if out['passed'] else 'FAILED'}: {out['summary']} in {out['seconds']}s")
                raise SystemExit(0 if out["passed"] else 1)
        else:
            out = await call(c, "cml_stop_lab", {"lab": title}, write=True)
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    asyncio.run(main())
