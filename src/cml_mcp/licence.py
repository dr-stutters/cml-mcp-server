"""Node-licence accounting: how many licensed nodes run where, and readable 'out of licences' errors.

CML counts every running node against the licence except external connectors and unmanaged
switches. The cap isn't reported by the API (an EVAL Personal licence says '20 nodes' but allows 5),
so CML_NODE_LICENSE_LIMIT can tell the server what it is.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import Counter
from typing import Any

from stutters_mcp_core import AuthError, InvalidRequest, NotFound, UpstreamError

from cml_mcp.build import UNLICENSED_DEFINITIONS
from cml_mcp.client import CmlApp

RUNNING_STATES = ("STARTED", "QUEUED", "BOOTED")

# Licensed node capacity (CML doesn't report a single number): the base licence's included nodes
# (parsed from its description, e.g. 'Enterprise License with 20 nodes capacity included') plus
# CML_NODE_COUNT expansion licences in use. An unregistered controller in EVAL mode allows 5
# (verified on 2.10: the Personal licence says 20 but refuses the 6th node).
EVAL_NODE_LIMIT = 5
BASE_DEFAULTS = {"CML_ENT_BASE": 20, "CML_PER_BASE": 20, "CML_PER_PLUS_BASE": 40, "CML_EDU_BASE": 20}
_NODES_IN_TEXT = re.compile(r"(\d+)\s+nodes?", re.IGNORECASE)
_CACHE_SECONDS = 300.0


def _feature_kind(feature: dict[str, Any]) -> str:
    m = re.search(r"com\.cisco\.([A-Z_]+)", str(feature.get("id") or ""))
    return m.group(1) if m else ""


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


GOOD_STATUSES = ("IN_COMPLIANCE", "AUTHORIZED")


def capacity_from_licensing(lic: dict[str, Any]) -> tuple[int | None, str]:
    """(running-node limit, how it was derived) from GET /licensing; (None, reason) if unknown."""
    features = [f for f in lic.get("features") or [] if isinstance(f, dict)]
    auth = str((lic.get("authorization") or {}).get("status") or "").upper()
    in_use_eval = any(
        str(f.get("status") or "").upper() == "EVAL" and _int(f.get("in_use")) for f in features
    )
    if auth == "EVAL" or (not auth and in_use_eval):
        return EVAL_NODE_LIMIT, "evaluation mode (unregistered): 5 running nodes"
    base = 0
    parts = []
    for f in features:
        kind = _feature_kind(f)
        if not kind.endswith("_BASE") or (f.get("in_use") is not None and _int(f.get("in_use")) == 0):
            continue
        if str(f.get("status") or "").upper() not in GOOD_STATUSES:
            continue
        m = _NODES_IN_TEXT.search(str(f.get("description") or ""))
        nodes = int(m.group(1)) if m else BASE_DEFAULTS.get(kind, 0)
        if nodes > base:
            base = nodes
            parts = [f"{kind} {nodes}"]
    if not base:
        return None, f"no compliant base licence found in /licensing (authorization {auth or 'unknown'})"
    expansion = sum(
        _int(f.get("in_use"))
        for f in features
        if _feature_kind(f) == "CML_NODE_COUNT" and str(f.get("status") or "").upper() in GOOD_STATUSES
    )
    if expansion:
        parts.append(f"CML_NODE_COUNT {expansion}")
    return base + expansion, " + ".join(parts)


async def node_limit(app: CmlApp) -> tuple[int | None, str]:
    """The running licensed-node limit: CML_NODE_LICENSE_LIMIT if set, else detected from the
    licensing API (cached for 5 minutes)."""
    if app.settings.node_license_limit:
        return app.settings.node_license_limit, "CML_NODE_LICENSE_LIMIT"
    cached = app.node_limit_cache
    if cached and time.monotonic() - cached[0] < _CACHE_SECONDS:
        return cached[1], cached[2]
    try:
        lic = await app.api.get("/licensing")
        limit, source = capacity_from_licensing(lic if isinstance(lic, dict) else {})
    except UpstreamError as e:
        return None, f"licensing not readable ({str(e)[:80]}); set CML_NODE_LICENSE_LIMIT"
    except Exception as e:  # a malformed response must not break every start preview
        return None, f"licensing not understood ({type(e).__name__}); set CML_NODE_LICENSE_LIMIT"
    if limit is not None:  # never cache 'unknown'
        app.node_limit_cache = (time.monotonic(), limit, source)
    return limit, source


def licensed(node: dict[str, Any]) -> bool:
    return str(node.get("node_definition")) not in UNLICENSED_DEFINITIONS


NOT_RUNNING_LAB_STATES = ("STOPPED", "DEFINED_ON_CORE")
NON_ADMIN_SCOPE = (
    "labs visible to this account only: it is not a CML admin, so other users' running nodes are not "
    "counted (CML still enforces the controller limit and the account's resource pool)"
)


async def running_nodes(app: CmlApp) -> tuple[list[dict[str, Any]], str | None]:
    """Every node on the controller (GET /nodes, admin only), or, for a non-admin account, the nodes of
    the labs it can see, with a note saying the count is partial."""
    try:
        nodes: list[dict[str, Any]] = await app.api.get("/nodes", {"operational": "false"})
        return nodes, None
    except AuthError:
        pass
    labs = [lab for lab in await app.list_labs() if lab.get("state") not in NOT_RUNNING_LAB_STATES]
    results = await asyncio.gather(*(app.list_nodes(str(lab["id"])) for lab in labs), return_exceptions=True)
    out: list[dict[str, Any]] = []
    skipped = 0
    for lab, res in zip(labs, results, strict=True):
        if isinstance(res, (AuthError, NotFound)):
            skipped += 1  # shared without node access, or deleted meanwhile
            continue
        if isinstance(res, BaseException):
            raise res
        out.extend({**n, "lab_id": n.get("lab_id") or lab["id"]} for n in res)
    note = NON_ADMIN_SCOPE + (f"; {skipped} lab(s) could not be read" if skipped else "")
    return out, note


async def resource_pool(app: CmlApp) -> dict[str, Any] | None:
    """The account's resource pool (licence/CPU/RAM limits CML enforces for this user), or None."""
    try:
        user = await app.current_user()
        if not user.get("id") or user.get("admin") is True:
            return None  # admins aren't limited by a pool in practice; saves two calls per preview
        me = await app.api.get(f"/users/{user['id']}")
        pool_id = me.get("resource_pool") if isinstance(me, dict) else None
        if not pool_id:
            return None
        usage = await app.api.get(f"/resource_pool_usage/{pool_id}")
    except UpstreamError:  # the pool is extra information: never break licence planning over it
        return None
    if not isinstance(usage, dict):
        return None
    limit = usage.get("limit") or {}
    used = usage.get("usage") or {}
    return {
        "id": pool_id,
        "label": usage.get("label"),
        "licenses_limit": limit.get("licenses"),
        "licenses_used": used.get("licenses"),
        "ram_mb_limit": limit.get("ram"),
        "ram_mb_used": used.get("ram"),
    }


async def licence_usage(app: CmlApp) -> dict[str, Any]:
    """{running_licensed_nodes, by_lab: {title: n}, labs: [{id, title, running, preferred, own}], limit,
    free} across every lab on the controller (or every lab the account can see, see `scope`).
    `free` is the tighter of the controller licence and the account's resource pool."""
    nodes, scope = await running_nodes(app)
    labs = {lab["id"]: lab for lab in await app.list_labs()}
    me = (await app.current_user()).get("id")
    running = [n for n in nodes if n.get("state") in RUNNING_STATES and licensed(n)]
    per_lab = Counter(str(n.get("lab_id")) for n in running)
    rows = []
    for lab_id, count in per_lab.most_common():
        lab = labs.get(lab_id, {})
        title = str(lab.get("lab_title") or lab_id)
        row = {"id": lab_id, "title": title, "running": count, "preferred": preferred_to_stop(lab)}
        if me and lab.get("owner"):
            row["own"] = lab.get("owner") == me
        rows.append(row)
    limit, limit_source = await node_limit(app)
    out: dict[str, Any] = {
        "running_licensed_nodes": len(running),
        "by_lab": {r["title"]: r["running"] for r in rows},
        "labs": rows,
    }
    if scope:
        out["scope"] = scope
    out["limit_source"] = limit_source
    if limit:
        out["limit"] = limit
        out["free"] = max(0, limit - len(running))
    pool = await resource_pool(app)
    if pool:
        out["resource_pool"] = pool
        plimit, pused = pool.get("licenses_limit"), pool.get("licenses_used")
        if isinstance(plimit, int):
            pfree = max(0, plimit - int(pused or 0))
            if "free" not in out or pfree < out["free"]:
                # the pool binds: only this account's own labs free pool licences when stopped
                out["limit"] = plimit
                out["free"] = pfree
                out["running_licensed_nodes"] = int(pused or 0)
                out["limit_source"] = f"resource pool {pool.get('label')!r} of this account"
                out["pool_binds"] = True
    return out


def preferred_to_stop(lab: dict[str, Any]) -> bool:
    """Test labs (recipes, mcp-test-*/mcp-* titles, 'recipe'/'mcp-test' in the description or tags)
    are the first candidates to stop; other people's labs come last."""
    title = str(lab.get("lab_title") or "").lower()
    text = f"{lab.get('lab_description') or ''} {' '.join(map(str, lab.get('tags') or []))}".lower()
    return title.startswith("mcp-") or "recipe" in text or "mcp-test" in text


def plan_stops(
    labs: list[dict[str, Any]], needed: int, free: int, *, exclude: str | None = None
) -> list[dict[str, Any]] | None:
    """The smallest set of labs to stop so `needed` licences are free: [] when enough are free already,
    None when even stopping everything else isn't enough. Ranked by fewest labs, then fewest labs
    that aren't ours (preferred), then the least capacity wasted. Exact, O(labs x deficit)."""
    deficit = needed - free
    if deficit <= 0:
        return []
    candidates = [lab for lab in labs if lab["id"] != exclude and int(lab.get("running") or 0) > 0]
    if sum(int(lab["running"]) for lab in candidates) < deficit:
        return None
    # best[f]: the best way found so far to free exactly f (< deficit) or at least f (== deficit)
    # licences, as (n_labs, n_not_preferred, freed, chosen indexes)
    Entry = tuple[int, int, int, tuple[int, ...]]
    best: dict[int, Entry] = {0: (0, 0, 0, ())}
    for idx, lab in enumerate(candidates):
        run = int(lab["running"])
        foreign = 0 if lab.get("preferred") else 1
        for f, (n, nf, freed, chosen) in sorted(best.items(), reverse=True):
            if f >= deficit:
                continue  # already enough; adding labs only makes it worse
            g = min(deficit, f + run)
            cand: Entry = (n + 1, nf + foreign, freed + run, (*chosen, idx))
            cur = best.get(g)
            if cur is None or (cand[0], cand[1], cand[2]) < (cur[0], cur[1], cur[2]):
                best[g] = cand
    found = best.get(deficit)
    return [dict(candidates[i]) for i in found[3]] if found else None


def plan_text(stops: list[dict[str, Any]] | None) -> str:
    if stops is None:
        return (
            "Not possible even with every other lab stopped: the target needs more than the licence allows."
        )
    if not stops:
        return "Enough licences are free."
    names = ", ".join(f"{s['title']!r} ({s['running']})" for s in stops)
    return f"Stop {names} first (cml_stop_lab), or let cml_plan_licences explain the options."


def licence_blocker(usage: dict[str, Any], needed: int, *, exclude: str | None = None) -> str | None:
    """A preview blocker when starting `needed` more licensed nodes would exceed the known limit; it
    names the smallest set of labs to stop (see plan_stops)."""
    limit = usage.get("limit")
    if limit is None or needed <= 0 or needed <= usage.get("free", 0):
        return None
    running = ", ".join(f"{t!r} ({n})" for t, n in usage["by_lab"].items()) or "none"
    stops = plan_stops(stop_candidates(usage), needed, usage.get("free", 0), exclude=exclude)
    where = f"the resource pool ({usage['limit_source']})" if usage.get("pool_binds") else "the licence"
    return (
        f"Starting needs {needed} node licence(s) but only {usage.get('free', 0)} of {limit} in {where} "
        f"are free (running: {running}). {plan_text(stops)} External connectors and unmanaged switches "
        "don't count." + (" Only labs visible to this account are counted." if usage.get("scope") else "")
    )


def stop_candidates(usage: dict[str, Any]) -> list[dict[str, Any]]:
    """Labs whose stopping frees licences for this account: all of them, except when the account's
    resource pool is the limit (then only its own labs count against it)."""
    labs: list[dict[str, Any]] = usage.get("labs") or []
    if not (usage.get("pool_binds") or usage.get("scope")):
        return labs
    if any("own" in lab for lab in labs):
        # a non-admin account can only stop its own labs (and the pool only counts those)
        return [lab for lab in labs if lab.get("own")]
    return labs  # ownership unknown: don't claim it's impossible


async def explain_licence_error(app: CmlApp, err: UpstreamError, what: str) -> Exception:
    """Turn CML's '5 of 5 node licenses are in use' into an actionable error; other errors pass."""
    if "licen" not in str(err).lower():
        return err
    app.node_limit_cache = None  # CML disagrees with what we thought was free: re-read the licence
    try:
        usage = await licence_usage(app)
        running = ", ".join(f"{t!r} ({n})" for t, n in usage["by_lab"].items()) or "none"
    except UpstreamError:
        running = "unknown"
    return InvalidRequest(
        f"{what}: CML refused for lack of node licences ({err}). Labs with running licensed nodes: "
        f"{running}. Stop one (cml_stop_lab) and retry; external connectors and unmanaged switches "
        "don't count."
    )


# --- RAM (L28): with 70 licences, memory is the practical limit ------------------------------------


def nodes_ram_mb(nodes: list[dict[str, Any]], defs: dict[str, dict[str, Any]]) -> int:
    """RAM the nodes need when started: their own `ram`, or their definition's default."""
    return sum(
        int(
            n.get("ram")
            or (defs.get(str(n.get("node_definition") or n.get("definition"))) or {})
            .get("sim", {})
            .get("ram")
            or 0
        )
        for n in nodes
    )


async def ram_headroom(app: CmlApp) -> dict[str, Any] | None:
    """The controller's memory in MB: total, in use, allocated to running nodes, and free = total minus
    the larger of used and allocated (booting nodes grow into their allocation). None if unreadable."""
    try:
        stats = await app.api.get("/system_stats")
    except UpstreamError:
        return None
    mem = ((stats or {}).get("all") or {}).get("memory") or {}
    total, used = mem.get("total"), mem.get("used")
    if not isinstance(total, int | float) or not isinstance(used, int | float):
        return None
    allocated_kib = sum(
        int(((c.get("stats") or {}).get("dominfo") or {}).get("allocated_memory") or 0)
        for c in ((stats or {}).get("computes") or {}).values()
    )
    mib = 2**20
    committed = max(float(used), allocated_kib * 1024.0)
    return {
        "total_mb": round(total / mib),
        "used_mb": round(used / mib),
        "allocated_to_running_nodes_mb": round(allocated_kib / 1024),
        "free_mb": max(0, round((total - committed) / mib)),
    }


def ram_check(ram: dict[str, Any] | None, needed_mb: int) -> dict[str, Any] | None:
    """{needed_mb, free_mb, total_mb, ok, warning?} for starting nodes that need `needed_mb`."""
    if ram is None or needed_mb <= 0:
        return None
    ok = needed_mb <= ram["free_mb"]
    out: dict[str, Any] = {
        "needed_mb": needed_mb,
        "free_mb": ram["free_mb"],
        "total_mb": ram["total_mb"],
        "ok": ok,
    }
    if not ok:
        out["warning"] = (
            f"Needs {needed_mb / 1024:.1f} GB RAM but only {ram['free_mb'] / 1024:.1f} GB of "
            f"{ram['total_mb'] / 1024:.0f} GB are free ({ram['allocated_to_running_nodes_mb'] / 1024:.1f} GB "
            "allocated to running nodes): nodes may fail to boot or the host may swap. Stop a lab first "
            "(cml_get_resource_usage shows which labs hold the most RAM)."
        )
    return out


def compact_usage(usage: dict[str, Any]) -> dict[str, Any]:
    """The licence block for a preview: just the numbers when the start fits, everything otherwise."""
    if usage.get("limit") is None or usage.get("free", 0) <= 0:
        return usage
    keep = ("running_licensed_nodes", "limit", "free", "limit_source", "scope", "pool_binds")
    return {k: usage[k] for k in keep if k in usage}
