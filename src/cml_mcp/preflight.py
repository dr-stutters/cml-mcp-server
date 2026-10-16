"""`cml-mcp-server check` (L37): what an operator needs to know before connecting a client.

Reachability and TLS of the controller API, the login (the client's own JWT login: /auth_extended, falling
back to /authenticate), the CML version vs the tested matrix, the API user's admin flag vs the enabled tiers
(docs/least-privilege.md) and, when writes are on, the node licences the account may start.
"""

from __future__ import annotations

from typing import Any

from cml_mcp._core import UpstreamError
from cml_mcp._core.preflight import Preflight
from cml_mcp.client import CmlApp
from cml_mcp.config import Settings
from cml_mcp.licence import node_limit, resource_pool

TESTED = ("2.10",)  # live-tested release (README)
MINIMUM = "2.7"  # the oldest 2.x release this server is written against (/api/v0, lab associations)

LEAST_PRIVILEGE = "docs/least-privilege.md"
ADMIN_ONLY_HINT = (
    "A regular user can wipe/delete its own labs (and labs it has lab_admin on); cml_upload_image and "
    "changes to other users' labs need a CML admin. Use an admin account only if you need those "
    f"({LEAST_PRIVILEGE}), never the built-in 'admin'."
)


async def _connect(app: CmlApp) -> tuple[dict[str, Any], dict[str, Any]]:
    """GET /system_information (logs in first) and the logged-in user."""
    info = await app.api.get("/system_information", retry=False)
    user = await app.current_user()
    return (info if isinstance(info, dict) else {}), user


async def account(app: CmlApp, user: dict[str, Any]) -> dict[str, Any]:
    """The API user's record (GET /users/<id>): admin flag and resource pool. Falls back to what the login
    said (a plain /authenticate login and a CML_TOKEN without claims don't say whether it is an admin)."""
    if user.get("id"):
        try:
            me = await app.api.get(f"/users/{user['id']}", retry=False)
        except UpstreamError:
            me = None
        if isinstance(me, dict):
            out = {**user, **{k: me.get(k) for k in ("username", "admin", "resource_pool") if k in me}}
            app.user = {k: out.get(k) for k in ("username", "id", "admin")}  # resource_pool() reads app.user
            return out
    return user


def _role(pf: Preflight, user: dict[str, Any]) -> None:
    s = pf.settings
    name = user.get("username") or "the account"
    admin = user.get("admin")
    if admin is True:
        # an admin can do everything: fine when every tier is on, a least-privilege warning otherwise
        pf.access(write=True, dangerous=True, role=f"{name} (CML admin)")
    elif admin is False and s.mcp_enable_dangerous:
        pf.warn(
            "role",
            f"{name} is a regular (non-admin) CML user: the dangerous tier works on its own labs only; "
            "admin-only tools (cml_upload_image, other users' labs, /system writes) will fail",
            hint=ADMIN_ONLY_HINT,
            role=f"{name} (regular user)",
            allowed={"read": True, "write": True},
            enabled=["read", "write", "dangerous"],
        )
    elif admin is False:
        # a regular user reads, and builds/runs its own labs; on a read-only server what it may start is
        # capped by its resource pool (0 licences in docs/least-privilege.md), not by the role
        pf.access(write=True if s.mcp_enable_writes else None, dangerous=False, role=f"{name} (regular user)")
    else:
        pf.access(write=None, detail="CML did not say whether the API user is an admin")


async def _licences(pf: Preflight, app: CmlApp, user: dict[str, Any]) -> None:
    """Writes on: how many licensed nodes this account may start (its resource pool, else the controller)."""
    pool = await resource_pool(app) if user.get("admin") is not True else None
    if pool and isinstance(pool.get("licenses_limit"), int):
        limit, used = pool["licenses_limit"], int(pool.get("licenses_used") or 0)
        free = max(0, limit - used)
        label = pool.get("label") or pool.get("id")
        data = {"source": f"resource pool {label}", "limit": limit, "used": used, "free": free}
        if free == 0:
            pf.warn(
                "licences",
                f"resource pool {label!r} leaves 0 node licences free ({used} of {limit} in use): "
                "builds and starts will be refused",
                hint="Raise the pool's licences (Tools > Resource Pools; sizes in "
                f"{LEAST_PRIVILEGE}) or stop labs (cml_plan_licences says which).",
                **data,
            )
        else:
            pf.ok("licences", f"resource pool {label!r}: {free} of {limit} node licences free", **data)
        return
    limit, source = await node_limit(app)
    if limit is None:
        pf.warn(
            "licences",
            f"could not tell how many nodes this account may start ({source})",
            hint="Give the account a resource pool with node licences, or set CML_NODE_LICENSE_LIMIT to the "
            "controller's licensed-node cap; start previews can't check licences otherwise.",
            source=source,
        )
        return
    pf.ok(
        "licences",
        f"controller licence: {limit} running licensed nodes ({source}), shared by every CML user",
        source=source,
        limit=limit,
    )


async def preflight(settings: Settings, pf: Preflight) -> None:
    app = CmlApp(settings)
    try:
        found = await pf.reach(
            "api",
            _connect(app),
            detail=lambda r: f"CML API answered; logged in as {r[1].get('username') or 'token user'}",
        )
        if found is None:
            last = pf.results[-1]
            if last.check == "role" and last.surface == "api":  # CML refuses a bad login with 403
                last.check = "auth"
                last.hint = (
                    "Check CML_USERNAME and CML_PASSWORD (or CML_PASSWORD_FILE / CML_PASSWORD_REF, or "
                    "CML_TOKEN) and that the user exists on this controller."
                )
            return
        info, user = found
        user = await account(app, user)
        pf.version(str(info["version"]) if info.get("version") else None, tested=TESTED, minimum=MINIMUM)
        if info.get("ready") is False:
            pf.warn("ready", "the controller reports ready=false (still starting?)", hint="Retry shortly.")
        _role(pf, user)
        if settings.mcp_enable_writes:
            await _licences(pf, app, user)
    finally:
        await app.aclose()
