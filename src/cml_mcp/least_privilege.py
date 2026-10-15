"""Least-privilege CML accounts (L17, docs/least-privilege.md): two non-admin users, their groups and
resource pools. Created idempotently by `scripts/seed_lab.py --least-privilege` (needs an admin login)."""

from __future__ import annotations

import os
from typing import Any

from stutters_mcp_core import NotFound

from cml_mcp.client import CmlApp

# Least-privilege accounts (L17, docs/least-privilege.md). Passwords come from the server's .env
# (CML_RO_PASSWORD / CML_RW_PASSWORD), never from this file. Each user gets its own group (labs are shared
# with the group, not the user) and a resource pool that caps what the account can start.
ACCOUNTS: list[dict[str, Any]] = [
    {
        "env": "CML_RO_",
        "username": "mcp-cml-viewer",
        "group": "mcp-cml-viewers",
        "description": (
            "cml-mcp-server read-only account (MCP read tier). Non-admin; sees labs shared with its group."
        ),
        # read tier only: no node launches at all
        "pool": {"label": "mcp-cml-viewer-pool", "licenses": 0, "cpus": 0, "ram": 0},
    },
    {
        "env": "CML_RW_",
        "username": "mcp-cml-operator",
        "group": "mcp-cml-operators",
        "description": (
            "cml-mcp-server write account (MCP read + write tiers). Non-admin; owns the labs it builds."
        ),
        "pool": {"label": "mcp-cml-operator-pool", "licenses": 12, "cpus": 24, "ram": 64 * 1024},
    },
]


def _env(name: str) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    try:
        from dotenv import dotenv_values

        return dotenv_values(".env").get(name)
    except ImportError:  # pragma: no cover
        return None


async def seed_least_privilege(app: CmlApp) -> dict[str, Any]:
    """Create or update the non-admin users, their groups and resource pools (idempotent)."""
    result: dict[str, Any] = {}
    groups = {g["name"]: g for g in await app.api.get("/groups")}
    pools = {p.get("label"): p for p in await app.api.get("/resource_pools", {"data": "true"}) or []}
    for acct in ACCOUNTS:
        username = _env(acct["env"] + "USERNAME") or acct["username"]
        password = _env(acct["env"] + "PASSWORD")
        try:
            user_id = await app.api.get(f"/users/{username}/id")
        except NotFound:
            user_id = None
        if user_id is None:
            if not password:
                print(f"skip {username}: {acct['env']}PASSWORD is not set in .env")
                continue
            res = await app.api.post(
                "/users",
                {
                    "username": username,
                    "password": password,
                    "fullname": username,
                    "description": acct["description"],
                    "admin": False,
                },
            )
            user_id = res["id"]
            print(f"created user {username}")
        else:
            # never promote/demote silently: admin must stay false
            await app.api.patch(f"/users/{user_id}", {"admin": False, "description": acct["description"]})
            print(f"user {username} exists ({user_id})")
        group = groups.get(acct["group"])
        if group is None:
            group = await app.api.post(
                "/groups", {"name": acct["group"], "description": acct["description"], "members": [user_id]}
            )
            print(f"created group {acct['group']}")
        elif user_id not in (group.get("members") or []):
            await app.api.patch(
                f"/groups/{group['id']}", {"members": [*(group.get("members") or []), user_id]}
            )
            print(f"added {username} to {acct['group']}")
        # CML: a user's pool must come from a template pool (the template carries the limits)
        spec = acct["pool"]
        tlabel = spec["label"] + "-template"
        template = pools.get(tlabel)
        limits = {k: v for k, v in spec.items() if k != "label"}
        if template is None:
            template = await app.api.post("/resource_pools", {"label": tlabel, **limits})
            template = template[0] if isinstance(template, list) else template
            pools[tlabel] = template
            print(f"created resource pool template {tlabel}")
        else:
            await app.api.patch(f"/resource_pools/{template['id']}", limits)
        pool = pools.get(spec["label"])
        if pool is None:
            created = await app.api.post(
                "/resource_pools",
                {"label": spec["label"], "template": template["id"], "shared": True, "users": [user_id]},
            )
            pool = created[0] if isinstance(created, list) else created
            pools[spec["label"]] = pool
            print(f"created resource pool {spec['label']}")
        await app.api.patch(f"/users/{user_id}", {"resource_pool": pool["id"]})
        print(f"  {username}: group {acct['group']}, pool {spec['label']} {spec}")
        result[username] = {"id": user_id, "group_id": group["id"], "pool_id": pool["id"]}
    return result
