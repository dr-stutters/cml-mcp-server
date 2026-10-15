"""The CML "app" object: one ApiClient on /api/v0, JWT login, name-or-id resolution helpers."""

from __future__ import annotations

import base64
import json
import os
import re
import time
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

import httpx
from stutters_mcp_core import InvalidRequest, NotFound, UpstreamError
from stutters_mcp_core.http import ApiClient, LoginTokenAuth, NoPaging, RateLimiter, StaticHeaderAuth, Token

from cml_mcp.config import Settings
from cml_mcp.console import ConsoleServer
from cml_mcp.scenarios import FlapManager

API_BASE = "/api/v0"
# Labs resolved during the current tool call (ref -> lab), so the safety guard checks exactly the lab the tool
# resolved and will act on, without a second lookup (a rename in between can't make them differ).
RESOLVED_LABS: ContextVar[dict[str, dict[str, Any]] | None] = ContextVar("cml_resolved_labs", default=None)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
DEFAULT_TOKEN_LIFETIME = 8 * 3600.0


def is_uuid(value: str) -> bool:
    return bool(UUID_RE.match(value.strip()))


def cml_error_detail(body: Any) -> str | None:
    """CML errors look like {"code": 400, "description": "..."}; validation failures put a JSON
    document into `description` ({"Input validation failed": [{"location": [...], "message": ...}]})."""
    if isinstance(body, str):
        return body.strip()[:500] or None
    if not isinstance(body, dict):
        return None
    desc = body.get("description") or body.get("detail") or body.get("message")
    if isinstance(desc, str):
        try:
            inner = json.loads(desc)
        except ValueError:
            return desc.strip()[:500] or None
        desc = inner
    if isinstance(desc, dict):
        parts = []
        for problems in desc.values():
            for p in problems if isinstance(problems, list) else [problems]:
                if isinstance(p, dict):
                    loc = ".".join(str(x) for x in p.get("location") or p.get("loc") or [])
                    msg = p.get("message") or p.get("msg") or ""
                    parts.append(f"{loc}: {msg}" if loc else str(msg))
                else:
                    parts.append(str(p))
        return "; ".join(parts)[:500] or None
    if isinstance(desc, list):
        out = []
        for p in desc:
            if isinstance(p, dict):
                loc = ".".join(str(x) for x in p.get("loc") or p.get("location") or [])
                out.append(f"{loc}: {p.get('msg') or p.get('message')}")
            else:
                out.append(str(p))
        return "; ".join(out)[:500] or None
    return None


def jwt_claims(token: str) -> dict[str, Any]:
    """Unverified JWT payload (only used for the expiry time and the user id)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _lifetime(claims: dict[str, Any]) -> float:
    exp = claims.get("exp")
    if isinstance(exp, int | float):
        return max(60.0, float(exp) - time.time())
    return DEFAULT_TOKEN_LIFETIME


class CmlApp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.user: dict[str, Any] = {}
        self._login_auth: LoginTokenAuth | None = None
        auth: LoginTokenAuth | StaticHeaderAuth
        if settings.token is not None:
            auth = StaticHeaderAuth("Authorization", f"Bearer {settings.token_value()}")
            claims = jwt_claims(settings.token_value())
            if claims.get("sub"):
                self.user = {"id": claims["sub"]}
        else:
            auth = self._login_auth = LoginTokenAuth(self._login)
        self.api = ApiClient(
            settings.url + API_BASE,
            product="CML",
            env_prefix="CML_",
            auth=auth,
            # TODO(core): ApiClient types verify as bool | str; httpx also takes an SSLContext (pinned cert)
            verify=settings.tls_verify(),  # type: ignore[arg-type]
            timeout=settings.timeout,
            retries=settings.retries,
            limiter=RateLimiter(settings.rate_limit, settings.max_concurrency or 8),
            error_detail=cml_error_detail,
            transport=transport,
        )
        self.pager = NoPaging()
        self._version: str | None = None
        known_hosts: str | None = None
        if settings.console_known_hosts:
            known_hosts = os.path.expanduser(settings.console_known_hosts)
        elif settings.verify_ssl or settings.ca_bundle is not None:
            known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        # (monotonic time, running-node limit, how it was derived): see licence.node_limit
        self.node_limit_cache: tuple[float, int | None, str] | None = None
        self.flaps = FlapManager()
        self.console = ConsoleServer(
            settings.url,
            settings.username,
            settings.password_value() or None,
            port=settings.console_port,
            timeout=settings.timeout,
            known_hosts=known_hosts,
            lock_wait=settings.console_lock_wait,
        )

    # --- auth ----------------------------------------------------------------------------

    async def _login(self, client: ApiClient) -> Token:
        username, password = self.settings.require_credentials("CML_")
        body = {"username": username, "password": password}
        resp = await client.send_raw("POST", "/auth_extended", json=body)
        if resp.status_code == 404:  # older controllers: plain /authenticate returns the JWT string
            resp = await client.send_raw("POST", "/authenticate", json=body)
        if resp.status_code != 200:
            raise client.error_from_response(resp)
        data = resp.json()
        if isinstance(data, str):
            token = data
            claims = jwt_claims(token)
            self.user = {"username": username, "id": claims.get("sub")}
        else:
            token = str(data["token"])
            self.user = {"username": data.get("username"), "id": data.get("id"), "admin": data.get("admin")}
            self.console.admin = data.get("admin")
        claims = jwt_claims(token)
        return Token({"Authorization": f"Bearer {token}"}, Token.expiring_in(_lifetime(claims)))

    async def aclose(self) -> None:
        await self.flaps.shutdown()  # every flapping link is brought back up first
        await self.api.aclose()

    # --- system --------------------------------------------------------------------------

    async def version(self) -> str:
        if self._version is None:
            info = await self.api.get("/system_information")
            self._version = str(info.get("version", "unknown"))
        return self._version

    async def current_user(self) -> dict[str, Any]:
        if not self.user.get("username"):
            if self._login_auth is not None:
                await self._login_auth.token_for(self.api)
            elif self.user.get("id"):
                u = await self.api.get(f"/users/{self.user['id']}")
                self.user = {"username": u.get("username"), "id": u.get("id"), "admin": u.get("admin")}
                self.console.admin = u.get("admin")
        return dict(self.user)

    async def status(self) -> dict[str, Any]:
        info = await self.api.get("/system_information")
        self._version = str(info.get("version", "unknown"))
        out: dict[str, Any] = {"version": self._version, "ready": info.get("ready")}
        try:  # TODO(core): status has core_version but not the server's own (CORE-REQUESTS.md)
            from importlib.metadata import version as _pkg_version

            out["server_version"] = _pkg_version("cml-mcp-server")
        except Exception:  # noqa: BLE001 - source checkout without metadata
            pass
        user = await self.current_user()
        out["user"] = user.get("username")
        out["admin"] = user.get("admin")
        health = await self.api.get("/system_health")
        out["health"] = health_summary(health)
        try:
            lic = await self.api.get("/licensing")
            out["licensing"] = licensing_summary(lic)
        except UpstreamError as e:  # non-admin users can't read licensing
            out["licensing"] = {"error": str(e)[:200]}
        if not user.get("admin"):
            from cml_mcp.licence import resource_pool  # local import: licence imports this module

            out["resource_pool"] = await resource_pool(self)
        labs = await self.api.get("/labs", {"show_all": "true"})
        from cml_mcp.safety import security_status

        out["security"] = security_status(self.settings)
        out["labs_visible"] = len(labs) if isinstance(labs, list) else None
        return out

    async def openapi(self) -> dict[str, Any]:
        doc: dict[str, Any] = await self.api.get("/openapi.json", timeout=120)
        return doc

    # --- labs ----------------------------------------------------------------------------

    async def list_labs(self) -> list[dict[str, Any]]:
        data = await self.api.get("/labs", {"show_all": "true", "with_data": "true"})
        labs = data if isinstance(data, list) else []
        if labs and isinstance(labs[0], str):  # controllers without with_data
            labs = [await self.api.get(f"/labs/{lab_id}") for lab_id in labs]
        return labs

    async def resolve_lab(self, ref: str, *, exact: bool = False) -> dict[str, Any]:
        """A lab by id or title: exact match first, then case-insensitive, then (unless `exact`, which
        write tools use) a unique case-insensitive substring."""
        raw = ref
        ref = ref.strip()
        if not ref:
            raise InvalidRequest("Give a lab id or title (see cml_list_labs).")
        if is_uuid(ref):
            lab: dict[str, Any] = await self.api.get(f"/labs/{ref}")
        else:
            labs = await self.list_labs()
            lab = pick_one(labs, ref, key="lab_title", kind="lab", list_tool="cml_list_labs", fuzzy=not exact)
        if exact:  # write paths resolve exactly; remember it for the guard of this call
            seen = RESOLVED_LABS.get()
            if seen is None:
                seen = {}
                RESOLVED_LABS.set(seen)
            seen[raw] = lab
        return lab

    # --- nodes / interfaces / links ------------------------------------------------------

    async def list_nodes(self, lab_id: str, *, operational: bool = False) -> list[dict[str, Any]]:
        params = {"data": "true", "exclude_configurations": "true"}
        if operational:
            params["operational"] = "true"
        nodes: list[dict[str, Any]] = await self.api.get(f"/labs/{lab_id}/nodes", params)
        return nodes

    async def resolve_node(self, lab_id: str, ref: str, *, exact: bool = False) -> dict[str, Any]:
        """A node in the lab by id or label (substring matches only when not `exact`)."""
        ref = ref.strip()
        if not ref:
            raise InvalidRequest("Give a node label or id (see cml_list_nodes).")
        if is_uuid(ref):
            node: dict[str, Any] = await self.api.get(
                f"/labs/{lab_id}/nodes/{ref}", {"operational": "true", "exclude_configurations": "true"}
            )
            return node
        nodes = await self.list_nodes(lab_id, operational=True)
        return pick_one(nodes, ref, key="label", kind="node", list_tool="cml_list_nodes", fuzzy=not exact)

    async def list_interfaces(self, lab_id: str, *, operational: bool = True) -> list[dict[str, Any]]:
        params = {"operational": "true"} if operational else None
        data: list[dict[str, Any]] = await self.api.get(f"/labs/{lab_id}/interfaces", params)
        return data

    async def list_links(self, lab_id: str) -> list[dict[str, Any]]:
        data: list[dict[str, Any]] = await self.api.get(f"/labs/{lab_id}/links", {"data": "true"})
        return data

    async def resolve_link(self, lab_id: str, ref: str) -> dict[str, Any]:
        """A link by id, by its label, or by its endpoints: 'r1<->r2', 'r1:Gi1<->r2:Gi1'."""
        ref = ref.strip()
        if is_uuid(ref):
            link: dict[str, Any] = await self.api.get(f"/labs/{lab_id}/links/{ref}")
            return link
        links = await self.list_links(lab_id)
        exact = [lk for lk in links if lk.get("label") == ref]
        if len(exact) == 1:
            return exact[0]
        if "<->" in ref:
            parts = [p.strip() for p in ref.split("<->")]
        elif "<>" in ref:
            parts = [p.strip() for p in ref.split("<>")]
        else:
            parts = ref.split()
        if len(parts) != 2 or not all(parts):
            raise NotFound(
                f"No link {ref!r}. Give a link id, its label, or endpoints like 'r1<->r2' or "
                "'r1:Ethernet0/0<->r2:Ethernet0/0' (see cml_list_links)."
            )
        nodes = {n["id"]: n for n in await self.list_nodes(lab_id)}
        ifaces = {i["id"]: i for i in await self.list_interfaces(lab_id, operational=False)}

        def matches(end: str, node_id: str, iface_id: str) -> bool:
            node_ref, _, iface_ref = end.partition(":")
            label = str(nodes.get(node_id, {}).get("label", "")).lower()
            if node_ref.lower() not in (label, node_id):
                return False
            iface_label = str(ifaces.get(iface_id, {}).get("label", "")).lower()
            return not iface_ref or iface_ref.lower() in (iface_label, iface_id)

        a, b = parts
        found = [
            lk
            for lk in links
            if (matches(a, lk["node_a"], lk["interface_a"]) and matches(b, lk["node_b"], lk["interface_b"]))
            or (matches(b, lk["node_a"], lk["interface_a"]) and matches(a, lk["node_b"], lk["interface_b"]))
        ]
        if len(found) == 1:
            return found[0]
        if not found:
            raise NotFound(f"No link between {a!r} and {b!r} in this lab (see cml_list_links).")
        raise InvalidRequest(
            f"{len(found)} links match {ref!r}: "
            + ", ".join(f"{lk['id']} ({lk.get('label')})" for lk in found)
            + ". Add interface names ('r1:Ethernet0/0<->r2:Ethernet0/0') or use the link id."
        )


def pick_one(
    items: list[dict[str, Any]], ref: str, *, key: str, kind: str, list_tool: str, fuzzy: bool = True
) -> dict[str, Any]:
    """Resolve a name: exact id/name match, then case-insensitive exact, then (if `fuzzy`) a unique
    case-insensitive substring."""
    tests: list[Callable[[dict[str, Any]], bool]] = [
        lambda it: it.get("id") == ref or it.get(key) == ref,
        lambda it: str(it.get(key, "")).lower() == ref.lower(),
    ]
    if fuzzy:
        tests.append(lambda it: ref.lower() in str(it.get(key, "")).lower())
    for test in tests:
        hits = [it for it in items if test(it)]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            names = ", ".join(f"{h.get(key)!r} ({h.get('id')})" for h in hits[:10])
            raise InvalidRequest(f"{len(hits)} {kind}s match {ref!r}: {names}. Use the id instead.")
    raise NotFound(f"No {kind} named {ref!r}. Use {list_tool} to see what exists.")


def health_summary(health: dict[str, Any]) -> dict[str, Any]:
    """{valid, problems[]} from /system_health: every False flag on the controller or a compute."""
    problems: list[str] = []
    for name, compute in (health.get("computes") or {}).items():
        host = compute.get("hostname") or name
        for flag, value in compute.items():
            if value is False and not flag.endswith("_overload"):
                problems.append(f"compute {host}: {flag} is false")
            elif value is True and flag.endswith("_overload"):
                problems.append(f"compute {host}: {flag}")
        if compute.get("admission_state") not in (None, "READY"):
            problems.append(f"compute {host}: admission_state={compute.get('admission_state')}")
    for flag, value in (health.get("controller") or {}).items():
        if value is False:
            problems.append(f"controller: {flag} is false")
    return {"valid": health.get("valid"), "computes": len(health.get("computes") or {}), "problems": problems}


def licensing_summary(lic: dict[str, Any]) -> dict[str, Any]:
    reg = lic.get("registration") or {}
    auth = lic.get("authorization") or {}
    return {
        "registration": reg.get("status"),
        "authorization": auth.get("status"),
        "authorization_expires": auth.get("expires"),
        "features": [
            {"name": f.get("name"), "status": f.get("status"), "in_use": f.get("in_use")}
            for f in lic.get("features") or []
        ],
        "enterprise": (lic.get("product_license") or {}).get("is_enterprise"),
    }
