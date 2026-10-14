"""System-level read tools: health, resource usage, licensing."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from stutters_mcp_core import AuthError, NotFound, ToolRegistrar, get_client

from cml_mcp.client import CmlApp, health_summary, licensing_summary
from cml_mcp.tools.common import gib, shaped


def _usage(stats: dict[str, Any]) -> dict[str, Any]:
    cpu = stats.get("cpu") or {}
    mem = stats.get("memory") or {}
    disk = stats.get("disk") or {}
    out: dict[str, Any] = {
        "cpu_count": cpu.get("count"),
        "cpu_percent": round(cpu["percent"], 1) if isinstance(cpu.get("percent"), int | float) else None,
        "memory_total_gb": gib(mem.get("total")),
        "memory_used_gb": gib(mem.get("used")),
        "disk_total_gb": gib(disk.get("total")),
        "disk_free_gb": gib(disk.get("free")),
    }
    if cpu.get("load"):
        out["load_avg"] = [round(x, 2) for x in cpu["load"]]
    return {k: v for k, v in out.items() if v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="CML system health")
    async def cml_get_system_health(ctx: Context) -> ToolResult:
        """Health of the CML controller and every compute host: a summary (valid + list of problems
        such as libvirt down, KVM/VMX missing, CPU/memory/disk overload, compute not READY) followed
        by the raw per-compute flags. Use it when labs fail to start or nodes stay QUEUED."""
        app: CmlApp = get_client(ctx)
        health = await app.api.get("/system_health")
        return shaped(
            {
                "summary": health_summary(health),
                "computes": health.get("computes"),
                "controller": health.get("controller"),
                "is_licensed": health.get("is_licensed"),
                "is_enterprise": health.get("is_enterprise"),
            }
        )

    @reg.read(title="CML resource usage")
    async def cml_get_resource_usage(ctx: Context) -> ToolResult:
        """CPU, memory and disk usage of the whole CML cluster and of each compute host, plus how many
        nodes are running and how many vCPUs/MB of RAM they have been allocated, and the licensed
        node capacity in use. Check this before starting big labs."""
        app: CmlApp = get_client(ctx)
        stats = await app.api.get("/system_stats")
        computes = []
        for cid, c in (stats.get("computes") or {}).items():
            s = c.get("stats") or {}
            row = {
                "id": cid,
                "hostname": c.get("hostname"),
                "is_controller": c.get("is_controller"),
                **_usage(s),
            }
            dom = s.get("dominfo") or {}
            row["running_nodes"] = dom.get("running_nodes")
            row["total_nodes"] = dom.get("total_nodes")
            row["allocated_cpus"] = dom.get("allocated_cpus")
            mem_kib = dom.get("allocated_memory")
            row["allocated_memory_mb"] = round(mem_kib / 1024) if isinstance(mem_kib, int | float) else None
            computes.append(row)
        out: dict[str, Any] = {"cluster": _usage(stats.get("all") or {}), "computes": computes}
        try:
            lic = licensing_summary(await app.api.get("/licensing"))
            out["license_features"] = lic["features"]
        except (AuthError, NotFound):
            out["license_features"] = "unavailable (needs an admin account)"
        return shaped(out)

    @reg.read(title="CML licensing")
    async def cml_get_licensing(ctx: Context) -> ToolResult:
        """Smart Licensing state of the controller: registration and authorization status (EVAL,
        AUTHORIZED, OUT_OF_COMPLIANCE...), expiry, licensed features with how many are in use (node
        capacity), product tier and reservation mode. Needs an admin account."""
        app: CmlApp = get_client(ctx)
        lic = await app.api.get("/licensing")
        reg_ = lic.get("registration") or {}
        return shaped(
            {
                **licensing_summary(lic),
                "smart_account": reg_.get("smart_account"),
                "virtual_account": reg_.get("virtual_account"),
                "registration_expires": reg_.get("expires"),
                "reservation_mode": lic.get("reservation_mode"),
                "features": lic.get("features"),
            }
        )
