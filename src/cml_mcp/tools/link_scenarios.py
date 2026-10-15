"""Named link conditioning scenarios: list, apply (netem profiles and background flapping), clear."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import Confirm, Plan, ToolRegistrar, get_client

from cml_mcp.client import CmlApp
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.scenarios import (
    FLAP_DEFAULTS,
    FLAP_MAX_TOTAL_SECONDS,
    SCENARIOS,
    FlapJob,
    match_scenario,
    netem_body,
)
from cml_mcp.tools.common import LabRef, LinkRef, Topo, load_topo
from cml_mcp.tools.links import condition_view

ScenarioName = Literal["wan-good", "wan-satellite", "lossy-wifi", "brownout", "flap"]


def link_name(topo: Topo, lk: dict[str, Any]) -> str:
    return f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}"


async def conditions(app: CmlApp, lid: str) -> dict[str, dict[str, Any]]:
    """link id -> configured conditioning, from one topology call (only links that have any)."""
    data = await app.api.get(f"/labs/{lid}/topology", {"exclude_configurations": "true"})
    out: dict[str, dict[str, Any]] = {}
    for lk in data.get("links") or []:
        cond = lk.get("conditioning") or {}
        if cond and any(v not in (None, False, 0) for k, v in cond.items() if k != "operational"):
            out[lk["id"]] = condition_view(cond)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Link scenarios")
    async def cml_get_link_scenarios(
        ctx: Context,
        lab: Annotated[
            str | None,
            Field(description="Also show which links of this lab are conditioned or flapping (title or id)"),
        ] = None,
    ) -> dict[str, Any]:
        """The named link conditioning scenarios (wan-good, wan-satellite, lossy-wifi, brownout,
        flap) with their netem values and the expected round-trip ping change (CML conditions both
        directions, so RTT grows by 2 x latency). With `lab`: every conditioned link (and which
        scenario its values match, or 'custom') and the flap jobs this server runs or ran there.
        Apply one with cml_apply_link_scenario; undo with cml_clear_link_scenarios."""
        app: CmlApp = get_client(ctx)
        out: dict[str, Any] = {"scenarios": [s.view() for s in SCENARIOS.values()]}
        if lab:
            info = await app.resolve_lab(lab)
            lid = info["id"]
            topo = await load_topo(app, lid)
            conds = await conditions(app, lid)
            by_id = {lk["id"]: lk for lk in topo.links}
            out["lab"] = info.get("lab_title")
            out["conditioned_links"] = [
                {
                    "link": link_name(topo, by_id[k]) if k in by_id else k,
                    "id": k,
                    "scenario": match_scenario(c),
                    "conditioning": c,
                }
                for k, c in conds.items()
            ]
            out["flaps"] = [j.view() for j in app.flaps.recent(lid)]
            if bad := [j.link_name for j in app.flaps.recent(lid) if j.error]:
                out["warning"] = f"Flap jobs reported errors (see flaps[].error): {', '.join(bad)}"
        return out

    @reg.write(title="Apply link scenario")
    async def cml_apply_link_scenario(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        scenario: Annotated[
            ScenarioName,
            Field(
                description="wan-good | wan-satellite | lossy-wifi | brownout (netem profiles, applied "
                "until cleared) or flap (timed down/up cycles in the background)"
            ),
        ],
        down_seconds: Annotated[
            int, Field(ge=2, le=3600, description="flap: how long the link stays down each cycle")
        ] = FLAP_DEFAULTS[0],
        up_seconds: Annotated[
            int, Field(ge=2, le=3600, description="flap: how long it stays up between cycles")
        ] = FLAP_DEFAULTS[1],
        cycles: Annotated[int, Field(ge=1, le=100, description="flap: number of down/up cycles")] = (
            FLAP_DEFAULTS[2]
        ),
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Put a named, repeatable impairment on a link instead of hand-typing netem values. The
        netem scenarios replace the link's conditioning (see cml_get_link_scenarios for values)
        and stay until cml_clear_link_scenarios. 'flap' starts a background job in this server that
        takes the link down for down_seconds and up again, `cycles` times, then leaves it up; it
        returns at once (watch it with cml_get_link_scenarios(lab), stop it early with
        cml_clear_link_scenarios). Flapping needs a started lab and stops if this server process
        exits (the link is brought back up first). The result includes the expected round-trip ping
        change, to check with cml_check_reachability."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        topo = await load_topo(app, lid)
        name = link_name(topo, lk)
        sc = SCENARIOS[scenario]
        current = condition_view(await app.api.get(f"/labs/{lid}/links/{lk['id']}/condition") or {})
        blockers: list[str] = []
        details: dict[str, Any] = {"link": name, "scenario": sc.name, "expected_ping_delta": sc.expected()}
        if sc.flap:
            total = cycles * (down_seconds + up_seconds)
            if lk.get("state") != "STARTED":
                blockers.append(f"Link is {lk.get('state')}; flapping needs a started lab with the link up")
            if any(j.link_id == lk["id"] for j in app.flaps.active(lid)):
                blockers.append(f"{name} is already flapping; cml_clear_link_scenarios stops it")
            if total > FLAP_MAX_TOTAL_SECONDS:
                blockers.append(f"Flap would run {total}s; the maximum is {FLAP_MAX_TOTAL_SECONDS}s")
            details.update(
                down_seconds=down_seconds,
                up_seconds=up_seconds,
                cycles=cycles,
                runs_about_seconds=total - up_seconds,
            )
            summary = f"Flap link {name}: {cycles} x ({down_seconds}s down, {up_seconds}s up)"
        else:
            details.update(current=current, new=dict(sc.netem))
            summary = f"Apply scenario {sc.name} to link {name}"
        plan = Plan(
            summary,
            details=details,
            # link state matters only to a flap (a running flap flips it, which must not void netem tokens)
            fingerprint={"state": lk.get("state") if sc.flap else None, "condition": current},
            blockers=blockers,
            side_effects=["Traffic across the link is impaired for every node in the lab"],
        )

        async def set_state(state: str) -> None:
            await app.api.put(f"/labs/{lid}/links/{lk['id']}/state/{'start' if state == 'up' else 'stop'}")

        async def apply() -> Any:
            if sc.flap:
                job = app.flaps.start(
                    FlapJob(
                        lab_id=lid,
                        lab_title=str(info.get("lab_title") or lid),
                        link_id=lk["id"],
                        link_name=name,
                        down_seconds=down_seconds,
                        up_seconds=up_seconds,
                        cycles=cycles,
                    ),
                    set_state,
                )
                return {"flap": job.view(), "expected_ping_delta": sc.expected()}
            res = await app.api.patch(f"/labs/{lid}/links/{lk['id']}/condition", netem_body(sc))
            return {
                "link": name,
                "scenario": sc.name,
                "conditioning": condition_view(res or {}),
                "expected_ping_delta": sc.expected(),
            }

        return await preview_or_apply(
            ctx,
            tool="cml_apply_link_scenario",
            args={
                "lab": lab,
                "link": link,
                "scenario": scenario,
                "down_seconds": down_seconds,
                "up_seconds": up_seconds,
                "cycles": cycles,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Clear link scenarios", idempotent=True)
    async def cml_clear_link_scenarios(
        ctx: Context,
        lab: LabRef,
        link: Annotated[
            str | None, Field(description="Only this link (id or 'r1<->r2'); default: every link in the lab")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Undo link scenarios in a lab: stop the flap jobs this server runs there (each flapped
        link is brought back up) and remove the conditioning from every conditioned link (named
        scenario or custom values from cml_set_link_condition). Links that are down for another
        reason are left alone. The preview lists what will be cleared."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        topo = await load_topo(app, lid)
        only = (await app.resolve_link(lid, link))["id"] if link else None
        by_id = {lk["id"]: lk for lk in topo.links}
        conds = {k: v for k, v in (await conditions(app, lid)).items() if only is None or k == only}
        flaps = [j for j in app.flaps.active(lid) if only is None or j.link_id == only]
        details = {
            "conditioning": {link_name(topo, by_id[k]) if k in by_id else k: v for k, v in conds.items()},
            "flaps": [j.link_name for j in flaps],
        }
        plan = Plan(
            f"Clear {len(conds)} conditioned link(s) and stop {len(flaps)} flap job(s) in lab "
            f"{info.get('lab_title')}",
            details=details,
            fingerprint={"conds": conds, "flaps": sorted(j.link_id for j in flaps)},
            blockers=[] if (conds or flaps) else ["Nothing to clear: no conditioned or flapping links"],
        )

        async def apply() -> Any:
            await app.flaps.cancel(flaps)
            cleared, failed = [], []
            for k in conds:
                nm = link_name(topo, by_id[k]) if k in by_id else k
                try:
                    await app.api.delete(f"/labs/{lid}/links/{k}/condition")
                    cleared.append(nm)
                except Exception as e:  # noqa: BLE001 - report per link, keep clearing the others
                    failed.append({"link": nm, "error": str(e)[:200]})
            return {
                "cleared": cleared,
                **({"failed": failed} if failed else {}),
                "flaps_stopped": [{"link": j.link_name, "phase": j.phase, "error": j.error} for j in flaps],
            }

        return await preview_or_apply(
            ctx,
            tool="cml_clear_link_scenarios",
            args={"lab": lab, "link": link},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
