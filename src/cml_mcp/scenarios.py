"""Named link conditioning scenarios (netem profiles) and the background link flapper.

CML applies link conditioning to **both directions** of a link (measured on CML 2.10: latency 50 ms
gives a 100 ms ping RTT, 30 % loss drops about half the echoes). The expected ping deltas below are
therefore round-trip values: RTT + 2 x latency (+- 2 x jitter), round-trip loss 1 - (1 - p)^2.

Flapping is the only scenario that changes link state over time. It runs as an asyncio task inside
the server process (it lives as long as the process: a stdio server that exits stops it). It is a
write *we* drive on a timer, not event ingestion: nothing is received or buffered (core ADR-003).
Every job leaves the link up when it ends, is cancelled, or the server shuts down.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from cml_mcp._core.writes import field_changes

log = logging.getLogger(__name__)

# netem fields CML accepts on PATCH /labs/{lab}/links/{link}/condition (LinkConditionConfiguration)
NETEM_FIELDS = ("latency", "jitter", "loss", "bandwidth", "duplicate", "corrupt_prob")


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    use_for: str
    netem: dict[str, float] = field(default_factory=dict)
    flap: bool = False

    def expected(self) -> dict[str, Any]:
        """Expected change in a ping matrix across the conditioned link (round trip)."""
        if self.flap:
            return {
                "while_down": "0 % success across the link; routing protocols drop the adjacency after "
                "their dead timer (IOS OSPF 40 s) unless the down time is shorter",
                "while_up": "pings recover once ARP/routing reconverge (a few seconds on a direct link)",
            }
        lat = float(self.netem.get("latency", 0))
        jit = float(self.netem.get("jitter", 0))
        loss = float(self.netem.get("loss", 0)) / 100
        out: dict[str, Any] = {
            "rtt_added_ms": round(2 * lat),
            "rtt_spread_ms": round(2 * jit),
            "round_trip_loss_pct": round(100 * (1 - (1 - loss) ** 2), 1),
        }
        if self.netem.get("bandwidth"):
            out["throughput_kbps_max"] = int(self.netem["bandwidth"])
        if self.netem.get("duplicate") or self.netem.get("corrupt_prob"):
            out["note"] = "duplicates show as 'DUP!' on Linux ping; corrupted frames count as loss"
        if lat * 2 + jit * 2 >= 2000:
            out["ping_timeout_hint"] = "RTT may exceed the IOS default 2 s ping timeout"
        return out

    def view(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "description": self.description, "use_for": self.use_for}
        if self.netem:
            out["netem"] = dict(self.netem)
        if self.flap:
            out["flap"] = {
                "default_down_seconds": FLAP_DEFAULTS[0],
                "default_up_seconds": FLAP_DEFAULTS[1],
                "default_cycles": FLAP_DEFAULTS[2],
            }
        out["expected_ping_delta"] = self.expected()
        return out


FLAP_DEFAULTS = (20, 40, 3)  # down seconds, up seconds, cycles
FLAP_MAX_TOTAL_SECONDS = 4 * 3600

SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario(
            "wan-good",
            "A healthy MPLS/Internet WAN: 20 ms one way, 2 ms jitter, 0.1 % loss, 50 Mbit/s.",
            "Baseline for site-to-site VPN, SD-WAN and RADIUS-over-WAN tests",
            {"latency": 20, "jitter": 2, "loss": 0.1, "bandwidth": 50_000},
        ),
        Scenario(
            "wan-satellite",
            "GEO satellite: 300 ms one way, 20 ms jitter, 0.5 % loss, 5 Mbit/s.",
            "Timer-sensitive protocols (BFD, HA hellos, RADIUS timeouts, TCP throughput)",
            {"latency": 300, "jitter": 20, "loss": 0.5, "bandwidth": 5_000},
        ),
        Scenario(
            "lossy-wifi",
            "A congested wireless hop: 5 ms one way, 30 ms jitter, 5 % loss, 1 % duplicates.",
            "Client-side flakiness: 802.1X/EAP retransmits, DHCP retries, assurance health scores",
            {"latency": 5, "jitter": 30, "loss": 5, "duplicate": 1},
        ),
        Scenario(
            "brownout",
            "A failing circuit: 150 ms one way, 50 ms jitter, 20 % loss, 256 kbit/s.",
            "Degraded-but-up links: does failover trigger, do health scores drop, do RADIUS servers "
            "get marked dead",
            {"latency": 150, "jitter": 50, "loss": 20, "bandwidth": 256},
        ),
        Scenario(
            "flap",
            "Timed down/up cycles (a cable pulled and replugged), run in the background; with `side` only "
            "one end loses carrier (an optic failing on one side).",
            "HA failover (FTD failover link), routing reconvergence (OSPF), NAD RADIUS dead timers",
            flap=True,
        ),
    )
}


def netem_body(s: Scenario) -> dict[str, Any]:
    """Full PATCH body: every netem field set (fields the profile leaves out reset to none)."""
    return {**{k: s.netem.get(k) for k in NETEM_FIELDS}, "enabled": True}


def condition_changes(current: dict[str, Any], new: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Preview diff for a conditioning PATCH that sends every netem field (omitted ones reset), so it acts
    as a replace: impairments it resets are listed as removed. `new` is {} for a clear."""
    known = {k: v for k, v in current.items() if k in (*NETEM_FIELDS, "enabled")}
    return field_changes(known, {k: v for k, v in new.items() if v is not None}, replace=True)


def match_scenario(cond: dict[str, Any]) -> str | None:
    """The profile name whose netem values the link's current conditioning equals, if any."""
    if not cond.get("enabled"):
        return None
    current = {k: float(cond[k]) for k in NETEM_FIELDS if cond.get(k) not in (None, 0)}
    for s in SCENARIOS.values():
        if s.netem and current == {k: float(v) for k, v in s.netem.items()}:
            return s.name
    return "custom" if current else None


# --- flapping -------------------------------------------------------------------------------

SetState = Callable[[str], Awaitable[None]]  # "up" | "down"


@dataclass
class FlapJob:
    lab_id: str
    lab_title: str
    link_id: str
    link_name: str
    down_seconds: float
    up_seconds: float
    cycles: int
    side: str | None = (
        None  # one-sided flap: the interface ('r1:Ethernet0/0') that goes down; peer keeps carrier
    )
    started: float = field(default_factory=time.time)
    cycles_done: int = 0
    phase: str = "starting"
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    def view(self) -> dict[str, Any]:
        total = self.cycles * (self.down_seconds + self.up_seconds)
        out: dict[str, Any] = {
            "lab": self.lab_title,
            "link": self.link_name,
            "link_id": self.link_id,
            **({"side": self.side} if self.side else {}),
            "running": self.running,
            "phase": self.phase,
            "cycles_done": self.cycles_done,
            "cycles": self.cycles,
            "down_seconds": self.down_seconds,
            "up_seconds": self.up_seconds,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started)),
            "ends_by": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started + total)),
            "events": self.events[-12:],
        }
        if self.error:
            out["error"] = self.error
        return out


class FlapManager:
    """Background flap jobs of one server process, keyed by link id (one job per link)."""

    def __init__(self) -> None:
        self.jobs: dict[str, FlapJob] = {}

    def active(self, lab_id: str | None = None) -> list[FlapJob]:
        return [j for j in self.jobs.values() if j.running and (lab_id is None or j.lab_id == lab_id)]

    def recent(self, lab_id: str | None = None) -> list[FlapJob]:
        return [j for j in self.jobs.values() if lab_id is None or j.lab_id == lab_id]

    def start(self, job: FlapJob, set_state: SetState) -> FlapJob:
        # no await between this check and create_task: two concurrent starts cannot both pass
        old = self.jobs.get(job.link_id)
        if old is not None and old.running:
            raise RuntimeError(f"link {job.link_name} is already flapping")
        job.task = asyncio.create_task(self._run(job, set_state), name=f"cml-flap-{job.link_id}")
        self.jobs[job.link_id] = job
        return job

    async def _run(self, job: FlapJob, set_state: SetState) -> None:
        def note(what: str) -> None:
            job.phase = what
            job.events.append({"t": time.strftime("%H:%M:%S", time.gmtime()), "link": what})

        try:
            for i in range(job.cycles):
                await set_state("down")
                note("down")
                await asyncio.sleep(job.down_seconds)
                await set_state("up")
                note("up")
                job.cycles_done = i + 1
                if i + 1 < job.cycles:
                    await asyncio.sleep(job.up_seconds)
            job.phase = "done"
        except asyncio.CancelledError:
            job.phase = "cancelled"
            await self._restore(job, set_state)
            raise
        except Exception as e:  # noqa: BLE001 - recorded on the job, link restored
            job.error = str(e)[:300]
            job.phase = "failed"
            await self._restore(job, set_state)

    @staticmethod
    async def _restore(job: FlapJob, set_state: SetState) -> None:
        """Bring the link back up; retried, because a link left down silently is the worst outcome."""
        last: Exception | None = None
        for attempt in range(3):
            try:
                await asyncio.shield(asyncio.wait_for(set_state("up"), 30))
                job.events.append({"t": time.strftime("%H:%M:%S", time.gmtime()), "link": "up (restored)"})
                return
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                last = e
                await asyncio.sleep(1 + 2 * attempt)
        log.warning("could not bring link %s back up: %s", job.link_name, last)
        fix = (
            f"cml_set_interface_state on {job.side} (state='up')"
            if job.side
            else "cml_set_link_state(state='up')"
        )
        job.error = f"LINK MAY STILL BE DOWN: could not bring it back up ({str(last)[:200]}); use {fix}"

    async def cancel(self, jobs: list[FlapJob]) -> None:
        """Cancel the jobs and wait for their restores (concurrently). A cancel of the caller still
        propagates (gather with return_exceptions only absorbs the jobs' own outcomes)."""
        tasks = [j.task for j in jobs if j.task is not None]
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def shutdown(self) -> None:
        await self.cancel(self.active())
