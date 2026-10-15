"""Node and link write tools: add/update nodes, configs, node state, wiring, conditioning, captures."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import contextlib
import difflib
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    get_settings,
    poll_until,
    preview_or_apply,
)

from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.licence import explain_licence_error, licence_blocker, licence_usage, licensed
from cml_mcp.tools.common import LabRef, LinkRef, NodeRef, config_text, load_topo
from cml_mcp.tools.lab_writes import Wait, known_definitions
from cml_mcp.tools.smart import Timeout

RUNNING = ("STARTED", "QUEUED", "BOOTED")
WIPE_HINT = (
    "CML only accepts this change while the node is wiped (DEFINED_ON_CORE): stop it "
    "(cml_set_node_state), wipe it (cml_wipe_node, dangerous tier), change it, then start it again"
)


def node_fingerprint(node: dict[str, Any]) -> Any:
    return {k: node.get(k) for k in ("state", "label", "tags", "ram", "cpus", "x", "y", "node_definition")}


def config_diff(old: str, new: str, label: str) -> str:
    lines = list(
        difflib.unified_diff(
            old.splitlines(), new.splitlines(), f"{label} (current)", f"{label} (new)", lineterm="", n=1
        )
    )
    if len(lines) > 120:
        lines = lines[:120] + [f"... {len(lines) - 120} more lines"]
    return "\n".join(lines) or "(no change)"


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Add node")
    async def cml_add_node(
        ctx: Context,
        lab: LabRef,
        definition: Annotated[str, Field(description="Node definition id, e.g. iol-xe, ioll2-xe, alpine")],
        label: Annotated[
            str, Field(min_length=1, max_length=128, description="Node label (unique in the lab)")
        ],
        configuration: Annotated[
            str | None, Field(description="Day-0 configuration text (main config file)")
        ] = None,
        image: Annotated[str | None, Field(description="Image definition id (default: the newest)")] = None,
        x: Annotated[int, Field(description="Canvas X position")] = 0,
        y: Annotated[int, Field(description="Canvas Y position")] = 0,
        tags: Annotated[list[str] | None, Field(description="Tags, e.g. ['core']")] = None,
        ram: Annotated[
            int | None, Field(ge=64, description="RAM in MB (default from the definition)")
        ] = None,
        cpus: Annotated[
            int | None, Field(ge=1, le=64, description="vCPUs (default from the definition)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a node to a lab with the definition's default interfaces, optionally with a day-0
        configuration, image, position, tags and resources. The node starts stopped; wire it with
        cml_connect_nodes and boot it with cml_set_node_state or cml_start_lab. Preview checks the
        definition exists and the label is free."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        defs = await known_definitions(app)
        nodes = await app.list_nodes(lid)
        blockers = []
        if definition not in defs:
            blockers.append(f"Unknown node definition {definition!r} (see cml_list_node_definitions)")
        elif image and image not in (defs[definition].get("image_definitions") or []):
            blockers.append(
                f"Image {image!r} is not an image of {definition!r} (see cml_list_image_definitions)"
            )
        if any(n.get("label") == label for n in nodes):
            blockers.append(f"A node labelled {label!r} already exists in this lab")
        body: dict[str, Any] = {"node_definition": definition, "label": label, "x": x, "y": y}
        if configuration is not None:
            body["configuration"] = configuration
        if image:
            body["image_definition"] = image
        if tags:
            body["tags"] = tags
        if ram:
            body["ram"] = ram
        if cpus:
            body["cpus"] = cpus
        plan = Plan(
            f"Add {definition} node {label!r} to lab {info.get('lab_title')!r}",
            details={k: v for k, v in body.items() if k != "configuration"}
            | ({"configuration_lines": len(configuration.splitlines())} if configuration else {}),
            blockers=blockers,
        )

        async def apply() -> Any:
            res = await app.api.post(f"/labs/{lid}/nodes", body, params={"populate_interfaces": "true"})
            return {"id": res.get("id"), "label": label, "lab": info.get("lab_title")}

        return await preview_or_apply(
            ctx,
            tool="cml_add_node",
            args={
                "lab": lab,
                "definition": definition,
                "label": label,
                "configuration": configuration,
                "image": image,
                "x": x,
                "y": y,
                "tags": tags,
                "ram": ram,
                "cpus": cpus,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Update node", idempotent=True)
    async def cml_update_node(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        label: Annotated[str | None, Field(description="New label")] = None,
        tags: Annotated[list[str] | None, Field(description="Replace the tags with this list")] = None,
        x: Annotated[int | None, Field(description="New canvas X position")] = None,
        y: Annotated[int | None, Field(description="New canvas Y position")] = None,
        ram: Annotated[int | None, Field(ge=64, description="RAM in MB (node must be wiped)")] = None,
        cpus: Annotated[int | None, Field(ge=1, le=64, description="vCPUs (node must be wiped)")] = None,
        login_username: Annotated[
            str | None, Field(description="Console login user (CML pyATS username) the CLI tools use")
        ] = None,
        login_password: Annotated[
            str | None, Field(description="Console login password (CML pyATS password)")
        ] = None,
        enable_password: Annotated[str | None, Field(description="Enable secret (CML pyATS)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a node's label, tags, position, resources or console login. Label, tags, position
        and login can change at any time; RAM and vCPUs only while the node is wiped
        (DEFINED_ON_CORE). The login (CML's pyATS credentials) is what cml_run_commands and
        cml_configure_node use: update it after changing a device's password. The preview shows each
        field's old and new value (passwords only as 'changed'). For the configuration use
        cml_set_node_config."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        desired = {
            k: v
            for k, v in {"label": label, "tags": tags, "x": x, "y": y, "ram": ram, "cpus": cpus}.items()
            if v is not None
        }
        changes = field_changes(n, desired)
        current_login = {k: v for k, v in (n.get("pyats") or {}).items() if v is not None}
        login = {
            k: v
            for k, v in {
                "username": login_username,
                "password": login_password,
                "enable_password": enable_password,
            }.items()
            if v is not None and current_login.get(k) != v
        }
        for k in login:
            changes[f"login_{k}"] = (
                {"from": current_login.get(k), "to": login[k]}
                if k == "username"
                else {"from": "(hidden)", "to": "(changed)"}
            )
        blockers = []
        if not changes:
            blockers.append(
                "Nothing to change: every given field already has that value"
                if desired
                else "Nothing to change: give at least one field"
            )
        if {"ram", "cpus"} & set(changes) and n.get("state") != "DEFINED_ON_CORE":
            blockers.append(f"Node is {n.get('state')}; {WIPE_HINT}")
        if (
            label
            and label != n.get("label")
            and any(o.get("label") == label for o in await app.list_nodes(lid) if o["id"] != n["id"])
        ):
            blockers.append(f"Another node is already labelled {label!r}")
        plan = Plan(
            f"Update node {n.get('label')!r}" + ("" if changes else " (no changes)"),
            details={"changes": changes},
            fingerprint=node_fingerprint(n),
            blockers=blockers,
        )

        async def apply() -> Any:
            body: dict[str, Any] = {k: desired[k] for k in changes if k in desired}
            if login:
                body["pyats"] = {**current_login, **login}
            await app.api.patch(f"/labs/{lid}/nodes/{n['id']}", body)
            return {"id": n["id"], "changed": sorted(changes)}

        return await preview_or_apply(
            ctx,
            tool="cml_update_node",
            args={
                "lab": lab,
                "node": node,
                "label": label,
                "tags": tags,
                "x": x,
                "y": y,
                "ram": ram,
                "cpus": cpus,
                "login_username": login_username,
                "login_password": login_password,
                "enable_password": enable_password,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set node configuration", idempotent=True)
    async def cml_set_node_config(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        configuration: Annotated[str, Field(description="The complete new day-0 configuration text")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Replace a node's stored day-0 configuration (the config it boots with). The preview shows a
        unified diff against the current one. CML accepts this only while the node is wiped
        (DEFINED_ON_CORE); to change a running device use its CLI. Restart the node to apply."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        full = await app.api.get(f"/labs/{lid}/nodes/{n['id']}")
        current = config_text(full) or ""
        blockers = [] if n.get("state") == "DEFINED_ON_CORE" else [f"Node is {n.get('state')}; {WIPE_HINT}"]
        plan = Plan(
            f"Replace the day-0 configuration of {n.get('label')!r}",
            details={"diff": config_diff(current, configuration, str(n.get("label")))},
            fingerprint={"state": n.get("state"), "config": current},
            blockers=blockers,
        )

        async def apply() -> Any:
            await app.api.patch(
                f"/labs/{lid}/nodes/{n['id']}",
                {"configuration": [{"name": "Main", "content": configuration}]},
            )
            return {"id": n["id"], "lines": len(configuration.splitlines())}

        return await preview_or_apply(
            ctx,
            tool="cml_set_node_config",
            args={"lab": lab, "node": node, "configuration": configuration},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Start or stop node", idempotent=True)
    async def cml_set_node_state(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        state: Annotated[
            Literal["start", "stop"], Field(description="'start' boots the node, 'stop' powers it off")
        ],
        wait: Wait = True,
        timeout: Timeout = None,  # noqa: ASYNC109 - overall wait, handled by poll_until
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Start (boot) or stop (power off) a single node. Starting waits until the node has booted
        unless wait=false; stopping waits until it is STOPPED. Stopping loses unsaved running config
        (cml_extract_node_configs saves it)."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        current = n.get("state")
        noop = (state == "start" and current in RUNNING) or (state == "stop" and current not in RUNNING)
        blockers = []
        if (
            state == "start"
            and not noop
            and licensed(n)
            and (problem := licence_blocker(await licence_usage(app), 1, exclude=lid))
        ):
            blockers.append(problem)
        plan = Plan(
            f"{state.capitalize()} node {n.get('label')!r} (currently {current})"
            + (" - already done" if noop else ""),
            details={"node": n.get("label"), "from": current, "wait": wait},
            fingerprint=node_fingerprint(n),
            blockers=blockers,
        )
        limit = timeout or get_settings(ctx).wait_timeout

        async def apply() -> Any:
            try:
                await app.api.put(f"/labs/{lid}/nodes/{n['id']}/state/{state}")
            except UpstreamError as e:
                raise await explain_licence_error(app, e, f"Could not start {n.get('label')!r}") from e
            if not wait:
                return {"requested": state}
            if state == "start":
                return await wait_converged(app, lid, node_id=n["id"], timeout=limit, ctx=ctx)
            final = await poll_until(
                lambda: app.api.get(f"/labs/{lid}/nodes/{n['id']}/state"),
                done=lambda s: (
                    (s.get("state") if isinstance(s, dict) else s) in ("STOPPED", "DEFINED_ON_CORE")
                ),
                timeout=limit,
                interval=2.0,
                max_interval=5.0,
                ctx=ctx,
                what="node to stop",
            )
            return {"state": final.get("state") if isinstance(final, dict) else final}

        return await preview_or_apply(
            ctx,
            tool="cml_set_node_state",
            args={"lab": lab, "node": node, "state": state, "wait": wait, "timeout": timeout},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Connect nodes")
    async def cml_connect_nodes(
        ctx: Context,
        lab: LabRef,
        node_a: Annotated[str, Field(description="First node (label or id)")],
        node_b: Annotated[str, Field(description="Second node (label or id)")],
        interface_a: Annotated[
            str | None, Field(description="Interface on node_a, e.g. Ethernet0/1 (default: first free)")
        ] = None,
        interface_b: Annotated[
            str | None, Field(description="Interface on node_b (default: first free)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a link between two nodes. Without interface names it picks the first free physical
        interface on each side, adding a new interface when a wiped node has none free. The preview
        names the exact interfaces. Links can be added to running nodes if they have a free
        interface."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        a = await app.resolve_node(lid, node_a, exact=True)
        b = await app.resolve_node(lid, node_b, exact=True)
        topo = await load_topo(app, lid)
        peers = topo.peers()
        blockers: list[str] = []
        if a["id"] == b["id"]:
            blockers.append("node_a and node_b are the same node")

        def choose(n: dict[str, Any], wanted: str | None) -> tuple[str | None, str]:
            ifaces = sorted(
                (i for i in topo.interfaces.values() if i.get("node") == n["id"]),
                key=lambda i: (i.get("slot") is None, i.get("slot") or 0),
            )
            if wanted:
                match = [i for i in ifaces if wanted in (i.get("label"), i["id"])]
                if not match:
                    blockers.append(f"{n.get('label')} has no interface {wanted!r} (see cml_list_interfaces)")
                    return None, wanted
                if match[0]["id"] in peers:
                    blockers.append(
                        f"{n.get('label')}:{wanted} is already connected to {peers[match[0]['id']][0]}"
                    )
                if match[0].get("type") != "physical":
                    blockers.append(
                        f"{n.get('label')}:{wanted} is a {match[0].get('type')} interface; "
                        "links need physical ones"
                    )
                return match[0]["id"], str(match[0].get("label"))
            for i in ifaces:
                if i.get("type") == "physical" and i["id"] not in peers:
                    return i["id"], str(i.get("label"))
            if n.get("state") != "DEFINED_ON_CORE":
                blockers.append(
                    f"{n.get('label')} has no free interface and is {n.get('state')}; {WIPE_HINT}"
                )
            return None, "(new interface)"

        ia, name_a = choose(a, interface_a)
        ib, name_b = choose(b, interface_b)
        plan = Plan(
            f"Connect {a.get('label')}:{name_a} <-> {b.get('label')}:{name_b}",
            details={"a": f"{a.get('label')}:{name_a}", "b": f"{b.get('label')}:{name_b}"},
            fingerprint={
                "a": ia,
                "b": ib,
                "peers": sorted(peers),
                "states": [a.get("state"), b.get("state")],
            },
            blockers=blockers,
        )

        async def ensure(n: dict[str, Any], iface: str | None) -> str:
            if iface:
                return iface
            created = await app.api.post(f"/labs/{lid}/interfaces", {"node": n["id"]})
            if isinstance(created, list):
                created = created[-1]
            return str(created["id"])

        async def apply() -> Any:
            created: list[str] = []
            try:
                src = await ensure(a, ia)
                if src != ia:
                    created.append(src)
                dst = await ensure(b, ib)
                if dst != ib:
                    created.append(dst)
                res = await app.api.post(f"/labs/{lid}/links", {"src_int": src, "dst_int": dst})
            except Exception:
                for iface_id in created:  # don't leave half-done work behind
                    with contextlib.suppress(Exception):
                        await app.api.delete(f"/labs/{lid}/interfaces/{iface_id}")
                raise
            fresh = await load_topo(app, lid)
            return {"id": res.get("id"), "a": fresh.endpoint(src), "b": fresh.endpoint(dst)}

        return await preview_or_apply(
            ctx,
            tool="cml_connect_nodes",
            args={
                "lab": lab,
                "node_a": node_a,
                "node_b": node_b,
                "interface_a": interface_a,
                "interface_b": interface_b,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set link conditioning", idempotent=True)
    async def cml_set_link_condition(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        latency_ms: Annotated[
            int | None, Field(ge=0, le=10000, description="Added one-way delay (ms)")
        ] = None,
        jitter_ms: Annotated[int | None, Field(ge=0, le=10000, description="Delay variation (ms)")] = None,
        loss_pct: Annotated[float | None, Field(ge=0, le=100, description="Packet loss (%)")] = None,
        bandwidth_kbps: Annotated[
            int | None, Field(ge=0, le=10_000_000, description="Rate limit (kbps)")
        ] = None,
        duplicate_pct: Annotated[
            float | None, Field(ge=0, le=100, description="Duplicated packets (%)")
        ] = None,
        corrupt_pct: Annotated[float | None, Field(ge=0, le=100, description="Corrupted packets (%)")] = None,
        clear: Annotated[bool, Field(description="Remove all conditioning from the link instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Impair a link like a WAN (netem): latency, jitter, loss, bandwidth limit, duplication,
        corruption; or clear=true to remove all conditioning. Applies live to running links. The
        preview shows the current and new settings; fields you leave out are reset to none."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        topo = await load_topo(app, lid)
        current = await app.api.get(f"/labs/{lid}/links/{lk['id']}/condition") or {}
        current_view = {k: v for k, v in current.items() if k != "operational" and v is not None}
        desired = {
            "latency": latency_ms,
            "jitter": jitter_ms,
            "loss": loss_pct,
            "bandwidth": bandwidth_kbps,
            "duplicate": duplicate_pct,
            "corrupt_prob": corrupt_pct,
        }
        body = {k: v for k, v in desired.items() if v is not None}
        full = {**desired, "enabled": True}  # omitted impairments are reset to none
        blockers = [] if (clear or body) else ["Give at least one impairment, or clear=true"]
        name = f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}"
        plan = Plan(
            f"{'Clear conditioning on' if clear else 'Condition'} link {name}",
            details={"current": current_view, "new": {} if clear else {**body, "enabled": True}},
            fingerprint=current_view,
            blockers=blockers,
        )

        async def apply() -> Any:
            if clear:
                await app.api.delete(f"/labs/{lid}/links/{lk['id']}/condition")
                return {"cleared": True}
            res = await app.api.patch(f"/labs/{lid}/links/{lk['id']}/condition", full)
            return {k: v for k, v in (res or {}).items() if k != "operational" and v is not None}

        return await preview_or_apply(
            ctx,
            tool="cml_set_link_condition",
            args={
                "lab": lab,
                "link": link,
                "latency_ms": latency_ms,
                "jitter_ms": jitter_ms,
                "loss_pct": loss_pct,
                "bandwidth_kbps": bandwidth_kbps,
                "duplicate_pct": duplicate_pct,
                "corrupt_pct": corrupt_pct,
                "clear": clear,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Link up/down", idempotent=True)
    async def cml_set_link_state(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        state: Annotated[
            Literal["up", "down"], Field(description="'down' disconnects the link like a cable pull")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Bring a link down (simulated cable pull: both ends lose carrier) or back up, to test
        failover and convergence. Only meaningful in a running lab."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        topo = await load_topo(app, lid)
        name = f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}"
        plan = Plan(
            f"Bring link {name} {state} (currently {lk.get('state')})",
            details={"link": name, "from": lk.get("state")},
            fingerprint=lk.get("state"),
            blockers=[]
            if lk.get("state") in ("STARTED", "STOPPED")
            else [f"Link is {lk.get('state')}; links can only go up/down in a started lab"],
        )

        async def apply() -> Any:
            await app.api.put(f"/labs/{lid}/links/{lk['id']}/state/{'start' if state == 'up' else 'stop'}")
            fresh = await app.api.get(f"/labs/{lid}/links/{lk['id']}")
            return {"link": name, "state": fresh.get("state")}

        return await preview_or_apply(
            ctx,
            tool="cml_set_link_state",
            args={"lab": lab, "link": link, "state": state},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Start packet capture")
    async def cml_start_capture(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        max_packets: Annotated[
            int, Field(ge=1, le=1_000_000, description="Stop after this many packets")
        ] = 1000,
        max_time: Annotated[int, Field(ge=1, le=86400, description="Stop after this many seconds")] = 300,
        bpf_filter: Annotated[
            str | None, Field(description="Berkeley packet filter, e.g. 'icmp or arp'")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Start a packet capture on a running link (stops by itself after max_packets or max_time).
        Read the decoded packets with cml_list_capture_packets and stop early with cml_stop_capture.
        A new capture replaces the previous one on that link."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        status = await app.api.get(f"/labs/{lid}/links/{lk['id']}/capture/status") or {}
        body: dict[str, Any] = {"maxpackets": max_packets, "maxtime": max_time}
        if bpf_filter:
            body["bpfilter"] = bpf_filter
        blockers = []
        if lk.get("state") != "STARTED":
            blockers.append(f"Link is {lk.get('state')}; captures need a running link (start the lab first)")
        if status.get("starttime"):
            blockers.append("A capture is already running on this link; stop it first with cml_stop_capture")
        plan = Plan(f"Start packet capture on link {lk.get('label')}", details=body, blockers=blockers)

        async def apply() -> Any:
            res = await app.api.put(f"/labs/{lid}/links/{lk['id']}/capture/start", body)
            return {"started": (res or {}).get("starttime"), "next": "cml_list_capture_packets"}

        return await preview_or_apply(
            ctx,
            tool="cml_start_capture",
            args={
                "lab": lab,
                "link": link,
                "max_packets": max_packets,
                "max_time": max_time,
                "bpf_filter": bpf_filter,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Stop packet capture", idempotent=True)
    async def cml_stop_capture(
        ctx: Context,
        lab: LabRef,
        link: LinkRef,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stop the running packet capture on a link. The captured packets stay readable with
        cml_list_capture_packets until the next capture starts."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        status = await app.api.get(f"/labs/{lid}/links/{lk['id']}/capture/status") or {}
        plan = Plan(
            f"Stop packet capture on link {lk.get('label')}",
            details={"packets_captured": status.get("packetscaptured")},
            blockers=[] if status.get("starttime") else ["No capture is running on this link"],
        )

        async def apply() -> Any:
            await app.api.put(f"/labs/{lid}/links/{lk['id']}/capture/stop")
            return {"stopped": True}

        return await preview_or_apply(
            ctx,
            tool="cml_stop_capture",
            args={"lab": lab, "link": link},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
