"""Destructive tools (dangerous tier): wipe and delete labs, nodes and links."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cml_mcp._core import (
    Confirm,
    Plan,
    ToolRegistrar,
    get_client,
    get_settings,
    poll_until,
)
from cml_mcp.archive import archive_check
from cml_mcp.client import CmlApp
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import LabRef, LinkRef, NodeRef, load_topo, state_counts
from cml_mcp.tools.lab_writes import lab_fingerprint, wait_for_lab_state
from cml_mcp.tools.topology_writes import RUNNING, node_fingerprint

Force = Annotated[
    bool, Field(description="Stop (and wipe) first if needed, instead of refusing while it is running")
]


async def stop_and_wipe_lab(app: CmlApp, lid: str, state: str, ctx: Context) -> None:
    limit = get_settings(ctx).wait_timeout
    if state in RUNNING:
        await app.api.put(f"/labs/{lid}/stop")
        state = await wait_for_lab_state(app, lid, ("STOPPED", "DEFINED_ON_CORE"), limit, ctx)
    if state != "DEFINED_ON_CORE":
        await app.api.put(f"/labs/{lid}/wipe")
        await wait_for_lab_state(app, lid, ("DEFINED_ON_CORE",), limit, ctx)


async def stop_and_wipe_node(app: CmlApp, lid: str, node: dict[str, Any], ctx: Context) -> None:
    nid = node["id"]
    if node.get("state") in RUNNING:
        await app.api.put(f"/labs/{lid}/nodes/{nid}/state/stop")
        await poll_until(
            lambda: app.api.get(f"/labs/{lid}/nodes/{nid}/state"),
            done=lambda s: (s.get("state") if isinstance(s, dict) else s) in ("STOPPED", "DEFINED_ON_CORE"),
            timeout=get_settings(ctx).wait_timeout,
            interval=2.0,
            max_interval=5.0,
            ctx=ctx,
            what="node to stop",
        )
    await app.api.put(f"/labs/{lid}/nodes/{nid}/wipe_disks")


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Wipe lab")
    async def cml_wipe_lab(
        ctx: Context, lab: LabRef, force: Force = False, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Wipe a stopped lab: erase every node's disk so the next start boots fresh from the day-0
        configs (running configs and files on the nodes are lost). Required before changing node
        configs/resources. force=true stops the lab first. The preview shows the lab's latest archive
        (CML_ARCHIVE_DIR) and warns when there is none newer than the lab's last change: cml_archive_lab
        first."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid, state = info["id"], str(info.get("state"))
        blockers = []
        if state == "DEFINED_ON_CORE":
            blockers.append("Lab is already wiped")
        elif state in RUNNING and not force:
            blockers.append(f"Lab is {state}; stop it first (cml_stop_lab) or pass force=true")
        archive, warning = archive_check(get_settings(ctx).archive_dir, info)
        plan = Plan(
            f"WIPE lab {info.get('lab_title')!r} ({info.get('node_count')} nodes)",
            details={"state": state, "force": force, "archive": archive},
            fingerprint=lab_fingerprint(info),
            blockers=blockers,
            side_effects=["All node disks are erased; unsaved running configs are lost (irreversible)"]
            + (["The lab is stopped first"] if state in RUNNING else [])
            + ([warning] if warning else []),
        )

        async def apply() -> Any:
            await stop_and_wipe_lab(app, lid, state, ctx)
            return {"state": "DEFINED_ON_CORE"}

        return await preview_or_apply(
            ctx,
            tool="cml_wipe_lab",
            args={"lab": lab, "force": force},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete lab")
    async def cml_delete_lab(
        ctx: Context, lab: LabRef, force: Force = False, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Delete a lab and everything in it (nodes, configs, links, captures). CML only deletes
        stopped and wiped labs; force=true stops and wipes it first. Archive it first (cml_archive_lab) if
        it might be needed again: the preview shows the latest archive and warns when there is none newer
        than the lab's last change. Irreversible."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid, state = info["id"], str(info.get("state"))
        nodes = await app.list_nodes(lid)
        blockers = []
        if state != "DEFINED_ON_CORE" and not force:
            blockers.append(
                f"Lab is {state}; CML deletes only wiped labs. Pass force=true to stop and wipe it first"
            )
        archive, warning = archive_check(get_settings(ctx).archive_dir, info)
        plan = Plan(
            f"DELETE lab {info.get('lab_title')!r} ({len(nodes)} nodes, {info.get('link_count')} links)",
            details={
                "id": lid,
                "state": state,
                "node_states": state_counts(nodes),
                "force": force,
                "archive": archive,
            },
            fingerprint=lab_fingerprint(info),
            blockers=blockers,
            side_effects=["The lab and all its nodes, configs and links are deleted (irreversible)"]
            + ([warning] if warning else []),
        )

        async def apply() -> Any:
            await stop_and_wipe_lab(app, lid, state, ctx)
            await app.api.delete(f"/labs/{lid}")
            return {"deleted": lid}

        return await preview_or_apply(
            ctx,
            tool="cml_delete_lab",
            args={"lab": lab, "force": force},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Wipe node")
    async def cml_wipe_node(
        ctx: Context, lab: LabRef, node: NodeRef, force: Force = False, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Wipe one stopped node: erase its disk so it boots fresh from its day-0 config, and unlock
        config/interface/resource changes (cml_set_node_config, cml_update_node). force=true stops
        it first. Its running config is lost unless saved with cml_extract_node_configs."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        state = n.get("state")
        blockers = []
        if state == "DEFINED_ON_CORE":
            blockers.append("Node is already wiped")
        elif state in RUNNING and not force:
            blockers.append(f"Node is {state}; stop it first (cml_set_node_state) or pass force=true")
        plan = Plan(
            f"WIPE node {n.get('label')!r} in {info.get('lab_title')!r}",
            details={"state": state, "force": force},
            fingerprint=node_fingerprint(n),
            blockers=blockers,
            side_effects=["The node's disk is erased (irreversible)"],
        )

        async def apply() -> Any:
            await stop_and_wipe_node(app, lid, n, ctx)
            return {"node": n.get("label"), "state": "DEFINED_ON_CORE"}

        return await preview_or_apply(
            ctx,
            tool="cml_wipe_node",
            args={"lab": lab, "node": node, "force": force},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete node")
    async def cml_delete_node(
        ctx: Context, lab: LabRef, node: NodeRef, force: Force = False, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Delete a node and its links from a lab. CML only deletes wiped nodes; force=true stops and
        wipes it first. The preview lists the links that go with it. Irreversible."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        topo = await load_topo(app, lid)
        links = [
            f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}"
            for lk in topo.links
            if n["id"] in (lk.get("node_a"), lk.get("node_b"))
        ]
        state = n.get("state")
        blockers = []
        if state != "DEFINED_ON_CORE" and not force:
            blockers.append(
                f"Node is {state}; CML deletes only wiped nodes. Pass force=true to stop and wipe it"
            )
        plan = Plan(
            f"DELETE node {n.get('label')!r} from {info.get('lab_title')!r}",
            details={"state": state, "links_removed": links, "force": force},
            fingerprint={"node": node_fingerprint(n), "links": links},
            blockers=blockers,
            side_effects=[f"{len(links)} link(s) are removed with it (irreversible)"],
        )

        async def apply() -> Any:
            if state != "DEFINED_ON_CORE":
                await stop_and_wipe_node(app, lid, n, ctx)
            await app.api.delete(f"/labs/{lid}/nodes/{n['id']}")
            return {"deleted": n.get("label"), "links_removed": links}

        return await preview_or_apply(
            ctx,
            tool="cml_delete_node",
            args={"lab": lab, "node": node, "force": force},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete link")
    async def cml_delete_link(
        ctx: Context, lab: LabRef, link: LinkRef, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Remove a link between two interfaces (works on running labs: both ends lose carrier). The
        interfaces stay and can be reconnected with cml_connect_nodes. Its conditioning and capture
        are lost."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        lk = await app.resolve_link(lid, link)
        topo = await load_topo(app, lid)
        name = f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}"
        plan = Plan(
            f"DELETE link {name} in {info.get('lab_title')!r}",
            details={"id": lk["id"], "state": lk.get("state")},
            fingerprint=lk.get("state"),
            side_effects=["Both interfaces lose carrier if the lab is running"],
        )

        async def apply() -> Any:
            await app.api.delete(f"/labs/{lid}/links/{lk['id']}")
            return {"deleted": name}

        return await preview_or_apply(
            ctx,
            tool="cml_delete_link",
            args={"lab": lab, "link": link},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
