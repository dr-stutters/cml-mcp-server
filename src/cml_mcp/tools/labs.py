"""Lab read tools: list, details, topology, export, events, pyATS testbed."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    text_result,
)
from stutters_mcp_core.formatting import MASK
from stutters_mcp_core.http import page_of

from cml_mcp.client import CmlApp
from cml_mcp.tools.common import ACCESS_KEYS, LabRef, Topo, drop_keys, load_topo, shaped, state_counts

LAB_STATES = ("DEFINED_ON_CORE", "STARTED", "QUEUED", "BOOTED", "STOPPED")


def lab_row(lab: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": lab["id"],
        "title": lab.get("lab_title"),
        "state": lab.get("state"),
        "node_count": lab.get("node_count"),
        "link_count": lab.get("link_count"),
        "owner": lab.get("owner_username"),
        "modified": lab.get("modified"),
    }


def topology_summary(lab: dict[str, Any], topo: Topo, conditions: dict[str, Any]) -> dict[str, Any]:
    peers = topo.peers()
    nodes = []
    for n in topo.nodes.values():
        ifaces = [i for i in topo.interfaces.values() if i.get("node") == n["id"]]
        connected = {i["label"]: peers[i["id"]][0] for i in ifaces if i["id"] in peers}
        row: dict[str, Any] = {
            "label": n.get("label"),
            "id": n["id"],
            "definition": n.get("node_definition"),
            "state": n.get("state"),
            "connections": connected,
            "free_interfaces": sum(1 for i in ifaces if i["id"] not in peers and i.get("type") == "physical"),
        }
        if n.get("tags"):
            row["tags"] = n["tags"]
        nodes.append(row)
    links = []
    for lk in topo.links:
        row = topo.link_row(lk)
        if conditions.get(lk["id"]):
            row["conditioning"] = conditions[lk["id"]]
        links.append(row)
    return {
        "lab": {"id": lab["id"], "title": lab.get("lab_title"), "state": lab.get("state")},
        "node_states": state_counts(list(topo.nodes.values())),
        "nodes": nodes,
        "links": links,
    }


def mask_testbed(text: str) -> str:
    """Mask `password:` values in a pyATS testbed YAML (keeps structure)."""
    return re.sub(r"(?m)^(\s*(?:-\s+)?password:\s*)(?!null\s*$)(\S.*)$", rf"\g<1>{MASK}", text)


def mask_export(text: str) -> str:
    """Mask pyATS credentials stored on nodes in an exported topology (configs are left alone)."""
    return re.sub(
        r"(?m)^(\s*(?:-\s+)?(?:password|enable_password):\s*)(?!null\s*$)(\S.*)$", rf"\g<1>{MASK}", text
    )


def event_row(ev: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    data = ev.get("data") or {}
    prev = ev.get("previous") or {}
    elem = ev.get("element_id") or ""
    name = names.get(elem) or data.get("label") or data.get("title") or elem
    row: dict[str, Any] = {
        "time": ev.get("timestamp"),
        "event": ev.get("event"),
        "type": ev.get("element_type"),
        "element": name,
    }
    if ev.get("event") == "MODIFIED":
        row["changes"] = {
            k: {"from": prev.get(k), "to": v}
            for k, v in data.items()
            if k != "operational" and k not in ACCESS_KEYS and prev.get(k) != v
        }
    elif data.get("state"):
        row["state"] = data["state"]
    return row


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List labs")
    async def cml_list_labs(
        ctx: Context,
        title: Annotated[str | None, Field(description="Filter: title contains (case-insensitive)")] = None,
        state: Annotated[
            Literal["DEFINED_ON_CORE", "STARTED", "QUEUED", "BOOTED", "STOPPED"] | None,
            Field(description="Filter by lab state"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the labs visible to the API user: id, title, state (DEFINED_ON_CORE = never started
        or wiped, STARTED, STOPPED, ...), node and link counts, owner and last change. Start here to
        find a lab; every other lab tool accepts the title or the id."""
        app: CmlApp = get_client(ctx)
        labs = [lab_row(lab) for lab in await app.list_labs()]
        if title:
            labs = [r for r in labs if title.lower() in str(r["title"]).lower()]
        if state:
            labs = [r for r in labs if r["state"] == state]
        labs.sort(key=lambda r: str(r["title"]).lower())
        return list_result(page_of(labs, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get lab")
    async def cml_get_lab(ctx: Context, lab: LabRef) -> ToolResult:
        """Details of one lab: title, description, notes, owner, state, whether every node has
        converged (booted), node states by count, node/link counts, autostart and node-staging
        settings, and the total CPU/RAM the running nodes use. For the wiring use
        cml_get_lab_topology."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        nodes = await app.list_nodes(lid)
        converged = await app.api.get(f"/labs/{lid}/check_if_converged")
        out: dict[str, Any] = {
            "id": lid,
            "title": info.get("lab_title"),
            "description": info.get("lab_description"),
            "notes": info.get("lab_notes"),
            "owner": info.get("owner_username"),
            "state": info.get("state"),
            "converged": converged,
            "node_count": info.get("node_count"),
            "link_count": info.get("link_count"),
            "node_states": state_counts(nodes),
            "created": info.get("created"),
            "modified": info.get("modified"),
            "autostart": info.get("autostart"),
            "node_staging": info.get("node_staging"),
            "permissions": info.get("effective_permissions"),
        }
        if info.get("state") in ("STARTED", "BOOTED", "QUEUED"):
            stats = await app.api.get(f"/labs/{lid}/simulation_stats")
            running = [s for s in (stats.get("nodes") or {}).values() if s.get("is_running")]
            out["running_nodes"] = len(running)
            out["allocated_cpus"] = sum(s.get("cpus") or 0 for s in running)
            out["allocated_ram_mb"] = sum(s.get("ram") or 0 for s in running)
        return shaped({k: v for k, v in out.items() if v not in (None, "")})

    @reg.read(title="Lab topology")
    async def cml_get_lab_topology(
        ctx: Context,
        lab: LabRef,
        detail: Annotated[
            Literal["summary", "full"],
            Field(
                description="'summary': nodes with state and who each interface connects to, links with "
                "conditioning (compact; start here). 'full': every node/interface/link field."
            ),
        ] = "summary",
        include_configs: Annotated[
            bool, Field(description="With detail='full': include each node's day-0 configuration")
        ] = False,
    ) -> ToolResult:
        """The wiring of a lab. The summary lists every node (label, definition, state, interface ->
        peer 'node:interface', free physical interfaces) and every link ('r1:Ethernet0/0' <->
        'r2:Ethernet0/0', state, link conditioning such as latency/loss). Use detail='full' for all
        fields (positions, RAM/CPU, image, MACs), optionally with configs."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        if detail == "full":
            topo = await app.api.get(
                f"/labs/{lid}/topology", {"exclude_configurations": "false" if include_configs else "true"}
            )
            return shaped(drop_keys(topo))
        topo_data = await app.api.get(f"/labs/{lid}/topology", {"exclude_configurations": "true"})
        conditions = {
            lk["id"]: {k: v for k, v in (lk.get("conditioning") or {}).items() if v not in (None, False)}
            for lk in topo_data.get("links") or []
            if (lk.get("conditioning") or {}).get("enabled")
        }
        topo = await load_topo(app, lid)
        return shaped(topology_summary(info, topo, conditions))

    @reg.read(title="Export lab YAML")
    async def cml_export_lab(
        ctx: Context,
        lab: LabRef,
        include_credentials: Annotated[
            bool, Field(description="Keep pyATS passwords stored on nodes (masked by default)")
        ] = False,
    ) -> ToolResult:
        """Export a lab as CML topology YAML (the same file the UI downloads): lab metadata, nodes with
        their day-0 configurations, interfaces, links and annotations. The YAML can be re-imported
        with cml_import_lab, kept as a baseline for cml_diff_lab, or edited to build a new lab.
        Running configs are only included after cml_extract_node_configs. Secrets inside device
        configs (enable secret, keys) are NOT masked."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        text = await app.api.get(f"/labs/{info['id']}/download", expect="text")
        return text_result(text if include_credentials else mask_export(text))

    @reg.read(title="List lab events")
    async def cml_list_lab_events(
        ctx: Context,
        lab: LabRef,
        element_type: Annotated[
            Literal["Lab", "Node", "Interface", "Link"] | None,
            Field(description="Only events for this kind of element"),
        ] = None,
        event: Annotated[
            str | None, Field(description="Only this event type, e.g. CREATED, MODIFIED, DELETED, state")
        ] = None,
        element: Annotated[
            str | None, Field(description="Only events for this node label or element id")
        ] = None,
        include_empty_state: Annotated[
            bool, Field(description="Include 'state' events that carry no data (noisy)")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The lab's change and state history, newest first: element created/modified/deleted (with
        the fields that changed) and state transitions (STARTED, BOOTED, STOPPED...). Use it to see
        what changed in a lab and when, or why a node restarted."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        lid = info["id"]
        events: list[dict[str, Any]] = await app.api.get(f"/labs/{lid}/events") or []
        topo = await load_topo(app, lid)
        names = {nid: topo.node_label(nid) for nid in topo.nodes}
        names.update({iid: topo.endpoint(iid) for iid in topo.interfaces})
        names.update(
            {
                lk["id"]: f"{topo.endpoint(lk.get('interface_a'))}<->{topo.endpoint(lk.get('interface_b'))}"
                for lk in topo.links
            }
        )
        names[lid] = info.get("lab_title") or lid
        rows = []
        for ev in reversed(events):
            if element_type and ev.get("element_type") != element_type:
                continue
            if event and str(ev.get("event")).lower() != event.lower():
                continue
            if element:
                elem_name = names.get(ev.get("element_id") or "", "")
                if (
                    element != ev.get("element_id")
                    and element != elem_name
                    and not elem_name.startswith(element + ":")
                ):
                    continue
            if not include_empty_state and ev.get("event") == "state" and not ev.get("data"):
                continue
            rows.append(event_row(ev, names))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="pyATS testbed")
    async def cml_get_pyats_testbed(
        ctx: Context,
        lab: LabRef,
        include_credentials: Annotated[
            bool, Field(description="Keep device passwords in the YAML (masked by default)")
        ] = False,
    ) -> ToolResult:
        """The pyATS/Genie testbed YAML CML generates for a lab: one device per node, reached through
        the CML console server ('open /lab/node/0' over SSH), with OS/platform and default device
        credentials. Fill in the terminal_server credentials (your CML user) to use it with pyATS."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab)
        text = await app.api.get(f"/labs/{info['id']}/pyats_testbed", expect="text")
        return text_result(text if include_credentials else mask_testbed(text))
