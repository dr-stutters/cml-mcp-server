"""cml_build_recipe(extend=true) (#67): grow an existing recipe lab in place into a superset recipe.

Only what the lab is missing is added - nodes (with their day-0 and interfaces), links and the recipe's
text annotations - and the lab's recipe marker is rewritten, so cml_verify_recipe and cml_run_recipe_action
treat it as the new recipe's lab. Existing nodes are never changed: a node with the same label but another
definition, or a link end already used by another link, blocks the preview.
"""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from collections import Counter
from typing import Any

from fastmcp import Context

from cml_mcp._core import InvalidRequest, Plan, UpstreamError, get_client, get_settings
from cml_mcp.build import UNLICENSED_DEFINITIONS, BuildError, NodeSpec, build_topology
from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.licence import (
    compact_usage,
    explain_licence_error,
    licence_blocker,
    licence_usage,
    nodes_ram_mb,
    ram_check,
    ram_headroom,
)
from cml_mcp.recipes import base_relation, read_recipe_marker, redact_values, set_recipe_marker
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.safety import lab_blockers
from cml_mcp.tools.build_tool import assign_cat9kv_serials
from cml_mcp.tools.common import load_topo
from cml_mcp.tools.lab_writes import known_definitions
from cml_mcp.tools.topology_writes import WIPE_HINT, late_link_warning
from cml_mcp.topology import MCP_Z

# What a new node takes from the built topology (the rest - ids, interfaces - is created separately)
NODE_FIELDS = (
    "label",
    "node_definition",
    "x",
    "y",
    "tags",
    "configuration",
    "pyats",
    "parameters",
    "ram",
    "cpus",
    "priority",
)


def _ends(
    lk: dict[str, Any], topo_ifaces: dict[str, dict[str, Any]], labels: dict[str, str]
) -> frozenset[Any]:
    a, b = topo_ifaces.get(lk.get("interface_a") or ""), topo_ifaces.get(lk.get("interface_b") or "")
    return frozenset(
        (labels.get(str((i or {}).get("node")), "?"), str((i or {}).get("label"))) for i in (a, b)
    )


async def extend_lab_flow(
    ctx: Context,
    *,
    tool_args: dict[str, Any],
    recipe: str,
    title: str,
    nodes: list[NodeSpec],
    links: list[str],
    annotations: list[dict[str, Any]],
    substitute: dict[str, str] | None,
    start: bool,
    wait: bool,
    timeout: float | None,  # noqa: ASYNC109 - overall wait, handled by poll_until
    confirm: str | None,
    redact: dict[str, str],
    blockers: list[str] | None = None,
) -> dict[str, Any]:
    app: CmlApp = get_client(ctx)
    labs = [lab for lab in await app.list_labs() if lab.get("lab_title") == title]
    if len(labs) != 1:
        raise InvalidRequest(
            (f"No lab titled {title!r}" if not labs else f"{len(labs)} labs are titled {title!r}")
            + ": extend=true grows one existing lab; build the recipe without extend to create it"
        )
    info = labs[0]
    lid = str(info["id"])
    notes = (
        info.get("lab_notes") if "lab_notes" in info else (await app.api.get(f"/labs/{lid}")).get("lab_notes")
    )
    marker = read_recipe_marker(notes)
    blockers = list(blockers or [])
    # the rails resolve a lab from `lab`, which a recipe build has none of: an extend changes this lab
    blockers += await lab_blockers(ctx, "cml_build_recipe", tool_args, info)
    side_effects: list[str] = []
    relation = base_relation(recipe, marker["recipe"]) if marker else None
    if marker and relation is None:
        blockers.append(
            f"Lab {title!r} was built from recipe {marker['recipe']!r}, which recipe {recipe!r} neither "
            "extends nor contains (every node of it, same definitions): extend only grows a lab into a "
            "superset recipe"
        )
    if marker and (marker["substitute"] or {}) != (substitute or {}):
        blockers.append(
            f"Lab {title!r} was built with substitute {marker['substitute'] or {}}; pass the same "
            "`substitute` so the added nodes use the lab's addresses"
        )
    if not marker:
        side_effects.append(
            f"Lab {title!r} has no record of the recipe it was built from: its nodes are matched by label"
        )

    defs = await known_definitions(app)
    nodes, serials = await assign_cat9kv_serials(app, title, nodes)
    connectors = None
    if any(n.definition == "external_connector" for n in nodes):
        connectors = await app.api.get("/system/external_connectors")
    remarks: list[str] = []
    try:
        target, _wiring = build_topology(title, nodes, links, defs, connectors=connectors, notes=remarks)
    except BuildError as e:
        blockers.append(str(e))
        target = {"nodes": [], "links": []}

    topo = await load_topo(app, lid)
    labels = {nid: str(n.get("label")) for nid, n in topo.nodes.items()}
    existing = {str(n.get("label")): n for n in topo.nodes.values()}
    peers = topo.peers()
    spec = {n.label: n for n in nodes}

    # nodes: new ones are added whole; existing ones must be the same definition and are left as they are
    new_nodes: list[dict[str, Any]] = []
    differences: list[str] = []
    for tn in target["nodes"]:
        label = tn["label"]
        have = existing.get(label)
        if have is None:
            new_nodes.append(tn)
            continue
        if have.get("node_definition") != tn["node_definition"]:
            blockers.append(
                f"Node {label!r} is a {have.get('node_definition')} in the lab but a "
                f"{tn['node_definition']} in recipe {recipe!r}: extend never replaces a node"
            )
            continue
        for key in ("ram", "cpus"):
            want = getattr(spec[label], key)
            if want and have.get(key) != want:
                differences.append(f"{label} {key} {have.get(key) or 'default'} -> {want}")
    new_labels = {n["label"] for n in new_nodes}

    # links: one already there (same ends, or the same two nodes on other interfaces) is kept as it is
    t_ifaces = {(tn["id"], i["id"]): (tn["label"], i) for tn in target["nodes"] for i in tn["interfaces"]}
    wanted = [(t_ifaces[(lk["n1"], lk["i1"])], t_ifaces[(lk["n2"], lk["i2"])]) for lk in target["links"]]
    have_ends = {_ends(lk, topo.interfaces, labels) for lk in topo.links}
    pairs = Counter(frozenset(e[0] for e in _ends(lk, topo.interfaces, labels)) for lk in topo.links)
    missing: list[tuple[tuple[str, dict[str, Any]], tuple[str, dict[str, Any]]]] = []
    exact: set[int] = set()
    for idx, ((a, ia), (b, ib)) in enumerate(wanted):
        if frozenset({(a, ia["label"]), (b, ib["label"])}) in have_ends:
            exact.add(idx)
            pairs[frozenset({a, b})] -= 1
    kept_elsewhere: list[str] = []
    for idx, ((a, ia), (b, ib)) in enumerate(wanted):
        if idx in exact:
            continue
        if pairs[frozenset({a, b})] > 0:
            pairs[frozenset({a, b})] -= 1
            kept_elsewhere.append(f"{a}<->{b}")
            continue
        missing.append(((a, ia), (b, ib)))
    if kept_elsewhere:
        side_effects.append(
            "Already linked on other interfaces than the recipe allocates (kept): "
            + ", ".join(kept_elsewhere)
        )

    # link ends on existing nodes: a free interface of that name, or a new one on a wiped node
    new_ifaces: dict[str, list[dict[str, Any]]] = {}  # existing node label -> interfaces to create
    add_links: list[str] = []
    for (a, ia), (b, ib) in missing:
        add_links.append(f"{a}:{ia['label']}<->{b}:{ib['label']}")
        for label, iface in ((a, ia), (b, ib)):
            if label in new_labels:
                continue
            node = existing[label]
            found = next(
                (
                    i
                    for i in topo.interfaces.values()
                    if i.get("node") == node["id"] and i.get("label") == iface["label"]
                ),
                None,
            )
            if found is not None and found["id"] in peers:
                blockers.append(
                    f"{label}:{iface['label']} is already connected to {peers[found['id']][0]}; recipe "
                    f"{recipe!r} links it to {b if label == a else a}"
                )
            elif found is None:
                if node.get("state") != "DEFINED_ON_CORE":
                    blockers.append(
                        f"{label} has no {iface['label']} and is {node.get('state')}; {WIPE_HINT}"
                    )
                else:
                    new_ifaces.setdefault(label, []).append(iface)
            if warning := late_link_warning(node, found):
                side_effects.append(warning)

    # annotations: the recipe's text boxes the lab lacks are added; this server's boxes the recipe no longer
    # has (the base recipe's purpose, an edge's old address list) are removed; hand-drawn ones stay
    current: list[dict[str, Any]] = await app.api.get(f"/labs/{lid}/annotations") or []
    texts = {a.get("text_content") for a in current if a.get("type") == "text"}
    wanted_texts = {a.get("text_content") for a in annotations}
    add_notes = [a for a in annotations if a.get("text_content") not in texts]
    drop_notes = [
        a
        for a in current
        if a.get("z_index") == MCP_Z and a.get("type") == "text" and a.get("text_content") not in wanted_texts
    ]
    new_notes_text = set_recipe_marker(notes, recipe, substitute)
    marker_changes = not marker or marker["recipe"] != recipe
    if not (new_nodes or missing or add_notes or drop_notes or marker_changes) and not blockers:
        blockers.append(
            f"Lab {title!r} already has every node, link and note of recipe {recipe!r}: nothing to add"
        )

    licensed = [n for n in new_nodes if n["node_definition"] not in UNLICENSED_DEFINITIONS]
    licences: dict[str, Any] | None = None
    memory: dict[str, Any] | None = None
    if start and new_nodes:
        licences = await licence_usage(app)
        if problem := licence_blocker(licences, len(licensed)):
            blockers.append(problem)
        else:
            licences = compact_usage(licences)
        specs = [{"node_definition": n["node_definition"], "ram": n.get("ram")} for n in new_nodes]
        memory = ram_check(await ram_headroom(app), nodes_ram_mb(specs, defs))
        if memory and memory.get("warning"):
            side_effects.append(memory["warning"])
    if differences:
        side_effects.append(
            "Existing nodes are left as they are; these differ from the recipe and need a stop, wipe and "
            "cml_update_node to match: " + "; ".join(differences)
        )

    plan = Plan(
        f"Extend lab {title!r} to recipe {recipe!r}: add {len(new_nodes)} nodes, {len(missing)} links"
        + (", then start the new nodes" if start and new_nodes else ""),
        details={
            "built_from": ({"recipe": marker["recipe"], "relation": relation} if marker else "not recorded"),
            "add_nodes": {n["label"]: n["node_definition"] for n in new_nodes},
            "add_links": add_links,
            **(
                {"new_interfaces": {k: [i["label"] for i in v] for k, v in new_ifaces.items()}}
                if new_ifaces
                else {}
            ),
            "annotations": {"add": len(add_notes), "remove": len(drop_notes)},
            "unchanged": {
                "nodes": len(target["nodes"]) - len(new_nodes),
                "links": len(wanted) - len(missing),
            },
            "marker": {"recipe": recipe, "substitute": substitute or {}},
            "start": start,
            "licensed_nodes_added": len(licensed),
            **({"licences": licences} if licences else {}),
            **({"ram": memory} if memory else {}),
            **(
                {"cat9000v_serials": {k: v for k, v in serials.items() if k in new_labels}} if serials else {}
            ),
            **({"notes": remarks} if remarks else {}),
        },
        fingerprint={
            "nodes": sorted((str(n.get("label")), str(n.get("state"))) for n in topo.nodes.values()),
            "links": sorted(str(lk.get("id")) for lk in topo.links),
            "annotations": sorted(str(a.get("id")) for a in current),
        },
        blockers=redact_values(blockers, redact),
        blast_radius=len(new_nodes) + len(missing),
        side_effects=redact_values(side_effects, redact),
    )
    limit = timeout or get_settings(ctx).wait_timeout

    async def apply() -> Any:
        try:
            return redact_values(await apply_extend(), redact)
        except UpstreamError as e:
            raise UpstreamError(redact_values(str(e), redact), e.status_code) from None
        except InvalidRequest as e:
            raise InvalidRequest(redact_values(str(e), redact)) from None

    async def make_interfaces(node_id: str, wanted_ifaces: list[dict[str, Any]], have: set[int]) -> None:
        """Create each physical interface's slot the node lacks (CML may create the slots before it too)."""
        for iface in sorted(wanted_ifaces, key=lambda i: i.get("slot") or 0):
            if iface.get("type") != "physical" or iface.get("slot") in have:
                continue
            body: dict[str, Any] = {"node": node_id, "slot": iface["slot"]}
            if iface.get("mac_address"):
                body["mac_address"] = iface["mac_address"]
            res = await app.api.post(f"/labs/{lid}/interfaces", body)
            for made in res if isinstance(res, list) else [res]:
                if isinstance(made, dict) and made.get("slot") is not None:
                    have.add(int(made["slot"]))
            have.add(int(iface["slot"]))

    async def apply_extend() -> Any:
        done: dict[str, Any] = {"nodes": {}, "links": []}
        try:
            for tn in new_nodes:
                body = {k: tn[k] for k in NODE_FIELDS if tn.get(k) not in (None, [], {})}
                if tn.get("image_definition"):
                    body["image_definition"] = tn["image_definition"]
                res = await app.api.post(f"/labs/{lid}/nodes", body, params={"populate_interfaces": "true"})
                done["nodes"][tn["label"]] = str(res["id"])
            ifaces = await app.list_interfaces(lid, operational=False)
            slots: dict[str, set[int]] = {}
            for i in ifaces:
                if i.get("type") == "physical" and i.get("slot") is not None:
                    slots.setdefault(str(i.get("node")), set()).add(int(i["slot"]))
            for tn in new_nodes:
                nid = done["nodes"][tn["label"]]
                await make_interfaces(nid, tn["interfaces"], slots.setdefault(nid, set()))
            for label, wanted_ifaces in new_ifaces.items():
                nid = str(existing[label]["id"])
                await make_interfaces(nid, wanted_ifaces, slots.setdefault(nid, set()))
            ids = {
                (str(i.get("node")), str(i.get("label"))): str(i["id"])
                for i in await app.list_interfaces(lid, operational=False)
            }
            node_ids = {**{k: str(v["id"]) for k, v in existing.items()}, **done["nodes"]}
            for (a, ia), (b, ib) in missing:
                src, dst = ids.get((node_ids[a], ia["label"])), ids.get((node_ids[b], ib["label"]))
                if not src or not dst:
                    raise InvalidRequest(
                        f"CML created no interface {a}:{ia['label']} or {b}:{ib['label']} for the link"
                    )
                await app.api.post(f"/labs/{lid}/links", {"src_int": src, "dst_int": dst})
                done["links"].append(f"{a}:{ia['label']}<->{b}:{ib['label']}")
            for note in add_notes:
                await app.api.post(f"/labs/{lid}/annotations", note)
            for note in drop_notes:
                await app.api.delete(f"/labs/{lid}/annotations/{note['id']}")
            await app.api.patch(f"/labs/{lid}", {"notes": new_notes_text})
        except (UpstreamError, InvalidRequest) as e:
            progress = (
                f"Extending {title!r} stopped after adding nodes {sorted(done['nodes']) or 'none'} and "
                f"{len(done['links'])} links ({e}). Run cml_build_recipe(extend=true) again: it adds only "
                "what is still missing"
            )
            if isinstance(e, UpstreamError):
                raise UpstreamError(progress, e.status_code) from None
            raise InvalidRequest(progress) from None
        out: dict[str, Any] = {
            "lab": title,
            "recipe": recipe,
            "added_nodes": done["nodes"],
            "added_links": done["links"],
            "annotations": {"added": len(add_notes), "removed": len(drop_notes)},
            "marker": recipe,
        }
        if start and done["nodes"]:
            for label, nid in done["nodes"].items():
                try:
                    await app.api.put(f"/labs/{lid}/nodes/{nid}/state/start")
                except UpstreamError as e:
                    raise await explain_licence_error(
                        app, e, f"Lab {title!r} was extended but node {label!r} did not start"
                    ) from e
            if wait:
                out["convergence"] = await wait_converged(app, lid, timeout=limit, ctx=ctx)
            else:
                out["started"] = sorted(done["nodes"])
                out["next"] = "cml_wait_for_converged, then cml_verify_recipe"
        return out

    return await preview_or_apply(
        ctx, tool="cml_build_recipe", args=tool_args, confirm=confirm, plan=plan, apply=apply
    )
