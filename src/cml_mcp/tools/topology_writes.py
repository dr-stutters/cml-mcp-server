"""Node and link write tools: add/update nodes, configs, node state, wiring, conditioning, captures."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import contextlib
import difflib
import secrets
import time
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from cml_mcp._core import (
    Confirm,
    FromResult,
    Plan,
    ToolRegistrar,
    Undo,
    UpstreamError,
    field_changes,
    get_client,
    get_settings,
    poll_until,
)
from cml_mcp.build import PRIORITY_MAX, PRIORITY_MIN, is_placeholder
from cml_mcp.client import CmlApp
from cml_mcp.convergence import wait_converged
from cml_mcp.extract import full_definition
from cml_mcp.licence import explain_licence_error, licence_blocker, licence_usage, licensed
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.scenarios import condition_changes
from cml_mcp.tools.common import LabRef, LinkRef, NodeRef, config_text, load_topo
from cml_mcp.tools.lab_writes import Wait, known_definitions
from cml_mcp.tools.smart import Timeout
from cml_mcp.undo import condition_undo, replayable

RUNNING = ("STARTED", "QUEUED", "BOOTED")
WIPE_HINT = (
    "CML only accepts this change while the node is wiped (DEFINED_ON_CORE): stop it "
    "(cml_set_node_state), wipe it (cml_wipe_node, dangerous tier), change it, then start it again"
)


FTD_LINK_WARNING = (
    "this link stays down until the node is wiped (cml_wipe_node; day-0 survives): {node} has booted "
    "before, and FTDv only binds the NICs of links that existed at its first boot (stop/start or a link "
    "bounce leave the interface STOPPED). Create FTD links before the first boot"
)


def is_ftd(node: dict[str, Any]) -> bool:
    """FTDv-family node definitions (ftdv and its variants)."""
    return str(node.get("node_definition") or "").lower().startswith("ftd")


CAT9K_LINK_WARNING = (
    "{node} only uses links that exist at boot: stop and start the node after connecting, or connect "
    "while it is stopped (a Catalyst 9000v binds its data-plane NICs at boot, so a link hot-added to "
    "the running node shows STARTED but carries no frames; a link bounce does not help)"
)


def is_cat9k(node: dict[str, Any]) -> bool:
    """Catalyst 9000v node definitions (cat9000v-uadp, cat9000v-q200, cat9kv-*)."""
    return str(node.get("node_definition") or "").lower().startswith(("cat9000v", "cat9kv"))


def boot_bound_link_warning(node: dict[str, Any]) -> str | None:
    """A warning when a link added now is dead until the node restarts: a running (STARTED/BOOTED)
    Catalyst 9000v (#97). Stopped or wiped nodes pick the link up at their next boot."""
    if not is_cat9k(node) or node.get("state") not in ("STARTED", "BOOTED"):
        return None
    return CAT9K_LINK_WARNING.format(node=repr(node.get("label")))


def late_link_warning(node: dict[str, Any], iface: dict[str, Any] | None) -> str | None:
    """A warning when a new link on this node will not carry traffic: an FTDv that has booted before
    (not DEFINED_ON_CORE) and an interface that is new or not running now (never STARTED), or a running
    Catalyst 9000v (boot_bound_link_warning)."""
    if (warning := boot_bound_link_warning(node)) is not None:
        return warning
    if not is_ftd(node) or node.get("state") == "DEFINED_ON_CORE":
        return None
    if iface is not None and iface.get("state") == "STARTED":
        return None
    return FTD_LINK_WARNING.format(node=repr(node.get("label")))


class PortReservations:
    """Interfaces held for pending cml_connect_nodes previews (#69), so parallel previews to one switch
    (an unmanaged switch has many identical free ports) get different ports. Keyed by interface id;
    each hold names the preview token that owns it and expires with that token."""

    def __init__(self) -> None:
        self._held: dict[str, tuple[str, float]] = {}  # interface id -> (owner key, expiry)

    def _purge(self) -> None:
        now = time.monotonic()
        for iface in [i for i, (_, exp) in self._held.items() if exp < now]:
            del self._held[iface]

    def held_by_others(self, owner: str | None) -> set[str]:
        self._purge()
        return {i for i, (o, _) in self._held.items() if o != owner}

    def held_by(self, owner: str | None) -> set[str]:
        self._purge()
        return {i for i, (o, _) in self._held.items() if owner is not None and o == owner}

    def hold(self, owner: str, ifaces: list[str], ttl: float) -> None:
        self._purge()
        for iface in ifaces:
            self._held[iface] = (owner, time.monotonic() + ttl)

    def rekey(self, old: str, new: str) -> None:
        for iface, (o, exp) in list(self._held.items()):
            if o == old:
                self._held[iface] = (new, exp)

    def release(self, owner: str) -> None:
        for iface in [i for i, (o, _) in self._held.items() if o == owner]:
            del self._held[iface]


def port_reservations(ctx: Context) -> PortReservations:
    state = ctx.lifespan_context
    res = state.get("port_reservations")
    if res is None:
        res = state["port_reservations"] = PortReservations()
    return res


NODE_FINGERPRINT = (
    "state",
    "label",
    "tags",
    "ram",
    "cpus",
    "cpu_limit",
    "data_volume",
    "boot_disk_size",
    "parameters",
    "x",
    "y",
    "node_definition",
)
# NodeUpdate fields CML only takes on a wiped node (DEFINED_ON_CORE); node parameters too
WIPED_FIELDS = frozenset({"ram", "cpus", "cpu_limit", "data_volume", "boot_disk_size"})


def node_fingerprint(node: dict[str, Any]) -> Any:
    return {k: node.get(k) for k in NODE_FINGERPRINT}


def merged_parameters(current: dict[str, Any] | None, update: dict[str, Any] | None) -> dict[str, Any] | None:
    """The node's parameters after `update` (None values remove a key); None when nothing was given.
    CML replaces the whole parameters object on PATCH, so the other keys are sent back unchanged."""
    if update is None:
        return None
    merged = {**(current or {}), **{k: v for k, v in update.items() if v is not None}}
    for k, v in update.items():
        if v is None:
            merged.pop(k, None)
    return merged


def parameter_changes(current: dict[str, Any] | None, new: dict[str, Any] | None) -> dict[str, Any]:
    """{'parameters.<key>': {from, to}} per key that changes (removed keys carry removed=True)."""
    if new is None:
        return {}
    cur = current or {}
    out: dict[str, Any] = {}
    for k in sorted(cur.keys() | new.keys()):
        if k not in new:
            out[f"parameters.{k}"] = {"from": cur[k], "to": None, "removed": True}
        elif k not in cur or cur[k] != new[k]:
            out[f"parameters.{k}"] = {"from": cur.get(k), "to": new[k]}
    return out


def disk_warnings(node: dict[str, Any], changes: dict[str, Any]) -> list[str]:
    """Warnings for disk changes: a boot disk below the size the node runs with now (the image may not
    fit) and a data volume removed or shrunk (its contents go with the wipe anyway, the image may need it)."""
    out = []
    running = node.get("operational") or {}
    if "boot_disk_size" in changes:
        new, now = changes["boot_disk_size"]["to"], running.get("boot_disk_size")
        if isinstance(now, int) and new < now:
            out.append(
                f"boot_disk_size {new} GB is smaller than the {now} GB the node last ran with: CML "
                "may refuse to create the disk, or the image may not boot"
            )
    if "data_volume" in changes:
        new, now = changes["data_volume"]["to"], running.get("data_volume")
        if isinstance(now, int) and new < now:
            out.append(
                f"data_volume {new} GB is smaller than the {now} GB the node last ran with: images "
                "that keep their data there (FMCv, Catalyst SD-WAN Manager) need the definition's size"
            )
    return out


def config_files(node: dict[str, Any]) -> dict[str, str]:
    """The node's day-0 files as {name: text}, in CML's order (GET /labs/{id}/nodes/{id})."""
    cfg = node.get("configuration")
    if isinstance(cfg, dict):
        cfg = [cfg]
    if not isinstance(cfg, list):
        return {}
    return {
        str(f["name"]): str(f.get("content") or "")
        for f in cfg
        if isinstance(f, dict) and f.get("name") is not None
    }


def main_file_name(files: dict[str, str], main_text: str) -> str:
    """The name of the file config_text() reads as the main one ('Main', CML's alias, when unknown)."""
    for name, text in files.items():
        if text == main_text and not name.endswith(".json"):
            return name
    return next(iter(files), "Main") if len(files) == 1 else "Main"


def update_node_undo(lid: str, node: dict[str, Any], changes: dict[str, Any]) -> Undo | str:
    """cml_update_node back to each changed field's previous value. A field that had no value (CML's
    default) can't be unset by the tool, and passwords are never repeated: those make it a text step."""
    if not changes:
        return "nothing to back out: no field changes"
    args: dict[str, Any] = {"lab": lid, "node": node["id"]}
    params: dict[str, Any] = {}
    manual: list[str] = []
    for k, ch in sorted(changes.items()):
        before = ch.get("from")
        if k.startswith("parameters."):
            params[k.removeprefix("parameters.")] = before  # None removes a key the change added
        elif k in ("login_password", "login_enable_password"):
            manual.append(f"{k} back to the old value (not shown)")
        elif before is None:
            manual.append(f"{k} had no value before (CML's default); cml_update_node can't unset it")
        else:
            args["login_username" if k == "login_username" else k] = before
    if params:
        args["parameters"] = params
    if manual or not replayable("cml_update_node", args):
        return (
            f"cml_update_node on {node.get('label')!r} with each field's previous value (the preview's "
            f"changes, 'from'); " + "; ".join(manual or ["a previous value is masked here"])
        )
    return Undo("cml_update_node", args)


def node_config_undo(
    lid: str,
    node: dict[str, Any],
    previous_main: str | None,
    existing: dict[str, str],
    changed: dict[str, str],
) -> Undo | str:
    """cml_set_node_config back to the previous day-0 text of every file this call replaces."""
    args: dict[str, Any] = {"lab": lid, "node": node["id"]}
    if previous_main is not None:
        args["configuration"] = previous_main
    if old := {name: existing[name] for name in changed if name in existing}:
        args["files"] = old
    added = sorted(name for name in changed if name not in existing)
    if len(args) == 2 and not added:
        return "nothing to back out: no day-0 file is replaced"
    label = node.get("label")
    if not replayable("cml_set_node_config", args):
        return (
            f"cml_set_node_config on {label!r} with the previous day-0 text (the '-' side of the preview "
            "diff); it holds secrets, so it is not repeated here: cml_export_lab or cml_archive_lab keeps it "
            "whole"
        )
    if added:
        return (
            f"cml_set_node_config on {label!r} with the previous day-0 text (the '-' side of the preview "
            f"diff); the new file(s) {', '.join(added)} stay: CML keeps day-0 files a call doesn't name"
        )
    return Undo("cml_set_node_config", args)


def definition_files(definition: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The provisioning files a node definition declares (name, editable, default content)."""
    prov = ((definition or {}).get("configuration") or {}).get("provisioning") or {}
    return [f for f in prov.get("files") or [] if isinstance(f, dict) and f.get("name")]


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
            undo=Undo("cml_delete_node", {"lab": lid, "node": FromResult("id")}),
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
        cpu_limit: Annotated[
            int | None,
            Field(ge=20, le=100, description="CPU limit in percent of the vCPUs (node must be wiped)"),
        ] = None,
        data_volume: Annotated[
            int | None,
            Field(ge=0, le=4096, description="Data volume (second disk) in GB, 0 = none (must be wiped)"),
        ] = None,
        boot_disk_size: Annotated[
            int | None, Field(ge=1, le=4096, description="Boot disk size in GB (node must be wiped)")
        ] = None,
        parameters: Annotated[
            dict[str, str | int | float | bool | None] | None,
            Field(
                description="Node parameters to set, merged into the current ones (e.g. "
                "{'smbios.bios.vendor': 'x'}); a null value removes that key (node must be wiped)"
            ),
        ] = None,
        login_username: Annotated[
            str | None, Field(description="Console login user (CML pyATS username) the CLI tools use")
        ] = None,
        login_password: Annotated[
            str | None, Field(description="Console login password (CML pyATS password)")
        ] = None,
        enable_password: Annotated[str | None, Field(description="Enable secret (CML pyATS)")] = None,
        priority: Annotated[
            int | None,
            Field(
                ge=PRIORITY_MIN,
                le=PRIORITY_MAX,
                description="Boot priority (0-10000, higher boots first) when the lab's node staging is on",
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a node's label, tags, position, boot priority, resources, parameters or console login.
        Label, tags, position, priority and login can change at any time; RAM, vCPUs, CPU limit, data
        volume, boot disk size and node parameters only while the node is wiped (DEFINED_ON_CORE): stop
        and wipe it first, then start it to boot with the new values (e.g. an NX-OS 9000v at 4 vCPUs and
        12288 MB, a bigger FMCv data volume). The priority orders the lab's start only with node staging on
        (cml_set_lab_boot): higher first, so controllers boot before the devices that join them. The
        login (CML's pyATS credentials) is what cml_run_commands and cml_configure_node use: update it
        after changing a device's password. The preview shows each field's old and new value
        (passwords only as 'changed'). For the configuration use cml_set_node_config."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        desired = {
            k: v
            for k, v in {
                "label": label,
                "tags": tags,
                "x": x,
                "y": y,
                "ram": ram,
                "cpus": cpus,
                "cpu_limit": cpu_limit,
                "data_volume": data_volume,
                "boot_disk_size": boot_disk_size,
                "priority": priority,
            }.items()
            if v is not None
        }
        changes = field_changes(n, desired)  # partial on purpose: the PATCH sends only these fields
        new_params = merged_parameters(n.get("parameters"), parameters)
        changes |= parameter_changes(n.get("parameters"), new_params)
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
                if desired or parameters is not None or login_username or login_password or enable_password
                else "Nothing to change: give at least one field"
            )
        wiped_only = sorted(k for k in changes if k in WIPED_FIELDS or k.startswith("parameters."))
        if wiped_only and n.get("state") != "DEFINED_ON_CORE":
            blockers.append(f"Node is {n.get('state')}; {', '.join(wiped_only)}: {WIPE_HINT}")
        side_effects = disk_warnings(n, changes)
        undo = update_node_undo(lid, n, changes)
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
            side_effects=side_effects,
            undo=undo,
        )

        async def apply() -> Any:
            body: dict[str, Any] = {k: desired[k] for k in changes if k in desired}
            if any(k.startswith("parameters.") for k in changes):
                body["parameters"] = new_params
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
                "cpu_limit": cpu_limit,
                "data_volume": data_volume,
                "boot_disk_size": boot_disk_size,
                "parameters": parameters,
                "login_username": login_username,
                "login_password": login_password,
                "enable_password": enable_password,
                "priority": priority,
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
        configuration: Annotated[
            str | None,
            Field(description="The complete new day-0 text of the main configuration file"),
        ] = None,
        files: Annotated[
            dict[str, str] | None,
            Field(
                description="Other day-0 files to set, by name, each the complete new text, e.g. "
                "{'network-config': ...} on ubuntu or {'conf/vswitch.xml': ...} on cat9000v; files not "
                "named here are kept"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Replace a node's stored day-0 configuration (what it boots with): the main file
        (`configuration`), other files by name (`files`), or both. Files not named are kept as they are.
        The preview shows a unified diff per file. CML accepts this only while the node is wiped
        (DEFINED_ON_CORE); to change a running device use its CLI. Start the node to apply."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        full = await app.api.get(f"/labs/{lid}/nodes/{n['id']}")
        current = config_text(full) or ""
        existing = config_files(full)
        main_name = main_file_name(existing, current)
        main_text = configuration
        blockers = [] if n.get("state") == "DEFINED_ON_CORE" else [f"Node is {n.get('state')}; {WIPE_HINT}"]
        extra = dict(files or {})
        if main_text is None and not extra:
            blockers.append("Nothing to change: give configuration, files or both")
        for alias in {"Main", main_name} & extra.keys():
            if main_text is not None:
                blockers.append(
                    f"files[{alias!r}] is the main configuration file: give it as configuration or in "
                    "files, not both"
                )
            else:
                main_text = extra.pop(alias)

        definition = await full_definition(app, str(n.get("node_definition") or "")) if extra else None
        known = {str(f.get("name")): f for f in definition_files(definition)}
        side_effects = []
        for name in extra:
            if known.get(name, {}).get("editable") is False:
                blockers.append(f"{name!r} is not an editable file of {n.get('node_definition')}")
            elif name not in existing and definition is not None and name not in known:
                side_effects.append(
                    f"{name!r} is not a day-0 file of {n.get('node_definition')} (its files: "
                    f"{', '.join(sorted(known)) or 'none'}): CML stores it, but the node may never read it"
                )
        diffs: dict[str, str] = {}
        if main_text is not None:
            diffs[main_name] = config_diff(current, main_text, f"{n.get('label')}:{main_name}")
        for name, text in extra.items():
            tag = f"{n.get('label')}:{name}" + ("" if name in existing else " (new file)")
            diffs[name] = config_diff(existing.get(name, ""), text, tag)
        plan = Plan(
            f"Replace day-0 file(s) {', '.join(diffs) or '(none)'} of {n.get('label')!r}",
            details={"diff": diffs[main_name] if list(diffs) == [main_name] else diffs}
            | ({"kept": kept} if (kept := sorted(set(existing) - set(diffs) - {main_name})) else {}),
            fingerprint={"state": n.get("state"), "config": full.get("configuration")},
            blockers=blockers,
            side_effects=side_effects,
            undo=node_config_undo(lid, n, current if main_text is not None else None, existing, extra),
        )

        async def apply() -> Any:
            # CML replaces the whole file array: send every file back, the named ones changed
            merged = {name: text for name, text in existing.items() if name != main_name} | extra
            body: list[dict[str, Any]] = [
                {"name": "Main", "content": current if main_text is None else main_text}
            ]
            body += [{"name": name, "content": text} for name, text in merged.items()]
            await app.api.patch(f"/labs/{lid}/nodes/{n['id']}", {"configuration": body})
            return {"id": n["id"], "files": list(diffs)} | (
                {"lines": len(main_text.splitlines())} if main_text is not None else {}
            )

        return await preview_or_apply(
            ctx,
            tool="cml_set_node_config",
            args={"lab": lab, "node": node, "configuration": configuration, "files": files},
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
            undo=f"nothing to back out: {n.get('label')!r} is already {current}"
            if noop
            else Undo(
                "cml_set_node_state",
                {"lab": lid, "node": n["id"], "state": "stop" if state == "start" else "start"},
            ),
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
        interface on each side (never an FTDv/ASAv 'donotuse' placeholder slot), adding a new interface
        when a wiped node has none free. The preview names the exact interfaces and holds a picked one
        for its token, so parallel previews to one switch get different ports; if another link took it
        before the confirm, the confirm picks the next free one and says so ('repicked'), or refuses
        when none is left. Links can be added to running nodes that have a free interface, with two
        exceptions the preview warns about: an FTDv that has booted before keeps a link added now down
        until it is wiped (cml_wipe_node; the day-0 config survives), and a running Catalyst 9000v
        (cat9000v/cat9kv) only uses links that exist at boot, so stop and start it after connecting, or
        connect while it is stopped. IOL and cat8000v pick up hot-added links."""
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

        reservations = port_reservations(ctx)
        ttl = float(get_settings(ctx).mcp_confirm_ttl)
        taken_elsewhere = reservations.held_by_others(confirm)  # held for other pending previews
        own = reservations.held_by(confirm)  # what this token's preview picked
        repicked: list[str] = []

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
                if is_placeholder(match[0].get("label")):
                    blockers.append(
                        f"{n.get('label')}:{wanted} is a placeholder slot that never carries traffic; "
                        "pick a real interface (see cml_list_interfaces)"
                    )
                if match[0].get("type") != "physical":
                    blockers.append(
                        f"{n.get('label')}:{wanted} is a {match[0].get('type')} interface; "
                        "links need physical ones"
                    )
                return match[0]["id"], str(match[0].get("label"))
            previewed = next((i for i in ifaces if i["id"] in own), None)
            if previewed is not None and previewed["id"] not in peers:
                return previewed["id"], str(previewed.get("label"))
            unlinked = [
                i
                for i in ifaces
                if i.get("type") == "physical" and i["id"] not in peers and i["id"] not in taken_elsewhere
            ]
            # FTDv/ASAv 'donotuse' slots never carry traffic: never pick one (#96).
            free = [i for i in unlinked if not is_placeholder(i.get("label"))]
            placeholders = [str(i.get("label")) for i in unlinked if is_placeholder(i.get("label"))]
            was = f"{n.get('label')}:{previewed.get('label')}" if previewed is not None else None
            if free:
                if was is not None:
                    repicked.append(
                        f"{was} was connected since the preview; used {free[0].get('label')} instead"
                    )
                return free[0]["id"], str(free[0].get("label"))
            if n.get("state") != "DEFINED_ON_CORE":
                held = " (the others are held for pending previews)" if taken_elsewhere else ""
                lead = f"{was} was connected since the preview and " if was is not None else ""
                skipped = (
                    f" (only placeholder slots are free: {', '.join(placeholders)}, "
                    "which never carry traffic)"
                    if placeholders
                    else ""
                )
                blockers.append(
                    f"{lead}{n.get('label')} has no free interface{held}{skipped} and is "
                    f"{n.get('state')}; {WIPE_HINT}"
                )
            elif was is not None:
                repicked.append(f"{was} was connected since the preview; adding a new interface instead")
            return None, "(new interface)"

        ia, name_a = choose(a, interface_a)
        ib, name_b = choose(b, interface_b)
        auto = [i for i, wanted in ((ia, interface_a), (ib, interface_b)) if i and not wanted]
        warnings = [
            w
            for n, iface_id in ((a, ia), (b, ib))
            if (w := late_link_warning(n, topo.interfaces.get(iface_id) if iface_id else None))
        ]
        details: dict[str, Any] = {"a": f"{a.get('label')}:{name_a}", "b": f"{b.get('label')}:{name_b}"}
        if auto and confirm is None:
            details["reserved"] = (
                "the picked free interface is held for this preview until it is confirmed or expires, so "
                "other cml_connect_nodes previews pick a different one"
            )
        plan = Plan(
            f"Connect {a.get('label')}:{name_a} <-> {b.get('label')}:{name_b}",
            details=details,
            # Picked interfaces are not fingerprinted: the confirm re-picks when another link took
            # the previewed one (#69). Named interfaces are, so a confirm never swaps them.
            fingerprint={
                "a": ia if interface_a else None,
                "b": ib if interface_b else None,
                "states": [a.get("state"), b.get("state")],
            },
            blockers=blockers,
            side_effects=warnings,
            undo=Undo("cml_delete_link", {"lab": lid, "link": FromResult("id")}),
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
            out: dict[str, Any] = {"id": res.get("id"), "a": fresh.endpoint(src), "b": fresh.endpoint(dst)}
            if repicked:
                out["repicked"] = repicked
            return out

        # Hold the picked ports before anything else awaits, so a parallel preview can't pick them too.
        owner = confirm if confirm is not None else "pending-" + secrets.token_hex(8)
        if auto:
            reservations.hold(owner, auto, ttl)
        try:
            result = await preview_or_apply(
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
        except BaseException:
            reservations.release(owner)
            raise
        if confirm is None and isinstance(result.get("confirm"), str):
            reservations.rekey(owner, result["confirm"])  # held until confirmed or expired
        else:
            reservations.release(owner)  # applied, blocked or dry-run: nothing left to hold
        return result

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
        changes = condition_changes(current_view, {} if clear else full)  # PATCH resets omitted ones
        plan = Plan(
            f"{'Clear conditioning on' if clear else 'Condition'} link {name}",
            details={
                "current": current_view,
                "new": {} if clear else {**body, "enabled": True},
                "changes": changes,
            },
            fingerprint=current_view,
            blockers=blockers,
            undo=condition_undo(lid, lk["id"], current_view),
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
        was = "up" if lk.get("state") == "STARTED" else "down"
        plan = Plan(
            f"Bring link {name} {state} (currently {lk.get('state')})",
            details={"link": name, "from": lk.get("state")},
            fingerprint=lk.get("state"),
            blockers=[]
            if lk.get("state") in ("STARTED", "STOPPED")
            else [f"Link is {lk.get('state')}; links can only go up/down in a started lab"],
            undo=f"nothing to back out: the link is already {state}"
            if was == state
            else Undo("cml_set_link_state", {"lab": lid, "link": lk["id"], "state": was}),
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
        plan = Plan(
            f"Start packet capture on link {lk.get('label')}",
            details=body,
            blockers=blockers,
            undo=Undo("cml_stop_capture", {"lab": lid, "link": lk["id"]}),
        )

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
            undo="nothing to restart: the packets captured so far stay readable (cml_list_capture_packets); "
            "a new cml_start_capture begins a fresh capture and replaces them",
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
