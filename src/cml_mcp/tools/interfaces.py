"""Interface write tools (L52): one-sided up/down and MAC pinning.

`cml_set_link_state` drops both ends of a link; `cml_set_interface_state` stops one interface so only that
side loses carrier (an FTD HA monitored interface, an SD-WAN dead-WAN test) while the peer keeps it.
`cml_update_interface` pins an interface MAC so ISE MAB endpoints and DHCP bindings survive a wipe or a
re-import.
"""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from cml_mcp._core import Confirm, NotFound, Plan, ToolRegistrar, UpstreamError, get_client
from cml_mcp.client import CmlApp
from cml_mcp.extract import full_definition
from cml_mcp.macs import custom_mac_problem, mac_problem, normalise_mac
from cml_mcp.safety import guarded_preview_or_apply as preview_or_apply
from cml_mcp.tools.common import LabRef, NodeRef, load_topo
from cml_mcp.tools.topology_writes import WIPE_HINT

InterfaceRef = Annotated[
    str, Field(description="Interface label on that node, e.g. Ethernet0/1 or GigabitEthernet2, or its id")
]
RUNNING_NODE = ("STARTED", "BOOTED")


def interface_mac(iface: dict[str, Any]) -> str | None:
    """The MAC the interface has: the pinned one, else the one CML assigned when the node started."""
    return iface.get("mac_address") or (iface.get("operational") or {}).get("mac_address") or None


async def resolve_interface(
    app: CmlApp, lab_id: str, node: dict[str, Any], ref: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(the node's interface named by label or id, every interface in the lab)."""
    ref = ref.strip()
    ifaces = await app.list_interfaces(lab_id, operational=True)
    own = [i for i in ifaces if i.get("node") == node["id"]]
    hit = [i for i in own if i.get("id") == ref] or [
        i for i in own if str(i.get("label") or "").lower() == ref.lower()
    ]
    if not hit:
        names = ", ".join(str(i.get("label")) for i in own[:8]) + ("..." if len(own) > 8 else "")
        raise NotFound(
            f"{node.get('label')} has no interface {ref!r} (interfaces: {names or 'none'}; see "
            "cml_list_interfaces)."
        )
    return hit[0], ifaces


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Set interface state")
    async def cml_set_interface_state(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        interface: InterfaceRef,
        state: Annotated[
            Literal["up", "down"],
            Field(description="'down' takes carrier away from this end only; the peer stays up"),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Bring ONE interface down or back up on a running node (a one-sided failure: this end loses
        carrier, the peer end of the link keeps it), e.g. an FTD HA monitored interface or an SD-WAN
        dead-WAN test. cml_set_link_state drops both ends instead. The preview names the peer."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        iface, _ = await resolve_interface(app, lid, n, interface)
        topo = await load_topo(app, lid)
        name = f"{n.get('label')}:{iface.get('label')}"
        peer = topo.peers().get(iface["id"])
        current = iface.get("state")
        blockers: list[str] = []
        if iface.get("type") == "loopback":
            blockers.append(f"{name} is a loopback; only physical interfaces can go up/down")
        if n.get("state") not in RUNNING_NODE:
            blockers.append(
                f"Node {n.get('label')} is {n.get('state')}; interfaces only go up/down on a running node "
                "(start it with cml_set_node_state)"
            )
        elif current not in ("STARTED", "STOPPED"):
            blockers.append(f"Interface {name} is {current}; it can only go up/down once the node runs")
        side_effects: list[str] = []
        if peer:
            if state == "down":
                side_effects.append(
                    f"Only {name} loses carrier; the peer {peer[0]} stays up (use cml_set_link_state to "
                    "drop both ends). Bring it back with state='up'"
                )
        else:
            side_effects.append(f"{name} is not wired to anything, so no traffic is affected")
        if (state == "up") == (current == "STARTED"):
            side_effects.append(f"{name} is already {state}; nothing changes")
        plan = Plan(
            f"Bring interface {name} {state} (currently {current})",
            details={"interface": name, "from": current, "peer": peer[0] if peer else None},
            fingerprint={"iface": current, "node": n.get("state")},
            blockers=blockers,
            side_effects=side_effects,
        )

        async def apply() -> Any:
            verb = "start" if state == "up" else "stop"
            await app.api.put(f"/labs/{lid}/interfaces/{iface['id']}/state/{verb}")
            fresh = await app.api.get(f"/labs/{lid}/interfaces/{iface['id']}")
            return {"interface": name, "state": (fresh or {}).get("state"), "peer": peer[0] if peer else None}

        return await preview_or_apply(
            ctx,
            tool="cml_set_interface_state",
            args={"lab": lab, "node": node, "interface": interface, "state": state},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Pin interface MAC")
    async def cml_update_interface(
        ctx: Context,
        lab: LabRef,
        node: NodeRef,
        interface: InterfaceRef,
        mac_address: Annotated[
            str,
            Field(
                description="MAC to pin, in 52:54:00:xx:xx:xx (any of ':', '-', '.' separators), or 'auto' "
                "to clear the pin and let CML assign one"
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Pin an interface's MAC address so it survives wipes, re-imports and rebuilds (ISE MAB
        endpoints, DHCP reservations and Catalyst Center PnP bindings key on it), or clear the pin
        ('auto'). The preview names the old MAC and what references it. MACs must be in CML's
        52:54:00 block or the lab can no longer be imported. CML takes the change only on a wiped node
        (DEFINED_ON_CORE) of a definition that allows custom MACs (KVM or Docker; not IOL); the
        preview blocks otherwise. Interface labels are fixed by the node definition and cannot be
        changed."""
        app: CmlApp = get_client(ctx)
        info = await app.resolve_lab(lab, exact=True)
        lid = info["id"]
        n = await app.resolve_node(lid, node, exact=True)
        iface, ifaces = await resolve_interface(app, lid, n, interface)
        topo = await load_topo(app, lid)
        name = f"{n.get('label')}:{iface.get('label')}"
        old = interface_mac(iface)
        blockers: list[str] = []
        new: str | None = None
        if mac_address.strip().lower() != "auto":
            problem = mac_problem(mac_address)
            if problem:
                blockers.append(problem)
            else:
                new = normalise_mac(mac_address)
                clash = [
                    topo.endpoint(i["id"])
                    for i in ifaces
                    if i["id"] != iface["id"] and (interface_mac(i) or "").lower() == new
                ]
                if clash:
                    blockers.append(f"MAC {new} is already used in this lab by {', '.join(clash)}")
        if iface.get("type") == "loopback":
            blockers.append(f"{name} is a loopback; it has no MAC to pin")
        definition = str(n.get("node_definition") or "")
        if (
            new is not None
            and definition
            and (why := custom_mac_problem(definition, await full_definition(app, definition)))
        ):
            blockers.append(f"{n.get('label')}: {why}")
        if n.get("state") != "DEFINED_ON_CORE":
            # live, CML 2.10: PATCH on a BOOTED node -> 400 'Physical configuration of node is locked'
            blockers.append(f"Node {n.get('label')} is {n.get('state')}; {WIPE_HINT}")
        side_effects: list[str] = []
        if old and (old.lower() != (new or "")):
            side_effects.append(
                f"Anything keyed on the old MAC {old} stops matching: ISE endpoints (MAB, endpoint "
                "groups, ANC), DHCP reservations and leases, Catalyst Center PnP claims. Update or "
                "re-learn them (e.g. ise_list_endpoints, the DHCP server's bindings)"
            )
        if new is None and not iface.get("mac_address"):
            side_effects.append(f"{name} has no pinned MAC; nothing changes")
        plan = Plan(
            f"Set the MAC of {name} to {new or 'auto (CML assigns one)'} (currently {old or 'none'})",
            details={
                "interface": name,
                "old_mac": old,
                "pinned": iface.get("mac_address"),
                "new_mac": new,
                "node_state": n.get("state"),
            },
            fingerprint={"mac": iface.get("mac_address"), "node": n.get("state")},
            blockers=blockers,
            side_effects=side_effects,
        )

        async def apply() -> Any:
            try:
                res = await app.api.patch(f"/labs/{lid}/interfaces/{iface['id']}", {"mac_address": new})
            except UpstreamError as e:
                if n.get("state") != "DEFINED_ON_CORE" and e.status_code in (400, 403, 409, 422):
                    raise UpstreamError(f"{e} ({WIPE_HINT})", e.status_code) from e
                raise
            fresh = res if isinstance(res, dict) and "mac_address" in res else None
            if fresh is None:
                fresh = await app.api.get(f"/labs/{lid}/interfaces/{iface['id']}") or {}
            return {"interface": name, "old_mac": old, "mac_address": fresh.get("mac_address")}

        return await preview_or_apply(
            ctx,
            tool="cml_update_interface",
            args={"lab": lab, "node": node, "interface": interface, "mac_address": mac_address},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
