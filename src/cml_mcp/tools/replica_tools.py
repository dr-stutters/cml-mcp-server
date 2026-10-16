# ruff: noqa: E501 - the prompt text keeps its own line layout
"""Site replica (L16): cml_plan_replica (read) and the cml_replicate_site prompt."""

# No `from __future__ import annotations` in tool modules: FastMCP inspects signatures at runtime.

import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field

from cml_mcp._core import Tier, ToolRegistrar, get_client, tool_ref
from cml_mcp.client import CmlApp
from cml_mcp.licence import licence_usage
from cml_mcp.replica import plan_replica
from cml_mcp.tools.common import shaped


class Device(BaseModel):
    name: str = Field(min_length=1, max_length=128, description="Hostname as the product reports it")
    platform: str = Field(
        default="",
        max_length=128,
        description="Platform/model, e.g. 'C9300-48U', 'C8000V', 'FPR-2130', 'N9K-C93180YC-EX'",
    )
    role: str | None = Field(
        default=None, max_length=64, description="e.g. ACCESS, DISTRIBUTION, CORE, BORDER ROUTER"
    )
    management_ip: str | None = Field(default=None, max_length=64)
    family: str | None = Field(
        default=None, max_length=64, description="Catalyst Center family, e.g. 'Switches and Hubs' (fallback)"
    )


class Link(BaseModel):
    a: str = Field(min_length=1, max_length=128, description="Device name at one end")
    b: str = Field(min_length=1, max_length=128, description="Device name at the other end")


async def _available(app: CmlApp) -> set[str]:
    """Node definitions with at least one image on this controller (plus image-less built-ins)."""
    defs, images = await asyncio.gather(
        app.api.get("/simplified_node_definitions"), app.api.get("/image_definitions")
    )
    with_image = {i.get("node_definition_id") for i in images or []}
    return {
        d["id"]
        for d in defs or []
        if d.get("id") in with_image or d.get("id") in ("unmanaged_switch", "external_connector")
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Plan a site replica")
    async def cml_plan_replica(
        ctx: Context,
        devices: Annotated[
            list[Device], Field(min_length=1, max_length=200, description="Devices to replicate")
        ],
        links: Annotated[
            list[Link] | None, Field(max_length=1000, description="Links between those devices (by name)")
        ] = None,
        fidelity: Annotated[
            Literal["light", "faithful"],
            Field(
                description="'light': IOL for IOS/IOS-XE routers and switches (1 GB, boot in a minute), XRd "
                "for IOS-XR; 'faithful': cat9000v (18 GB), cat8000v, IOS-XRv 9000. Firewalls (FTDv 8 GB), WLCs "
                "(9800-CL 6 GB) and NX-OS (10 GB) are the same at both: set max_ram_gb to cap them"
            ),
        ] = "light",
        max_nodes: Annotated[
            int | None, Field(ge=1, le=300, description="Node budget for the replica")
        ] = None,
        max_ram_gb: Annotated[float | None, Field(gt=0, le=2048, description="RAM budget (GB)")] = None,
    ) -> ToolResult:
        """Map a real site's devices (from Catalyst Center, ISE or FMC inventories) to CML node definitions
        within a node/RAM budget and return a ready cml_build_lab spec (`build.nodes` / `build.links`), the
        per-device mapping (kind, definition, RAM), devices CML can't model (`gaps`, e.g. CAPWAP APs, Meraki)
        and devices left out for budget (`dropped`, switches first). Uses only images installed on this
        controller and reports how many licences are free. No configs or credentials are copied. Changes
        nothing: build the replica with cml_build_lab."""
        app: CmlApp = get_client(ctx)
        plan = plan_replica(
            [d.model_dump() for d in devices],
            [lk.model_dump() for lk in links or []],
            fidelity=fidelity,
            max_nodes=max_nodes,
            max_ram_gb=max_ram_gb,
            available=await _available(app),
        )
        usage = await licence_usage(app)
        out: dict[str, Any] = {
            **plan,
            "licences": {k: usage.get(k) for k in ("limit", "free", "limit_source")},
        }
        free = usage.get("free")
        if isinstance(free, int) and plan["licensed_nodes"] > free:
            out["warning"] = (
                f"The replica needs {plan['licensed_nodes']} licensed nodes but {free} are free; lower "
                "max_nodes or stop labs first (cml_plan_licences)"
            )
        return shaped(out)

    @reg.prompt(title="Replicate a site in CML", uses=["cml", "catc", "ise", "fmc"], tier=Tier.WRITE)
    def cml_replicate_site(
        site: Annotated[
            str,
            Field(
                min_length=1,
                max_length=200,
                description="Catalyst Center site name or path, e.g. 'Global/SYD/BLD1'",
            ),
        ],
        fidelity: Annotated[
            str, Field(description="'light' (IOL, fast, small) or 'faithful' (real virtual platforms)")
        ] = "light",
        max_nodes: Annotated[str, Field(description="Node budget for the replica (1-300)")] = "10",
    ) -> str:
        """Build a scaled-down CML replica of a real site: read its devices and links from Catalyst Center,
        firewalls from FMC and RADIUS clients from ISE, map them to CML node definitions within a budget,
        build the lab and report what could and couldn't be replicated."""
        if fidelity not in ("light", "faithful"):
            raise ValueError("fidelity must be 'light' or 'faithful'")
        if not max_nodes.strip().isdigit() or not 1 <= int(max_nodes) <= 300:
            raise ValueError("max_nodes must be a number from 1 to 300")
        if any(c in site for c in "'\"\n\r`{}"):
            raise ValueError("site: a site name or path (no quotes, braces or line breaks)")
        budget = int(max_nodes)
        return f"""Replicate the site '{site}' in CML ({fidelity} fidelity, at most {budget} nodes).

1. Inventory (read-only):
   - {tool_ref("catc_get_site")} with site='{site}', then {tool_ref("catc_list_devices")} with site='{site}' and
     limit=500 (page with offset if there are more): hostname (as name), platformId (as platform), family, role,
     managementIpAddress of each device.
   - {tool_ref("catc_get_physical_topology")} with response_format='json' (whole network): keep the links whose
     both ends are devices of the site.
   - {tool_ref("fmc_list_devices")} (limit=500): firewalls whose name or host matches the site; add them with their
     model as platform. The same firewall may also be in Catalyst Center: use one name for it.
   - {tool_ref("ise_list_nads")} with detail=false (and group=<the site's network device group>, if there is
     one): which of the site's devices are RADIUS/TACACS+ clients of ISE (report only).
   If a server isn't connected, carry on with the others and say so. More than 200 devices: replicate the core
   (routers, firewalls, distribution switches) and say what was left out.
2. Call {tool_ref("cml_plan_replica")} with the devices, the links, fidelity='{fidelity}' and max_nodes={budget}.
   Show the mapping table, the gaps, the dropped devices (budget or duplicate names) and estimated_ram_gb.
3. Check the plan's `licences` and `warning`. If licences or RAM are short, propose a smaller max_nodes (or
   fidelity='light'), or show {tool_ref("cml_plan_licences")} and ask before stopping anyone's labs.
4. After the user approves, build it with {tool_ref("cml_build_lab")}: title 'mcp-replica-<site short name>' (pick
   another title if that lab exists), nodes and links exactly from plan.build, start=true, wait=false (preview
   first; show the wiring). Then {tool_ref("cml_wait_for_converged")}.
5. Optional, only if the user asks: copy configuration. Read a device's config with
   {tool_ref("catc_get_device_config")}, adapt interface names to the CML node's (cml_list_interfaces) and remove
   every secret before sending anything: 'username ... secret/password', 'enable secret', 'snmp-server community',
   SNMPv3 users, 'key'/'key 7' lines (RADIUS, TACACS+, OSPF/BGP/NTP authentication), crypto keys and certificates.
   Show the cleaned config, refuse if any secret remains, then apply it with {tool_ref("cml_configure_node")}
   (preview first). Never copy secrets.
6. Report: the lab title, a table device -> CML node (definition, why), the gaps (not modelled: CAPWAP APs,
   Meraki, etc.), devices left out (budget, duplicates), unmatched link ends, which devices are ISE NADs and
   which firewalls FMC manages (so test copies of those servers can be pointed at the replica), and what wasn't
   replicated (configs, credentials, wireless clients, external connections)."""
