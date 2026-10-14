"""Create (idempotently) a small reusable test topology on the CML lab in .env.

    uv run python scripts/seed_lab.py              # create 'mcp-test-seed' if missing
    uv run python scripts/seed_lab.py --start      # ... and start it, waiting until booted
    uv run python scripts/seed_lab.py --recreate   # delete and rebuild it

Topology (all fast-booting Docker/IOL images):

    h1 (alpine 10.0.10.10) --- sw1 (ioll2-xe) --- r1 (iol-xe) ==== r2 (iol-xe) --- h2 (alpine 10.0.20.10)
                                          10.0.10.1   10.0.12.1/.2   10.0.20.1

r1/r2 run OSPF area 0 over 10.0.12.0/24 with loopbacks 1.1.1.1 / 2.2.2.2, so h1 can ping h2.
Device logins are cisco/cisco. The lab is a starting point for exercising this server (and the
other servers in the suite, e.g. switches as NADs) and is safe to delete at any time.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Any

from cml_mcp.build import NodeSpec, build_topology, to_yaml
from cml_mcp.client import CmlApp
from cml_mcp.config import Settings

TITLE = "mcp-test-seed"


def router(name: str, loopback: str, links: list[tuple[str, str]]) -> str:
    lines = [
        f"hostname {name}",
        "username cisco privilege 15 secret cisco",
        "enable secret cisco",
        "interface Loopback0",
        f" ip address {loopback} 255.255.255.255",
    ]
    for iface, addr in links:
        lines += [
            f"interface {iface}",
            f" ip address {addr} 255.255.255.0",
            " ip ospf 1 area 0",
            " no shutdown",
        ]
    lines += [
        "router ospf 1",
        f" router-id {loopback}",
        " network 0.0.0.0 255.255.255.255 area 0",
        "line con 0",
        " exec-timeout 0 0",
        " logging synchronous",
        "end",
    ]
    return "\n".join(lines) + "\n"


def host(name: str, addr: str, gateway: str) -> str:
    return (
        "\n".join(
            [
                "# this is a shell script which will be sourced at boot",
                f"hostname {name}",
                "USERNAME=cisco",
                "PASSWORD=cisco",
                "ip link set eth0 up",
                f"ip address add {addr}/24 dev eth0",
                f"ip route add default via {gateway}",
            ]
        )
        + "\n"
    )


NODES = [
    NodeSpec(
        label="r1",
        definition="iol-xe",
        tags=["core"],
        config=router("r1", "1.1.1.1", [("Ethernet0/0", "10.0.12.1"), ("Ethernet0/1", "10.0.10.1")]),
    ),
    NodeSpec(
        label="r2",
        definition="iol-xe",
        tags=["core"],
        config=router("r2", "2.2.2.2", [("Ethernet0/0", "10.0.12.2"), ("Ethernet0/1", "10.0.20.1")]),
    ),
    NodeSpec(
        label="sw1",
        definition="ioll2-xe",
        tags=["access"],
        config="hostname sw1\nusername cisco privilege 15 secret cisco\nenable secret cisco\nend\n",
    ),
    NodeSpec(label="h1", definition="alpine", tags=["host"], config=host("h1", "10.0.10.10", "10.0.10.1")),
    NodeSpec(label="h2", definition="alpine", tags=["host"], config=host("h2", "10.0.20.10", "10.0.20.1")),
]
LINKS = [
    "r1:Ethernet0/0 r2:Ethernet0/0",
    "r1:Ethernet0/1 sw1:Ethernet0/0",
    "sw1:Ethernet0/1 h1:eth0",
    "r2:Ethernet0/1 h2:eth0",
]


async def wait(app: CmlApp, lab_id: str, timeout: float = 600) -> None:  # noqa: ASYNC109
    deadline = time.monotonic() + timeout
    while await app.api.get(f"/labs/{lab_id}/check_if_converged") is not True:
        if time.monotonic() > deadline:
            raise SystemExit("timed out waiting for the lab to boot")
        await asyncio.sleep(5)


async def delete(app: CmlApp, lab_id: str) -> None:
    await app.api.put(f"/labs/{lab_id}/stop")
    await app.api.put(f"/labs/{lab_id}/wipe")
    await app.api.delete(f"/labs/{lab_id}")


async def main(args: argparse.Namespace) -> None:
    app = CmlApp(Settings())  # type: ignore[call-arg]
    try:
        existing = [lab for lab in await app.list_labs() if lab.get("lab_title") == args.title]
        if existing and args.recreate:
            for lab in existing:
                await delete(app, lab["id"])
                print(f"deleted {lab['id']}")
            existing = []
        if existing:
            lab_id = existing[0]["id"]
            print(f"{args.title} already exists: {lab_id} ({existing[0].get('state')})")
        else:
            defs: dict[str, Any] = {d["id"]: d for d in await app.api.get("/simplified_node_definitions")}
            topo, wiring = build_topology(
                args.title, NODES, LINKS, defs, "Reusable test topology (seed_lab.py)"
            )
            res = await app.api.post(
                "/import", None, content=to_yaml(topo), headers={"Content-Type": "application/x-yaml"}
            )
            lab_id = res["id"]
            print(f"created {args.title}: {lab_id}")
            for w in wiring:
                print(f"  {w}")
        if args.start:
            await app.api.put(f"/labs/{lab_id}/start")
            print("starting...")
            await wait(app, lab_id)
            print("all nodes booted")
    finally:
        await app.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--title", default=TITLE)
    parser.add_argument("--start", action="store_true", help="start the lab and wait until booted")
    parser.add_argument("--recreate", action="store_true", help="delete and rebuild if it exists")
    asyncio.run(main(parser.parse_args(sys.argv[1:])))
