"""Product side of the ise-fmc-identity recipe (L34): the ISE network device and the FMC device, zones,
policies and interfaces that make lab mcp-cml-identity a user-based-firewall test bed - and their removal.

    uv run python scripts/identity_lab.py up [--dry-run]       # idempotent; run after the lab has booted
    uv run python scripts/identity_lab.py --delete [--lab]     # remove the ISE/FMC objects (and the CML lab)

It drives the suite servers' own tools through ~/MCP-Suite/scripts/mcp_call.py from their checkouts
(ise-mcp-server, fmc-mcp-server; writes and dangerous enabled only in that process), exactly as a model
would: preview, then confirm. Secrets are passed as ${LAB_*} references that mcp_call.py fills from
~/MCP-Suite/lab-secrets.env; nothing secret is printed.

Objects (all mcp-test-* except the FMC device name, which the FMC suite names mcp-ftd*):
  ISE  NAD mcp-test-cml-identity-sw (198.18.128.194, NDG Location#All Locations#mcp-test-lab)
  FMC  zones mcp-test-identity-inside/-outside, ACP mcp-test-identity-acp (default BLOCK) with rule
       mcp-test-identity-baseline (inside -> outside tcp/23, tcp/80), network mcp-test-identity-clients
       10.10.34.0/24, NAT policy mcp-test-identity-nat (dynamic interface PAT inside -> outside), device
       mcp-ftd-identity (198.18.128.157, domain Global/mcp-test-leaf) with Ethernet0/1 inside 10.10.34.1/24
       and Ethernet0/0 outside 172.31.34.1/24.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SUITE = Path.home() / "MCP-Suite"
MCP_CALL = SUITE / "scripts" / "mcp_call.py"
LEAF = "Global/mcp-test-leaf"  # FMC registers devices only in a leaf domain
DEVICE = "mcp-ftd-identity"
LAB = "mcp-cml-identity"
# the tools' own "it is already there" answers (idempotent re-runs); anything else counts as a failure
EXISTS = r"named '[^']+' already exists|already has a rule named|is already registered"


def call(
    server: str,
    tool: str,
    args: dict[str, object],
    *,
    ok_if: str | None = None,
    timeout: int = 600,
    dry: bool = False,
) -> bool:
    cmd = [
        "uv",
        "run",
        "-q",
        "python",
        str(MCP_CALL),
        server,
        tool,
        json.dumps(args),
        "--yes",
        "--timeout",
        str(timeout),
    ]
    if ok_if:
        cmd += ["--ok-if", ok_if]
    print(f"-- {server} {tool} {json.dumps(args)}", flush=True)
    if dry:
        return True
    res = subprocess.run(
        cmd,
        cwd=SUITE / f"{server}-mcp-server",
        capture_output=True,
        text=True,
        timeout=timeout + 120,
        check=False,
    )
    tail = (res.stdout + res.stderr).strip().splitlines()[-3:]
    print(
        "   "
        + ("ok" if res.returncode == 0 else f"FAILED ({res.returncode})")
        + ": "
        + " | ".join(tail)[:300]
    )
    LAST_OUTPUT[0] = res.stdout + res.stderr
    return res.returncode == 0


LAST_OUTPUT = [""]  # output of the last call (to tell 'already exists' from a failure)


def up(dry: bool) -> bool:
    ok = call(
        "ise",
        "ise_create_nad",
        {
            "name": "mcp-test-cml-identity-sw",
            "ips": ["198.18.128.194"],
            "radius_secret": "${LAB_RADIUS_SECRET}",
            "coa_port": 1700,
            "groups": ["Location#All Locations#mcp-test-lab", "Device Type#All Device Types"],
            "description": "mcp-test CML recipe ise-fmc-identity sw1",
        },
        ok_if=EXISTS,
        dry=dry,
    )
    for z in ("inside", "outside"):
        ok &= call(
            "fmc",
            "fmc_create_security_zone",
            {"name": f"mcp-test-identity-{z}", "description": f"CML recipe ise-fmc-identity ({z})"},
            ok_if=EXISTS,
            dry=dry,
        )
    ok &= call(
        "fmc",
        "fmc_create_access_policy",
        {
            "name": "mcp-test-identity-acp",
            "default_action": "BLOCK",
            "description": "CML recipe ise-fmc-identity: user rules (F34) go above the baseline",
        },
        ok_if=EXISTS,
        dry=dry,
    )
    ok &= call(
        "fmc",
        "fmc_create_access_rule",
        {
            "policy": "mcp-test-identity-acp",
            "name": "mcp-test-identity-baseline",
            "action": "ALLOW",
            "source_zones": ["mcp-test-identity-inside"],
            "destination_zones": ["mcp-test-identity-outside"],
            "destination_ports": ["tcp/23", "tcp/80"],
            "log": "end",
            "comment": "CML ise-fmc-identity baseline: any user, telnet+http; user rules (F34) go above",
        },
        ok_if=EXISTS,
        dry=dry,
    )
    ok &= call(
        "fmc",
        "fmc_create_object",
        {
            "type": "network",
            "name": "mcp-test-identity-clients",
            "value": "10.10.34.0/24",
            "description": "CML ise-fmc-identity client VLAN 34",
        },
        ok_if=EXISTS,
        dry=dry,
    )
    created = call(
        "fmc",
        "fmc_create_nat_policy",
        {"name": "mcp-test-identity-nat", "description": "CML ise-fmc-identity: PAT clients to outside"},
        dry=dry,
    )
    if not created and "already exists" in LAST_OUTPUT[0]:
        print("   (the NAT policy exists already: its rule is kept, not added again)")
    elif not created:
        ok = False
    else:  # a new policy has no rules yet
        ok &= call(
            "fmc",
            "fmc_create_nat_rule",
            {
                "policy": "mcp-test-identity-nat",
                "kind": "auto",
                "nat_type": "DYNAMIC",
                "original_source": "mcp-test-identity-clients",
                "translated_source": "interface",
                "source_interface": "mcp-test-identity-inside",
                "destination_interface": "mcp-test-identity-outside",
            },
            dry=dry,
        )
    registered = call(
        "fmc",
        "fmc_register_device",
        {
            "name": DEVICE,
            "host": "198.18.128.157",
            "reg_key": "${LAB_FTD_REG_KEY}",
            "access_policy": "mcp-test-identity-acp",
            "license_caps": ["ESSENTIALS", "IPS"],
            "performance_tier": "FTDv5",
            "wait": True,
            "domain": LEAF,
        },
        ok_if=EXISTS,
        timeout=1800,
        dry=dry,
    )
    if not registered:
        print(
            "!! the FTD is not registered (booted? 'show managers' on it); stopping before interfaces/deploy"
        )
        return False
    for iface, name, zone, ip in (
        ("Ethernet0/1", "inside", "mcp-test-identity-inside", "10.10.34.1/24"),
        ("Ethernet0/0", "outside", "mcp-test-identity-outside", "172.31.34.1/24"),
    ):
        ok &= call(
            "fmc",
            "fmc_update_interface",
            {
                "device": DEVICE,
                "interface": iface,
                "logical_name": name,
                "security_zone": zone,
                "ipv4": ip,
                "enabled": True,
                "domain": LEAF,
            },
            ok_if="no changes|nothing to change",
            dry=dry,
        )
    ok &= call(
        "fmc",
        "fmc_assign_policy",
        # the NAT policy lives in Global: assigning it from the leaf domain is refused (406)
        {"kind": "nat", "policy": "mcp-test-identity-nat", "devices": [DEVICE], "domain": "Global"},
        ok_if="already",
        dry=dry,
    )
    ok &= call(
        "fmc",
        "fmc_deploy",
        {"devices": [DEVICE], "wait": True, "domain": LEAF},
        ok_if="nothing to deploy|no pending|up to date",
        timeout=1800,
        dry=dry,
    )
    return ok


def delete(dry: bool, lab: bool) -> bool:
    # the tools' "no such object" answers only (a wrong-domain or other error still fails)
    gone = r"(?i)not found|no [a-z -]+ (named|matches|matching|with (the )?(name|id))"
    ok = call("fmc", "fmc_delete_device", {"device": DEVICE, "domain": LEAF}, ok_if=gone, dry=dry)
    ok &= call(
        "fmc", "fmc_delete_policy", {"kind": "nat", "policy": "mcp-test-identity-nat"}, ok_if=gone, dry=dry
    )
    ok &= call(
        "fmc", "fmc_delete_policy", {"kind": "access", "policy": "mcp-test-identity-acp"}, ok_if=gone, dry=dry
    )
    ok &= call(
        "fmc",
        "fmc_delete_object",
        {"object": "mcp-test-identity-clients", "type": "network"},
        ok_if=gone,
        dry=dry,
    )
    for z in ("inside", "outside"):
        ok &= call(
            "fmc",
            "fmc_delete_object",
            {"object": f"mcp-test-identity-{z}", "type": "security_zone"},
            ok_if=gone,
            dry=dry,
        )
    ok &= call("ise", "ise_delete_nad", {"device": "mcp-test-cml-identity-sw"}, ok_if=gone, dry=dry)
    if lab:
        ok &= call("cml", "cml_delete_lab", {"lab": LAB, "force": True}, ok_if=gone, dry=dry)
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", nargs="?", choices=["up"], help="create/refresh the product-side objects")
    ap.add_argument("--delete", action="store_true", help="remove the ISE/FMC objects instead")
    ap.add_argument("--lab", action="store_true", help="--delete: also delete the CML lab mcp-cml-identity")
    ap.add_argument("--dry-run", action="store_true", help="print the tool calls only")
    args = ap.parse_args()
    if args.delete == bool(args.action):
        sys.exit("give 'up' or --delete")
    ok = delete(args.dry_run, args.lab) if args.delete else up(args.dry_run)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
