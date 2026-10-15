# Lab recipes

Ready-made labs for testing the other suite servers against real devices in CML. Each
`<recipe>.yaml` holds an address plan, credentials, what to configure on the other product, and a
`build:` section that is **exactly the argument set of `cml_build_lab`** - a model can build a recipe
with one tool call, or you can run:

```bash
uv run python scripts/recipes.py list
uv run python scripts/recipes.py build ftd-fmc --start --no-wait   # FTDv: 15-30 min to boot
uv run python scripts/recipes.py wait ftd-fmc                      # until booted
uv run python scripts/recipes.py verify ftd-fmc [--json]           # run the verify contract (pass/fail)
uv run python scripts/recipes.py stop ftd-fmc                      # keep it defined, free licences
uv run python scripts/recipes.py start catc-routers                # bring a stopped recipe back
```

All of them attach to the dCloud network (198.18.128.0/18, gateway 198.18.128.1) through the
`System Bridge` external connector (layer 2 on the controller's `ens192`; CML snoops addresses there).

| Recipe | Lab | Licensed nodes | Addresses | For |
|---|---|---:|---|---|
| `ftd-fmc` | `mcp-cml-ftd` | 1 (ftdv, 8 GB, 4 vCPU) | ftd1 mgmt 198.18.128.151 | FMC 198.18.134.76, reg key `***REDACTED***` |
| `catc-routers` | `mcp-cml-catc` | 2 (cat8000v) | r1 198.18.128.152, r2 198.18.128.153 | Catalyst Center 198.18.128.11 discovery |
| `ftd-ha` | `mcp-cml-ftd-ha` | 3 (2x ftdv + alpine) | ftd-a 198.18.128.190, ftd-b .191 (not registered) | FMC HA pair tests (`fmc_form_ha`); failover link Gi0/2, state link Gi0/3 |
| `ise-access` | `mcp-cml-ise` | 2 (cat9000v-uadp 18 GB + alpine) | sw1 198.18.128.154 | ISE 198.18.134.35 RADIUS/802.1X/MAB |

Reserved for recipes: 198.18.128.150-.159 and (since phase 4) .190-.199: .190/.191 ftd-ha management, .192/.193 ftd-ha outside (suggested), .194 copies of ise-access (`mcp-cml2-ise`); (.150 probe, .155 spare FTD outside, .156-.159 free);
checked unused by ping/ARP on 2026-10-14.

Running licensed nodes are capped by the controller's licence (external connectors and unmanaged
switches don't count); the three recipes together need 5. `scripts/recipes.py plan <recipe>` (or
`cml_plan_licences`) shows the cap and which labs to stop; `scripts/recipes.py swap <recipe>` stops
them and starts the recipe.

Gotchas found while building them:
- FTDv forces a password change at first login when the day-0 `AdminPassword` is weak or a
  dictionary word (`***REDACTED***!` is rejected); the recipe uses a strong one. `cml_run_commands` reports
  this case clearly.
- FTD's `ping system <ip>` (management interface) never stops by itself; use
  `cml_check_reachability(..., vrf='management')`, which interrupts it.
- cat9000v reports BOOTED about 2-3 minutes before its routed uplink forwards; re-run `verify`.
- IOS-XE NETCONF (port 830) needs `aaa new-model` + `aaa authorization exec default local` and
  takes several minutes after boot to listen.
- Wiping a node gives its interfaces new MAC addresses (matters for ISE endpoint/MAB tests).

## Verify contracts

Each recipe's `verify:` section is a contract that `cml_verify_recipe` (and `scripts/recipes.py verify`,
and `pytest -m live_recipes`) checks against the running lab, pass/fail per check. Nothing is changed.
- `booted`: nodes that must be BOOTED (default: every licensed node).
- `nodes` / `targets` / `vrf`: a ping matrix through the consoles.
- `addresses`: addresses each node must show in its CLI.
- `probes`: `{name, node, command, expect, reject}` runs a console command and matches regexes;
  `{name, tcp: host:port}` and `{name, snmp: {host, community}}` run from the MCP server's host.

Verified on 2026-10-15: ftd-fmc 6/6 (FTD 'show managers' points at FMC), catc-routers 14/14 (SSH, NETCONF
and SNMP from cortex), ise-access 9/9 (RADIUS server UP and `test aaa` answered by ISE).
