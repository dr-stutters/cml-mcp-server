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

All of them attach to the lab network (198.18.128.0/18, gateway 198.18.128.1) through the
`System Bridge` external connector (layer 2 on the controller's `ens192`; CML snoops addresses there).

| Recipe | Lab | Licensed nodes | Addresses | For |
|---|---|---:|---|---|
| `ftd-fmc` | `mcp-cml-ftd` | 1 (ftdv, 8 GB, 4 vCPU) | ftd1 mgmt 198.18.128.151 | FMC 198.18.134.76, reg key `${LAB_FTD_REG_KEY}` |
| `catc-routers` | `mcp-cml-catc` | 2 (cat8000v) | r1 198.18.128.152, r2 198.18.128.153 | Catalyst Center 198.18.128.11 discovery |
| `fmc-local` | `mcp-cml-fmc-local` | 2 (fmcv 32 GB + ftdv 8 GB) | fmc 198.18.128.192, ftd .193 | A private, resettable FMCv 10.0.1 (evaluation licence) with an FTDv pre-registered to it: destructive fmc-server tests away from the lab FMC |
| `ftd-ha` | `mcp-cml-ftd-ha` | 3 (2x ftdv + alpine) | ftd-a 198.18.128.190, ftd-b .191 (not registered) | FMC HA pair tests (`fmc_form_ha`); failover link Gi0/2, state link Gi0/3 |
| `fabric` | `mcp-cml-fabric` | 5 (3x cat9000v-uadp 18 GB + iol-xe + alpine) | bcp 198.18.128.197, edge1 .198, edge2 .199 (management); Loopback0 RLOCs 10.255.255.11-.14 | Catalyst Center SD-Access (D13): pre-built underlay (OSPF, MTU 9100), fusion router with DHCP for the fabric pool 10.10.40.0/24, unassigned client port edge1 Gi1/0/3 |
| `wireless` | `mcp-cml-wireless` | 3 (cat9800 6 GB + wireless-ap + wireless-client) | wlc 198.18.128.195, ap .196 | ISE wireless 802.1X: hostapd WPA2-Enterprise AP with RADIUS to ISE (NAD `mcp-test-cml-ap`) and a PEAP client (`mcp-test-cml-wifi`); a 9800-CL WLC (WLAN + RADIUS) for ISE/CatC WLC tests. CML's wireless-ap is hostapd, not CAPWAP: it can't join the 9800 |
| `ise-fmc-identity` | `mcp-cml-identity` | 4 (cat9000v-uadp 18 GB + ftdv 8 GB + 2x ubuntu) | sw1 198.18.128.194 (ISE NAD `mcp-test-cml-identity-sw`), FTD mgmt .157 (`mcp-ftd-identity` in FMC); client VLAN 10.10.34.0/24 (gateway = FTD inside .1), outside 172.31.34.0/24 (host .10) | User-based firewalling (Wave 3 A): 802.1X PEAP client as AD user mcp-alice / mcp-bob (switch with `cml_run_recipe_action` login-alice / login-bob), ISE pxGrid -> FMC; outside host offers telnet + http. Product side (the recipe's `ise_side` / `fmc_side`): an ISE network device for sw1 with the RADIUS secret, and in FMC the zones, an access policy with the baseline rule, the NAT policy, the FTD registration, its interfaces and a deploy (the suite's lab tooling scripts this; it is not part of this repo) |
| `ise-access` | `mcp-cml-ise` | 3 (cat9000v-uadp 18 GB + alpine + ubuntu) | sw1 198.18.128.154 | ISE 198.18.134.35 RADIUS, IBNS 2.0 802.1X then MAB; MAB client + EAP-TLS client (self-made lab CA) |

Reserved for recipes: 198.18.128.150-.159 and (since phase 4) .190-.199: .190/.191 ftd-ha management, .192/.193 ftd-ha outside (suggested), .194 sw1 of `ise-fmc-identity` (the old `mcp-cml2-ise` copy was deleted); (.150 probe, .155 spare FTD outside, .157 `ise-fmc-identity` FTD management, .156/.158/.159 free);
checked unused by ping/ARP on 2026-10-14.

Running licensed nodes are capped by the controller's licence (external connectors and unmanaged
switches don't count); the three recipes together need 5. `scripts/recipes.py plan <recipe>` (or
`cml_plan_licences`) shows the cap and which labs to stop; `scripts/recipes.py swap <recipe>` stops
them and starts the recipe.

Copies: `cml_build_recipe(recipe, title='mcp-cml2-...', substitute={'198.18.128.154': '198.18.128.194'})` builds a copy
next to the recipe's own lab (e.g. to try a recipe change while someone uses the original), and
`cml_verify_recipe(recipe, lab=..., substitute=...)` verifies it against the same contract.

Gotchas found while building them:
- FTDv forces a password change at first login when the day-0 `AdminPassword` is weak or a
  dictionary word (a vendor-style default such as `<Name>123!` is rejected); the recipe uses a strong one. `cml_run_commands` reports
  this case clearly.
- FTD's `ping system <ip>` (management interface) never stops by itself; use
  `cml_check_reachability(..., vrf='management')`, which interrupts it.
- cat9000v reports BOOTED about 2-3 minutes before its routed uplink forwards; re-run `verify`.
- IOS-XE NETCONF (port 830) needs `aaa new-model` + `aaa authorization exec default local` and
  takes several minutes after boot to listen.
- Wiping a node gives its interfaces new MAC addresses (matters for ISE endpoint/MAB tests).
- EAP-TLS (`ise-access` eaptls-client): the Ubuntu client installs `wpasupplicant` through the NAT connector at first
  boot and makes its own lab CA + client certificate in `/etc/eaptls` (no keys in git). ISE must trust that CA
  (import `/etc/eaptls/ca.pem` with trust for client authentication); every rebuild makes a new CA. ISE's
  trusted-certificate import answers 400 "Security Check Failed" when the description contains parentheses.
- FTD 10 re-types a rejected command after `Syntax error`; the console clears it (Ctrl-U) and returns the error.
- `ise-fmc-identity` (FMC 10): devices register only into a leaf domain (here `Global/mcp-test-leaf`; Global answers
  "Device cannot be registered to non-leaf domain"); a Global NAT policy is assigned from the Global domain (from the
  leaf: 406); FMC refuses interface addresses in TEST-NET 203.0.113.0/24 ("IPv4 Address is Invalid"), hence the
  172.31.34.0/24 outside network. The outside host is Ubuntu (telnetd + python http.server): an IOL host's
  `ip http server` listens on 80 but answers every SYN with RST.

## Secrets

Recipes never contain secret values. Device passwords, the FMC registration key, RADIUS keys and SNMP
communities are written as `${LAB_*}` references, the same names as `labs/*.yaml`:
`LAB_CLI_PASSWORD`, `LAB_SNMP_RO`, `LAB_SNMP_RW`, `LAB_RADIUS_SECRET`, `LAB_FTD_REG_KEY`,
`LAB_FTD_ADMIN_PASSWORD`, `LAB_FTD_HA_ADMIN_PASSWORD`. `cml_build_recipe` and `cml_verify_recipe` fill them
in from `LAB_*` environment variables, or from the dotenv file named by `CML_LAB_SECRETS_FILE`. A missing value
is an error that names the variable. Previews, `cml_list_recipes` and the lab annotations show only the
references, and every tool result or error that would contain a resolved value (e.g. reading back a
built lab's day-0 config) shows the reference instead. `scripts/check_secrets.py` (CI) fails if a value or a literal credential is committed.

## Verify contracts

Each recipe's `verify:` section is a contract that `cml_verify_recipe` (and `scripts/recipes.py verify`,
and `pytest -m live_recipes`) checks against the running lab, pass/fail per check. Nothing is changed.
- `booted`: nodes that must be BOOTED (default: every licensed node).
- `nodes` / `targets` / `vrf`: a ping matrix through the consoles.
- `addresses`: addresses each node must show in its CLI.
- `probes`: `{name, node, command, expect, reject}` runs a console command and matches regexes;
  `{name, tcp: host:port}` and `{name, snmp: {host, community}}` run from the MCP server's host, and so does
  `{name, ise_session: {url, username, password, user, nas_ip?, framed_ip?, verify_tls}}`: a live session in ISE's
  MnT ActiveList whose user (regex) came from that NAS with a matching framed IP (credentials as `${LAB_ISE_*}`).

## Actions

A recipe's `actions:` are named console commands that change the lab's state the way a test needs, run with
`cml_run_recipe_action(recipe, action)` or `scripts/recipes.py run <recipe> <action>` (preview-first; the command
comes from the recipe only). `ise-fmc-identity`: `login-alice`, `login-bob` (EAPOL-Logoff, then 802.1X as that AD
user; prints `user=... port=Authorized eap=SUCCESS ip=10.10.34.x/24`) and `logoff`.

Verified on 2026-10-15: ftd-fmc 6/6 (FTD 'show managers' points at FMC), catc-routers 14/14 (SSH, NETCONF
and SNMP from cortex), ise-access 9/9 (RADIUS server UP and `test aaa` answered by ISE).
