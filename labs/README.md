# Lab exports (dCloud lab of 2026-10-15)

CML topology exports of every `mcp-*` lab the suite builders used, taken while the lab was up so the
same labs can be re-created on a fresh dCloud lab. They are the CML UI's YAML download (day-0 configs,
not running configs) with two changes:

- **Secrets scrubbed** to `${LAB_*}` placeholders (device passwords, enable secrets, SNMP communities,
  RADIUS keys, FTD admin passwords and registration key, the Samba AD admin password).
  The suite's private lab repo (stutters-mcp-lab) has `import_lab.py`, which fills them in from the
  environment or a lab secrets dotenv file (not in git) and imports the lab.
  Placeholders: `LAB_CLI_PASSWORD`, `LAB_DEFAULT_PASSWORD`, `LAB_SNMP_RO`, `LAB_SNMP_RW`,
  `LAB_RADIUS_SECRET`, `LAB_FTD_ADMIN_PASSWORD`, `LAB_FTD_HA_ADMIN_PASSWORD`, `LAB_FTD_REG_KEY`,
  `LAB_AD_ADMIN_PASSWORD`, `LAB_AD_TEST_USER_PASSWORD`.
- **Lab CA certificate as a placeholder**: `${LAB_CA_PEM}` stands alone on a line inside a YAML block scalar
  (`mcp-cml-identity`'s client writes it to `/etc/mcp-dot1x/mitchcloud-CA.pem` for PEAP server validation).
  `import_lab.py` replaces that line with the lab AD CS root certificate (`lab-ca/mitchcloud-CA.pem` in the
  private lab repo), each PEM line at the placeholder's indent. Every DC rebuild makes a new root, so no export
  embeds one.
- **Interface MAC addresses pinned** to the live values. ISE endpoints learned by MAB (client
  `52:54:00:61:3D:9E`) and the CatC PnP DHCP binding depend on them; without pinning CML assigns new
  MACs. Import each lab only once per controller.

The full rebuild order (appliance seeding, manual steps, timings) is the rebuild runbook in the suite's private
lab repo (stutters-mcp-lab).

All labs use the dCloud network 198.18.128.0/18 (gateway .1, DNS 198.18.133.1) through `System Bridge`
external connectors. Address blocks: recipes .150-.159, FMC .160-.169, CatC .170-.179, ISE .180-.189,
CML .190-.199.

| Start | Lab | Owner | Purpose | Nodes (licensed) | Addresses | Boot |
|---:|---|---|---|---|---|---|
| 1 | `mcp-ise-infra` | ISE | Samba AD DC `MCP.LAB` + OpenSSL lab CA on Ubuntu `dc1` (cloud-init installs Samba; needs internet via .1) | dc1 ubuntu (1) | dc1 198.18.128.180 | ~10 min incl. apt |
| 2 | `mcp-cml-ise` | ISE (recipe `ise-access`) | cat9000v access switch, 802.1X/MAB to ISE (TACACS+ lines are added after boot by the rebuild), Alpine client (DHCP on VLAN 10) + NAT connector on client eth1, Ubuntu `eaptls-client` on Gi1/0/3 (802.1X EAP-TLS with a CA it makes at first boot, as in the recipe) + NAT connector `ext-nat` on its ens3 | sw1 cat9000v-uadp, client alpine, eaptls-client ubuntu (3) | sw1 198.18.128.154; client 10.10.10.x (DHCP), MAC 52:54:00:61:3D:9E; eaptls-client 10.10.10.50 | ~8-10 min (eaptls-client +3 min apt) |
| 3 | `mcp-cml-catc` | CatC (recipe `catc-routers`) | two cat8000v discovered/provisioned by Catalyst Center | r1, r2 cat8000v (2) | r1 198.18.128.152, r2 .153 | ~6 min |
| 4 | `mcp-cml-ftd` | FMC (recipe `ftd-fmc` + additions) | FTDv managed by FMC; inside host and IOL BGP/OSPF peer | ftd1 ftdv, inside-host alpine, peer1 iol-xe (3) | ftd1 mgmt .151, outside .155; inside 10.99.1.1/24, inside-host .10, peer1 .2 | 15-30 min |
| 5 | `mcp-fmc-ha` | FMC (F8/F10/F11) | FTDv HA pair for FMC, failover link Gi0/2 <-> Gi0/2 | ftd2, ftd3 ftdv, inside-host2 alpine (3) | ftd2 mgmt .161, ftd3 .162, outside .163/.164; inside 10.99.2.0/24, host .10 | 15-30 min |
| 6 | `mcp-cml-ftd-ha` | CML (recipe `ftd-ha`, L10) | 2x FTDv cabled for an HA pair, deliberately NOT registered to FMC | ftd-a, ftd-b ftdv, inside-host alpine (3) | mgmt .190/.191, outside: pick free addresses (.192/.193 are fmc-local), inside 10.20.0.0/24 | 15-30 min |
| - | `mcp-cml-fabric` | CML (recipe `fabric`, L15) | SD-Access-style underlay for Catalyst Center: border/CP + 2 edges, fusion (DHCP for 10.10.40.0/24), client | bcp, edge1, edge2 cat9000v-uadp, fusion iol-xe, client alpine (5) | bcp .197, edge1 .198, edge2 .199 | ~12-15 min |
| - | `mcp-cml-fmc-local` | CML (recipe `fmc-local`, L14) | private FMCv 10.0.1 + FTDv registered to it (evaluation licence) | fmc fmcv, ftd ftdv (2) | fmc .192, ftd .193 | 30-45 min |
| - | `mcp-cml-wireless` | CML (recipe `wireless`, L13) | 9800-CL WLC + hostapd WPA2-Enterprise AP (RADIUS to ISE) + PEAP client on the simulated 802.11 medium | wlc cat9800, ap wireless-ap, client wireless-client (3) | wlc .195, ap .196 | ~8-12 min |
| - | `mcp-test-seed` | CML (`scripts/seed_lab.py`) | IOL OSPF pair + L2 switch + 2 Alpine hosts, internal only | r1, r2, sw1, h1, h2 (5) | internal 10.0.x | <1 min |
| - | `mcp-catc-onboard` | CatC (D3/D6) | fresh cat9000v for the onboarding prompt test (the test discovers and deletes it) | sw2 cat9000v-uadp (1) | sw2 198.18.128.170 | ~8 min |
| - | `mcp-catc-pnp` | CatC (D11) | blank cat8000v booting into PnP; Alpine `dhcp` serves option 43 -> CatC for pnp1's MAC only (the DHCP server is set up at runtime, not in day-0) | pnp1 cat8000v, dhcp alpine (2) | dhcp 198.18.128.171 | ~6 min |
| - | `mcp-cml-ospf` | CML (operator pass, v0.9.0) | IOL OSPF triangle r1-r3 + r4 behind r3 (loopbacks 10.255.0.x), internal only; used for the "prove it converges", diff and link-scenario tasks | r1-r4 iol-xe (4) | internal 10.0.x | <1 min |
| 7 | `mcp-cml-identity` | CML (recipe `ise-fmc-identity`, L34; for FMC F34 / ISE I30) | 802.1X AD-user client behind an FMC-managed FTDv, cat9000v RADIUS to ISE, outside telnet/http host. After import: the recipe's product side (ISE NAD + FMC registration/policies; lab tooling in stutters-mcp-lab) | sw1 cat9000v-uadp, ftd ftdv, client + outside-host ubuntu (4) | sw1 198.18.128.194, ftd mgmt .157; inside 10.10.34.0/24 (FTD .1), outside 172.31.34.0/24 (host .10) | 15-30 min |
| - | `mcp-cml-probe` | CML (P1) | obsolete reachability probe; kept for the record, don't import | probe alpine (1) | - | - |

"-" = import only, start when a test needs it. Exported 2026-10-15 ~12:00 UTC from CML 2.10.0.
