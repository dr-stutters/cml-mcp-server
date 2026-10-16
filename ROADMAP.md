# cml-mcp-server roadmap
_Last updated 2026-10-15. Current release v0.9.0 (operator-eyes pass L25-L33 delivered) (Now, Next L8-L11, Production gate L17/L19/L20/L21 and Later L13/L14/L15/L16 delivered; L18 skipped (needs older CML versions); L12 waits for the runner).; L15 first slice; L12 waits for the runner). Suite roadmap: [stutters-mcp-core/ROADMAP.md](https://github.com/dr-stutters/stutters-mcp-core/blob/main/ROADMAP.md). Gap analysis: [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)._

## Summary
- **Where it stands (v0.4.0):** 59 tools (35 read, 19 write, 5 dangerous plus `cml_api_call`) and the prompt
  `cml_build_test_lab`, against CML 2.10. About 70 % of the
  day-to-day lab operations have curated tools. Console CLI works on IOS/IOS-XE/NX-OS/FTD/Linux. Three recipes
  (`ftd-fmc`, `catc-routers`, `ise-access`) are the **test bed for the FMC, Catalyst Center and ISE servers**.
- **Biggest gaps:** non-admin accounts (L17, now unblocked) and older CML versions (L18) are untested; no
  scheduled recipe verification yet (L12); recipe secrets still live in git (L21).
- **Lab capacity (updated 2026-10-15):** the controller is now **CML Enterprise, registered and in compliance: 20 + 50
  expansion = 70 running licensed nodes**, with extra users and groups allowed. The three recipes (5 nodes) run side by side;
  RAM (250 GB) is now the practical limit for big recipes. L15 (fabric) and L17 (non-admin) are no longer blocked by the licence.
- **Now (done in v0.4.0):** the `cml_build_test_lab` prompt, a licence planner that decides which labs to stop, scripted recipe
  verification, console hardening, capture summaries and node config diffs.

## Now
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| L1 ✅ v0.4.0 | **`cml_build_test_lab` prompt**: argument `recipe` (ftd-fmc / catc-routers / ise-access, later more), optional `reuse=true`. Steps: list recipes (new read tool `cml_list_recipes` exposes `recipes/*.yaml` without credentials) → licence plan (L2) → build or start → `cml_wait_for_converged` → `cml_check_reachability` → print the hand-off block that the fmc/catc/ise servers need (addresses, reg key, NAD secret, credentials reference). Depends on core [C2](https://github.com/dr-stutters/stutters-mcp-core/issues/7). | One sentence gets the FMC/CatC/ISE builders a working device. This is the entry point for the other three servers' live tests. | none | Live: run the prompt for each of the 3 recipes from a stopped state and check the verify output. Unit: the prompt renders, and the tools it names exist (core C9 once available). | M | [#10](https://github.com/dr-stutters/cml-mcp-server/issues/10) |
| L2 ✅ v0.4.0 | **Licence-aware scheduling**: new read tool `cml_plan_licences(target=<lab or recipe>)` returns licences in use per lab, what the target needs, and the smallest set of labs to stop (preferring labs tagged `recipe`/`mcp-test`). Add `scripts/recipes.py swap <recipe>` (stop the plan's labs, start the target, verify). The start previews show the plan instead of just refusing. | With 5 node licences, testing ISE means stopping CatC. Today the operator has to work that out by hand from a 400 error. | none (`CML_NODE_LICENSE_LIMIT=5` already set) | Unit: planner cases (free, swap one, impossible). Live: `swap ise-access` while `catc-routers` runs, then `swap catc-routers` back. | S | [#11](https://github.com/dr-stutters/cml-mcp-server/issues/11) |
| L3 ✅ v0.4.0 | **Recipe verification harness**: each recipe gets a `verify:` contract (booted markers, expected addresses, a reachability matrix, per-product probes: FTD `show managers`, IOS-XE NETCONF :830 / SNMP, sw1 RADIUS `test aaa`). `recipes.py verify --json` returns pass/fail per check, wrapped in a `live_recipes` pytest marker. | Recipes rot as images and appliances change; the other servers' live tests need a known-good device. | none | Live: verify all 3 recipes (one at a time under L2). Unit: contract parsing and the result model. | M | [#12](https://github.com/dr-stutters/cml-mcp-server/issues/12) |
| L4 ✅ v0.4.0 | **Console hardening**: a per-node console lock (one session per node per process; a clear "busy" error, not interleaved output), `logout`/`exit` on close (sessions currently stay logged in), a re-login check when a node was wiped/rebooted mid-session, and a cat9000v "BOOTED but not forwarding" hint in `cml_wait_for_converged`. Notes deferral: console sessions aren't coordinated across server processes. | Parallel callers (prompts plus another server's session) can corrupt each other's console output. A stale logged-in console is a security smell. | none | Unit: the scripted fake console (concurrency, logout, relogin). Live: two concurrent `cml_run_commands` on `mcp-test-seed` r1. | M | [#13](https://github.com/dr-stutters/cml-mcp-server/issues/13) |
| L5 ✅ v0.4.0 | **Packet capture analysis**: new read tool `cml_summarize_capture(link, ...)`: protocol mix, top conversations, filters (src/dst/proto/port), decoded highlights for RADIUS (code, attributes minus secrets), EAP/EAPOL, OSPF, ARP/DHCP and ICMP. A write tool `cml_capture(link, seconds\|packets, filter)` runs start → wait → stop → summary in one call. | Proves the 802.1X/MAB exchange to ISE, FTD registration (sftunnel :8305), or OSPF adjacency without anyone reading raw packet lists. | none | Live: `ise-access` sw1 uplink during MAB (RADIUS to ISE); `mcp-test-seed` r1–sw1 OSPF hellos. Unit: decoder fixtures from captured packets. | M | [#14](https://github.com/dr-stutters/cml-mcp-server/issues/14) |
| L6 ✅ v0.4.0 | **Node config diff**: new read tool `cml_diff_node_config(node, against='saved'\|'day0'\|<other node>\|<file text>)` takes the running config from the console (`show running-config`, read tier) and returns a unified diff with secrets masked. `cml_diff_lab` gains `configs=true`. | Shows what a product server (CatC template, ISE AAA push) actually changed on a lab device. That makes it the test oracle for CatC/ISE writes. | none | Live: `catc-routers` r1 before and after a manual config line. Unit: diff and masking. | S | [#15](https://github.com/dr-stutters/cml-mcp-server/issues/15) |

## Next
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| L8 ✅ v0.5.0 | **Link conditioning scenarios**: `cml_apply_link_scenario(link, scenario)` with named profiles (`wan-good`, `wan-satellite`, `lossy-wifi`, `brownout`, `flap` = timed up/down cycles, run as a background task and cancellable) and `cml_clear_link_scenarios(lab)`. Each scenario also returns its expected ping matrix deltas. | Repeatable degraded-network tests: FMC/FTD HA failover, ISE RADIUS timeouts and CatC assurance health scores, all without hand-typing netem values. | none | Live: `mcp-test-seed` r1–r2 with each profile, checking loss/latency through `cml_check_reachability`; the flap scenario's OSPF adjacency changes show in `cml_get_node_console_log(grep=...)`. | M | [#17](https://github.com/dr-stutters/cml-mcp-server/issues/17) |
| L9 ✅ v0.5.0 | **Topology export and annotations**: `cml_export_topology(lab, format='mermaid'\|'drawio'\|'json')` with addresses from L3 discovery; `cml_list_annotations` (read); `cml_annotate_lab` (write: text boxes for addresses, credentials *references* and the recipe purpose). The recipes annotate their own labs. Reverses the gap-analysis "cosmetic" call for PoC use. | PoC write-ups and customer demos need a diagram and a self-describing lab. | none | Live: export and annotate `mcp-cml-catc`, render the Mermaid. Unit: format snapshot tests. | S | [#18](https://github.com/dr-stutters/cml-mcp-server/issues/18) |
| L10 ✅ v0.5.0 | **`ftd-ha` recipe**: 2 FTDv (failover and state links over an unmanaged switch, inside/outside data links), an Alpine inside host, outside on the System Bridge (198.18.128.155–.157). Built for the fmc server's `fmc_form_ha` / `fmc_ha_action` / `fmc_break_ha` live tests. | FMC HA tools are mock-only without two FTDs. | 3 node licences (fine on the 70-node licence). FMC device and eval licence for 2 more FTDs. IPs .155–.157 free. | Live: build, register both to FMC, form HA, fail over via L8 `flap` on the failover link, break HA, delete. | M | [#19](https://github.com/dr-stutters/cml-mcp-server/issues/19) |
| L11 ✅ v0.5.0 | **EAP-TLS wired client in `ise-access`**: add an Ubuntu client with `wpa_supplicant` (802.1X EAP-TLS) next to the Alpine MAB client. Day-0 `files` carry the client cert and key, issued by the Windows CA. Change sw1 to IBNS 2.0 with dot1x before MAB. | ISE certificate-based auth (the real enterprise case) can't be tested with MAB-only clients. | Windows lab CA (`Windows_Server` MCP: `win_sign_csr`). ISE trusts that CA (`ise_import_trusted_cert`) and has an EAP-TLS allowed-protocols entry. 1 more licence (ise-access becomes 3). | Live: client authenticates, ISE `ise_session_by_mac` shows EAP-TLS, L5 capture shows the EAPOL/RADIUS exchange. | M | [#20](https://github.com/dr-stutters/cml-mcp-server/issues/20) |
| L12 (workflow ✅ v0.5.0; runner install is the user's, see docs/ci-runner.md) | **Recipe verification in CI**: a scheduled GitHub Actions workflow (nightly plus manual) on a self-hosted runner on cortex runs L3 for each recipe in turn under the L2 scheduler and posts a pass/fail table to the job summary. It stops only labs it started. | Catches image, appliance or CML drift before another server's session hits it. | A self-hosted GitHub runner on cortex (reaches CML 198.18.128.10 and the appliances). Repo secrets for CML credentials. | Run the workflow manually once per recipe; check that it restores the starting lab state. | S | [#21](https://github.com/dr-stutters/cml-mcp-server/issues/21) |

## Later
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| L13 ✅ v0.7.0 (first slice: hostapd 802.1X + 9800-CL; CAPWAP APs don't exist in CML) | **`wireless` recipe**: cat9800-CL WLC, CML wireless-ap and wireless-client nodes, an unmanaged switch, WLC RADIUS to ISE (PSK, then 802.1X EAP-TLS with the L11 cert). Wireless pcap (`/wireless/pcap`) behind L5. | ISE wireless policies and CatC wireless assurance, both untestable today. | 3 licences. ISE NAD for the WLC. Windows CA (from L11). Needs a check that the CML 2.10 wireless-ap model joins a 9800-CL. | Live: AP joins the WLC, the client associates and authenticates against ISE; wireless capture summary. | L | [#22](https://github.com/dr-stutters/cml-mcp-server/issues/22) |
| L14 ✅ v0.7.0 | **`fmc-local` recipe (FMCv in CML)**: FMCv (eval licence) plus 1–2 FTDv on a private segment. A resettable FMC for destructive fmc-server tests (HA break, deploy failures, version skew) that leaves the dCloud FMC alone. | Lets the fmc server's dangerous tools run live without touching shared appliances. Also gives a second FMC version for core G6. | 2–3 node licences (fine on the 70-node Enterprise licence). FMCv takes about 32 GB RAM and a 30–45 min first boot. The FMCv 90-day eval licence. | Live: build, wait (console_pattern), register an FTD, deploy, run the fmc server's live suite against it. | L | [#23](https://github.com/dr-stutters/cml-mcp-server/issues/23) |
| L15 (v0.6.0 underlay; v0.7.0 unique cat9000v serials; CatC fabric provisioning test open) | **`fabric` recipe (SD-Access-style)**: 3× cat9000v (border/control plane plus 2 edges), a fusion router and a client, for CatC fabric provisioning tests. | CatC SDA workflows are the largest untested area in the catc server. | 5–6 licensed nodes and about 60 GB RAM. **Unblocked (2026-10-15):** the controller is now Enterprise (70 nodes). Still needs a check that CatC supports cat9000v as a fabric node. | Live: CatC discovers the 3 switches, a fabric site is provisioned, and a client authenticates via ISE. | L | [#24](https://github.com/dr-stutters/cml-mcp-server/issues/24) |
| L16 ✅ v0.7.0 | **`cml_replicate_site` prompt**: reads a site from CatC (devices, links, roles), ISE (NADs, RADIUS) and FMC (FTDs, interfaces), maps them to CML node definitions within the licence budget (L2) and builds a scaled-down replica with `cml_build_lab`, with the gaps listed explicitly. Depends on core [C2](https://github.com/dr-stutters/stutters-mcp-core/issues/7), [C9](https://github.com/dr-stutters/stutters-mcp-core/issues/14). | Reproduce a customer's site in a lab before a change. | The catc, ise and fmc servers (read tools only). Enough licences for the replica. | Live: replicate the dCloud CatC site plus FMC/ISE into a 5-node lab; unit: mapping table. | L | [#25](https://github.com/dr-stutters/cml-mcp-server/issues/25) |

## Added overnight 2 (step 4)
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| L23 ✅ v0.8.0 | **Long CML tools as MCP background tasks** (core C12): upload, waits, verify, captures with `task=True` | HTTP clients time out on 10-45 min calls (1.9 GB upload 549 s, FMCv converge 30 min) | none | unit: task registration; live: converge as a task | S | [#56](https://github.com/dr-stutters/cml-mcp-server/issues/56) |
| L24 ✅ v0.7.0 | **Safety guard and console hardening** (review follow-ups): guard reuses the tool's lab resolution, console `all` toggle only for non-admins, `server_version` in status | robustness of the production rails | none | unit | S | [#57](https://github.com/dr-stutters/cml-mcp-server/issues/57) |
| L25 ✅ v0.9.0 | **Recipe copies verify with their recorded substitutions**: cml_build_recipe writes `cml-mcp-recipe: {recipe, substitute}` into the lab notes, cml_verify_recipe applies it | operator pass: verifying a copy probed the recipe's own addresses (another lab's devices; a false PASS when that lab runs) | none | unit: marker round trip, verify applies it, wrong-recipe refusal; live: copy build + verify | S | [#63](https://github.com/dr-stutters/cml-mcp-server/issues/63) |
| L26 ✅ v0.9.0 | **Recipe hand-off keeps `${LAB_*}` references and names intact** | operator pass: 'reg key ********}', node='********-client' in the hand-off block | none | unit: every recipe's detail has no garbled masks | S | [#64](https://github.com/dr-stutters/cml-mcp-server/issues/64) |
| L27 ✅ v0.9.0 | **Section-aware config diff** (cml_diff_node_config): IOS-rendered defaults hidden, block order ignored, changes per section | operator pass: 4 changed lines reported as +38/-4 | none | unit: IOS day-0 vs running fixture; live: mcp-cml-ospf r1 | M | [#65](https://github.com/dr-stutters/cml-mcp-server/issues/65) |
| L28 ✅ v0.9.0 | **RAM in licence plans and start previews** | 'can this start now?' ignored RAM, the practical limit with 70 licences | none | unit: short RAM blocks; live: plan fmc-local | S | [#66](https://github.com/dr-stutters/cml-mcp-server/issues/66) |
| L29 ✅ v0.9.0 | **Guidance fixes**: wrong defaults in two descriptions, instructions name the newer workflows, BOOTED vs protocol convergence (`cml_check_reachability(wait_seconds)`) | operator pass: misleading descriptions, OSPF 2WAY right after 'converged' | core request for spec-tool examples | unit: descriptions match defaults | S | [#67](https://github.com/dr-stutters/cml-mcp-server/issues/67) |
| L30 ✅ v0.9.0 | **cml_get_resource_usage per lab and top nodes** | 'what's using the RAM' took 7 calls | none | unit + live | S | [#68](https://github.com/dr-stutters/cml-mcp-server/issues/68) |
| L31 ✅ v0.9.0 | **Capture findings and grouped highlights** | 13 identical DHCP Discovers, no 'no Offer' finding | none | unit: decoder fixtures | M | [#69](https://github.com/dr-stutters/cml-mcp-server/issues/69) |
| L32 ✅ v0.9.0 | **Token trims**: IOS route legend, compact licence block, short boot_minutes in the recipe list | about 900 chars per 'show ip route', duplicated licence data in every preview | none | unit | S | [#70](https://github.com/dr-stutters/cml-mcp-server/issues/70) |
| L33 ✅ v0.9.0 | **cml_stop_labs**: several labs, one preview | 'stop everything I'm not using' = 1 + 2 calls per lab | none | unit + live on own labs | S | [#71](https://github.com/dr-stutters/cml-mcp-server/issues/71) |

## Events (pull-only)
The suite's servers are **pull-only** ([core ADR-003](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/adr/003-no-event-ingestion.md)):
they query the platform's own history on demand and never receive pushed data. For CML that means:

| On-demand lookup | What it gives | Tool |
|---|---|---|
| Lab events `GET /labs/{id}/events` | Lab, node and link state changes per lab (start, stop, boot, wipe) | `cml_list_lab_events` (exists) |
| Node console logs | Device-side messages (syslog lines on the console, boot progress, OSPF/interface changes) | `cml_get_node_console_log(grep=...)` (exists) |

Not planned: the CML websocket stream (former L7, [#16](https://github.com/dr-stutters/cml-mcp-server/issues/16))
and the push-event relay (former L22, [#31](https://github.com/dr-stutters/cml-mcp-server/issues/31)); both were
event ingestion, dropped with core 0.3.0.

## Workflow prompts owned by this server
| Prompt | What it does | Other servers used | Bucket |
|---|---|---|---|
| `cml_build_test_lab` (L1) | Recipe → licence plan → build or start → converge → verify → hand-off block for the product server | none (its output feeds fmc, catc and ise) | Now |
| `cml_replicate_site` (L16) | CatC/ISE/FMC site → scaled-down CML replica | catc, ise, fmc | Later |

## Production gate (server-specific)
Server-specific items (each is an issue under the `Production gate` milestone):

| # | Item | Why | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| L17 ✅ v0.6.0 | **Non-admin CML account support**: run every tool as a non-admin user. Fall back where admin-only endpoints fail (`/nodes` across all labs for licence accounting, `/system/*` health and stats, `/users`, external connectors). `cml_status` reports the role. Document the least-privilege setup (a user plus a group with lab access) for core [G3](https://github.com/dr-stutters/stutters-mcp-core/issues/20). | Production and shared controllers won't hand an MCP server the admin account. | **Unblocked (2026-10-15):** the controller is now Enterprise, so extra users and groups can be created (EVAL refused them). | Live: the full live suite as a non-admin user; unit: 403 fallbacks with respx. | M | [#26](https://github.com/dr-stutters/cml-mcp-server/issues/26) |
| L18 (skipped overnight 2: needs CML 2.7-2.9) | **Version matrix CML 2.7–2.10**: feature detection from the controller's OpenAPI (sample labs, external connector API, `auth_extended`, smart annotations, wireless pcap) so tools degrade with a clear message. A live test run per version. Feeds core [G6](https://github.com/dr-stutters/stutters-mcp-core/issues/23). | Customers run older controllers; 2.7–2.9 are untested today. | **Blocked:** CML 2.7/2.8/2.9 controllers (a second CML VM, a customer lab, or dCloud). Only 2.10 exists here. | Live suite on each version; a spec diff report across the versions' `openapi.json`. | L | [#27](https://github.com/dr-stutters/cml-mcp-server/issues/27) |
| L19 ✅ v0.6.0 | **Binary image upload path**: `cml_upload_image` (dangerous tier, admin) uploads from an allow-listed directory on the server host (`CML_IMAGE_DIR`), never through the MCP payload, as a chunked multipart `POST /images/upload` with a SHA-256 check. Then `cml_create_image_definition` (preview-first). The alternative of SCP to the controller's drop folder (`/list_image_definition_drop_folder`) is evaluated as part of this. | Today the only CML operation that can't be done through MCP at all. Customers need it to bring their own image versions (also needed for L18 and recipes on new releases). | Image files on the server host (cisco.com downloads). An admin account. Disk space on the controller. | Live: upload a small image (e.g. an Alpine/net-tools qcow2 copy) under a new definition, boot it, delete it. Unit: chunking and checksum. | M | [#28](https://github.com/dr-stutters/cml-mcp-server/issues/28) |
| L20 ✅ v0.6.0 | **CML safety rails** on top of core [G7](https://github.com/dr-stutters/stutters-mcp-core/issues/24): `CML_PROTECTED_LABS` (name/tag patterns that dangerous tools refuse), an `mcp-managed` tag (wipe/delete only tagged labs unless `force_unmanaged`), maximum nodes per build, a `cml_configure_node` line deny-list (`write erase`, `reload`, `format`, `delete`, FTD `configure manager delete`). TLS verification on by default and SSH console host keys pinned (`CML_CONSOLE_KNOWN_HOSTS`). Lab mode keeps `CML_VERIFY_SSL=false`. | Production controllers hold other people's labs. A typo in a lab name must not wipe them. | The CML CA cert or the controller's cert for verification. | Unit: refusal cases and deny-list. Live: protected-lab refusal on `mcp-test-seed`; TLS on with the controller cert pinned. | M | [#29](https://github.com/dr-stutters/cml-mcp-server/issues/29) |
| L21 ✅ v0.6.0 | **Recipe secrets scrub**: recipes, notes and tests carry lab passwords, the FMC reg key and RADIUS keys in git. Replace them with `${VAR}` references resolved at build time (env or `*_FILE`, core [G4](https://github.com/dr-stutters/stutters-mcp-core/issues/21)). `cml_list_recipes` never returns secret values. Scrub the history before public release (core [G9](https://github.com/dr-stutters/stutters-mcp-core/issues/26)). | Lab credentials must not ship in a public repo or reach a model's context. | none | Unit: resolver plus a grep-based CI check for known secret patterns. Live: build `catc-routers` from env-provided secrets. | S | [#30](https://github.com/dr-stutters/cml-mcp-server/issues/30) |

Core gate items that also apply to this server: [G1](https://github.com/dr-stutters/stutters-mcp-core/issues/18) OAuth,
[G2](https://github.com/dr-stutters/stutters-mcp-core/issues/19) per-user roles,
[G3](https://github.com/dr-stutters/stutters-mcp-core/issues/20) least privilege (via L17),
[G4](https://github.com/dr-stutters/stutters-mcp-core/issues/21) secrets (via L21),
[G5](https://github.com/dr-stutters/stutters-mcp-core/issues/22) observability,
[G6](https://github.com/dr-stutters/stutters-mcp-core/issues/23) version matrix (via L18),
[G7](https://github.com/dr-stutters/stutters-mcp-core/issues/24) safety rails (via L20),
[G8](https://github.com/dr-stutters/stutters-mcp-core/issues/25) security scanning (including a review of the
`cml_run_commands` allow-list), [G9](https://github.com/dr-stutters/stutters-mcp-core/issues/26) public release.

## External services and prerequisites
| Service / prerequisite | Needed for (items) | Provided by | Network path | Status |
|---|---|---|---|---|
| CML 2.10 controller, admin account | everything | dCloud lab (198.18.128.10) | cortex → CML :443 (API, wss) and :22 (console server) | ✅ in place |
| **CML licence: Enterprise, 20 + 50 expansion = 70 running nodes, extra users** | L2 reads the capacity from `/licensing`; unblocks L15 (fabric), L17 (non-admin), several recipes at once, L12 without stopping labs | Cisco Smart Account (registered 2026-10-15, authorization renews monthly) | CML → Cisco Smart Licensing (outbound HTTPS) | ✅ in place |
| Second CML controller (older version) | **Unblocks** L18 (2.7–2.9 matrix); also gives L15 and L17 room | Another CML VM or a customer lab | cortex → controller :443/:22 | ❌ unavailable |
| Node images: ftdv, fmcv, cat8000v, cat9000v-uadp, cat9800, wireless-ap/client, ubuntu, alpine, iol | L1, L3, L10, L11, L13, L14, L15 | CML image library | — | ✅ present |
| FMC (dCloud 198.18.134.76), device and eval licences | L1/L3 (ftd-fmc), L10 (2 more FTDs) | dCloud FMC | FTD mgmt (System Bridge) → FMC :8305 | ✅ in place (headroom for 2 more FTDs to confirm) |
| ISE (198.18.134.35) as RADIUS for recipes | L3, L5, L11, L13 | dCloud ISE | lab switch/WLC → ISE UDP 1812/1813; ISE → switch CoA UDP 1700 | ✅ in place |
| Catalyst Center (198.18.128.11) | L3 (catc-routers), L15 | dCloud CatC | CatC → routers SSH/SNMP/NETCONF | ✅ in place |
| Windows lab CA (ADCS) for client certs | L11, L13 | `Windows_Server` MCP (`win_install_adcs_ca`, `win_sign_csr`) | cortex → Windows (WinRM); ISE trusts the CA | ⏳ to set up |
| Self-hosted GitHub Actions runner on cortex | L12 | cortex | runner → GitHub (outbound HTTPS); runner → CML and appliances | ⏳ to set up |
| Address block 198.18.128.150–.159 | all recipes; L10 needs .155–.157 | dCloud flat /18 | System Bridge | ✅ reserved (.151–.154 used) |
| Image files for upload | L19 | cisco.com downloads | onto the server host | ⏳ when needed |

## Not planned
- **Event ingestion** (CML websocket stream L7, push-event relay L22, receivers): servers are pull-only (core ADR-003). Use `cml_list_lab_events` and console logs on demand.
- **Licensing registration/reservation, users/groups/resource pools writes, maintenance mode, notices, lab repos,
  telemetry, compute host admin:** one-off admin work, often dangerous. Left to `cml_api_call` (GET at the read tier,
  other methods at the dangerous tier).
- **Raw pcap download:** binary and not useful in a model's context. L5 gives decoded summaries instead.
- **Node-definition authoring** (custom YAML definitions): rare and admin-only. Left to `cml_api_call`. Image upload is L19.
- **VNC, console and pcap access keys:** hidden on purpose and never returned.
- **Syslog from lab devices into this server:** console logs cover test labs. Product-side syslog belongs to the fmc server.
- **pyATS/Genie as a dependency:** the console path stays dependency-light (asyncssh). Parsers are added per need.
- **Sharing labs with groups:** now testable (Enterprise licence). Revisit with L17.


## Wave 3 (planned 2026-10-16)
See the [suite roadmap](https://github.com/dr-stutters/stutters-mcp-core/blob/main/ROADMAP.md#wave-3-planned-2026-10-16).

| # | Item | Milestone |
|---|---|---|
| [L34](https://github.com/dr-stutters/cml-mcp-server/issues/81) | `ise-fmc-identity` recipe (802.1X client behind the FTD) | Next |
