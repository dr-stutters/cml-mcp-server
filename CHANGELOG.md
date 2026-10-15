# Changelog

## Unreleased

### Fixed
- cat9000v serials: every cat9000v reported CMLUADP, so Catalyst Center merged multi-switch labs (e.g. `fabric`) into one
  device. `cml_build_lab` / `cml_build_recipe` now give each cat9000v without its own `conf/vswitch.xml` a unique, stable serial
  (shown in the preview as `cat9000v_serials`); `cml_verify_recipe` fails on duplicate serials in a lab and warns about
  collisions with cat9000v in other running labs.

### Changed
- Safety guard (L24): checks exactly the lab the tool resolved (no second lookup; no rename window), the console
  server's `all` toggle only for non-admin accounts, `cml_status` reports `server_version`.

### Added
- Site replica (L16): `cml_plan_replica` (read) maps devices to CML node definitions (light: IOL; faithful: cat9000v,
  cat8000v, NX-OS 9000v, FTDv, FMCv, ...) within a node/RAM budget and only to installed images, keeps firewalls/routers/WLCs
  before switches, lists gaps (CAPWAP APs, Meraki) and returns a `cml_build_lab` spec; the `cml_replicate_site` prompt chains
  Catalyst Center (`catc_get_site`, `catc_list_devices`, `catc_get_physical_topology`), FMC (`fmc_list_devices`) and ISE
  (`ise_list_nads`) into it. Other servers' tool manifests in `tests/manifests/` check the prompt's references; `cml.json`
  is this server's manifest for theirs.
- Recipe `fmc-local` (L14): a private FMCv 10.0.1 (198.18.128.192, evaluation licence) with an FTDv (.193) that registers to it
  from day 0, for destructive fmc-server tests that must not touch the lab FMC. Verify: FTD `show managers` -> the local FMC,
  FMC HTTPS and FTD SSH from the server. Lab export `labs/mcp-cml-fmc-local.yaml`. `ftd-ha`'s suggested outside addresses moved off .192/.193.
- Recipe `wireless` (L13): Catalyst 9800-CL WLC (WLAN mcp-lab-dot1x, RADIUS to ISE) + CML's hostapd `wireless-ap` doing
  WPA2-Enterprise with RADIUS straight to ISE + a `wireless-client` authenticating with PEAP-MSCHAPv2; verify contract
  (11 checks, incl. the client passing data once authorized; the 9800 is checked over the network). CML's wireless-ap is not a CAPWAP AP, so it can't join
  the 9800. Lab export `labs/mcp-cml-wireless.yaml`.
- `cml_capture_wireless` (write): capture the simulated 802.11 medium at a wireless node and decode it. The pcap
  decoder now reads 802.11 (radiotap or bare; CML 2.10 labels bare frames as radiotap): beacons/probes with SSID,
  auth/assoc status, deauth/disassoc reasons, EAPOL over LLC/SNAP with EAPOL-Key 4-way/group handshake messages.
  CML captures the frames a node transmits: capture at the AP for its side, at the client for the station side.

## 0.6.0 - 2026-10-15

Production gate (L17, L19, L20, L21; L18 skipped) and the fabric recipe (L15 first slice). 65 -> 69 tools
(read 38, write 23, dangerous 8 incl. `cml_api_call`). Core pinned v0.10.0.

### Added
- Recipe `fabric` (L15, first slice): SD-Access-style underlay for Catalyst Center - border/control plane + 2 edges
  (cat9000v-uadp, OSPF, Loopback0 RLOCs, MTU 9100, management .197-.199), a fusion router serving DHCP for the fabric
  client pool and an unassigned client port; verify contract with 23 checks (OSPF adjacencies, RLOC reachability,
  SSH/SNMP from the server). Lab export `labs/mcp-cml-fabric.yaml`.
- Image upload (L19): `cml_get_image_files` (read), `cml_upload_image` (dangerous: streamed multipart from the
  allow-listed `CML_IMAGE_DIR`, symlink escapes refused, SHA-256 / name / controller-disk checks),
  `cml_create_image_definition` (write), `cml_delete_image` (dangerous; refused while nodes use it). Admin-only in CML.
- Non-admin CML accounts (L17): `docs/least-privilege.md` (read account `mcp-cml-viewer`, write account
  `mcp-cml-operator`, groups, resource pools), `scripts/seed_lab.py --least-privilege`, live test
  `tests/live/test_least_privilege.py` (read tier as the viewer via core's `read_tier_report`, write tier as the
  operator). `cml_status` reports the account's resource pool.
- Recipe secrets scrub (L21): recipes reference `${LAB_*}` instead of carrying lab passwords, keys and
  communities. They are filled at build/verify time from `LAB_*` environment variables or `CML_LAB_SECRETS_FILE`,
  with a clear error naming any missing variable; previews, listings and annotations keep the references.
  `scripts/check_secrets.py` (CI job `secrets-scan`) fails on known lab values (from `LAB_*` repo secrets)
  and on literal credentials in recipe/lab data. A server middleware replaces any resolved lab secret value with
  its `${LAB_*}` reference in every tool result and error (a recipe lab's day-0 configs hold the real values).

- CML safety rails (L20, docs/safety.md): `CML_PROTECTED_LABS` (no changes to matching labs), `CML_MANAGED_LABS`
  (dangerous tools only on matching labs), blast radius = nodes affected on every change (core
  `MCP_MAX_BLAST_RADIUS`), a `cml_configure_node` deny-list for destructive device commands (on by default;
  `CML_CONFIG_DENY` adds a regex), certificate pinning for self-signed controllers (`CML_TLS_CHECK_HOSTNAME=false`
  with `CML_CA_BUNDLE`) and `scripts/pin_controller.py` (certificate + console SSH host key). `cml_status`
  reports `security`.

### Changed
- Licence planning and start/build previews work for non-admin accounts: per-lab node counts when `/nodes`
  is refused (`scope` says the count is partial), and the account's resource pool as the limit when it is
  tighter or `/licensing` isn't readable (only the account's own labs are proposed for stopping then).
- `cml_get_licensing` explains that licensing is admin-only.
- Core pinned to v0.10.0.

### Fixed
- Consoles of labs shared with a non-admin account were "not found": the console server lists only the
  account's own labs until `all` is toggled, which the server now does.

## 0.5.0 - 2026-10-15

Roadmap "Next" (L8-L12). 59 -> 65 tools (read 35 -> 38, write 19 -> 22, dangerous 5).

### Added
- Link scenarios (L8): `cml_get_link_scenarios`, `cml_apply_link_scenario` (wan-good, wan-satellite,
  lossy-wifi, brownout; `flap` = timed down/up cycles as a cancellable background job that always leaves
  the link up), `cml_clear_link_scenarios`. Each scenario states the expected round-trip ping change.
- Topology export and annotations (L9): `cml_export_topology` (Mermaid / draw.io / JSON with addresses
  from day-0 configs, CML snooping or the CLI), `cml_list_annotations`, `cml_annotate_lab`. Recipe labs
  are built with annotations (purpose, address plan, where the credentials are kept; never values).
- Recipe `ftd-ha` (L10): 2x FTDv cabled for an FMC HA pair (direct failover and state links), not
  registered to any manager.
- Recipe `ise-access` gains an Ubuntu EAP-TLS client (wpa_supplicant, a lab CA it generates itself) and
  IBNS 2.0 on the switch (802.1X first, then MAB) (L11).
- Recipe copies: `cml_build_recipe(title, substitute)` and `cml_verify_recipe(lab, substitute)`.
- `scripts/recipes.py ci` and the `recipes-verify` workflow for a self-hosted runner (manual, off by
  default), with `docs/ci-runner.md` (L12).

### Changed
- `cml_check_reachability` reports the average round-trip time (`rtt_avg_ms`).
- `scripts/recipes.py build|swap` build through `cml_build_recipe`.
- Core pinned to stutters-mcp-core v0.6.0 (spec examples in `cml_get_definition`, opt-in safety rails
  and per-user roles; nothing changes unless configured).

### Fixed
- FTD console: a rejected command was re-typed by FTD after "Syntax error" and the session hung until
  the timeout; it is now cleared and the error returned at once.
- `cml_list_recipes` crashed on recipes whose nodes carry extra config files as a mapping.

## 0.4.0 - 2026-10-15

Roadmap "Now" (L1-L6). 52 -> 59 tools (read 30 -> 35, write 17 -> 19, dangerous 5) and the first MCP prompt.

### Added
- Prompt `cml_build_test_lab(recipe, reuse)`: recipe -> licence plan -> build/start -> converge -> verify ->
  hand-off block for the FMC / Catalyst Center / ISE server (L1).
- `cml_list_recipes` (no secret values), `cml_build_recipe` (L1); recipes are packaged in `cml_mcp/recipes/`.
- `cml_plan_licences`: licences per lab, what a lab or recipe needs, the smallest set of labs to stop (L2).
  Capacity is read from `/licensing` (base licence + `CML_NODE_COUNT` expansion; 5 in evaluation mode).
- `cml_verify_recipe` and `verify:` contracts in every recipe (booted, addresses, ping matrix, console,
  TCP and SNMP probes); `scripts/recipes.py verify [--json]`, `pytest -m live_recipes` (L3).
- `cml_summarize_capture` and `cml_capture`: a dependency-free pcap decoder (ARP, ICMP, TCP, UDP, OSPF,
  DHCP, RADIUS incl. CoA and Cisco AV-pairs, EAP/EAPOL) with secrets dropped (L5).
- `cml_diff_node_config` (running config vs day-0, startup, another node or a baseline) and
  `cml_diff_lab(running_configs=true)` (L6).
- `scripts/recipes.py plan|swap` (swap asks before stopping labs); `CML_CONSOLE_LOCK_WAIT`.

### Changed
- Console sessions: one per node per process, with a "busy" error after `CML_CONSOLE_LOCK_WAIT` (60 s);
  devices are logged out on close; a login prompt mid-command re-logs in and reports `SessionLost`
  (the command is never re-sent) (L4).
- `cml_wait_for_converged` adds a hint for cat9000v (BOOTED before it forwards).
- Start/build previews name the labs to stop when licences run out.
- `CML_NODE_LICENSE_LIMIT` is optional (detected); it still overrides.
- Core pinned to stutters-mcp-core v0.3.0 (prompts; pull-only, no event ingestion).

### Fixed
- Secret masking of CLI output works line by line: a `key 1` line no longer swallows the next line
  (which left e.g. an SNMP community in clear); OSPF/NTP authentication keys, IKEv2 pre-shared keys,
  SNMPv3 user secrets and trap communities are masked.
- `cml_diff_lab` no longer shows plain-text day-0 passwords in config diffs.

## 0.3.0 - 2026-10-15

Phase 2: gap analysis against the CML 2.10 OpenAPI (docs/GAP-ANALYSIS.md) and hardening for the
FMC / Catalyst Center / ISE builders, live-tested with FTDv 10.0, cat8000v, cat9000v-uadp, IOL and Alpine.

### Added
- `cml_check_reachability`: ping matrix from nodes to targets with per-OS syntax (IOS/IOS-XE, NX-OS,
  Linux, FTD incl. `ping system` on the management interface).
- `cml_list_external_connectors`, `cml_list_sample_labs`, `cml_load_sample_lab`.
- `cml_build_lab`: `files` (other config files), `credentials` (console login / pyATS), `parameters`,
  `x`/`y`, `wait`; external-connector names validated; node-licence use in the preview.
- `cml_configure_node`: `mode='exec'` (FTD CLISH `configure manager add ...`), `answer_questions`,
  `line_timeout`.
- `cml_get_layer3_addresses(source='cli'|'both')`: addresses read from each node's CLI.
- `cml_wait_for_converged(console_pattern=...)`: wait for a later console message after BOOTED.
- `cml_get_node_console_log(grep=...)`; `cml_update_node` login fields (`login_username`,
  `login_password`, `enable_password`).
- `CML_NODE_LICENSE_LIMIT`: start/build/node-start previews refuse to exceed the licence; CML's
  "N of N node licenses are in use" becomes an error naming the labs that hold them.
- `recipes/` (now `src/cml_mcp/recipes/`: ftd-fmc, catc-routers, ise-access) and `scripts/recipes.py`.

### Changed
- Console: os-aware login from the pyATS testbed (no `enable` on FTD), NX-OS POAP skipped, terminal
  escape codes stripped from console logs, timed-out commands are interrupted with Ctrl-C.
- Auto interface allocation skips FTDv/ASAv `donotuse` slots.

### Fixed
- FTD: login looped on the forced password-change prompt; now a clear error.
- Commands that ask a question (`[confirm]`, `[yes/no]`) no longer hang until the timeout.
- `cml_get_layer3_addresses` description wrongly said labs need traffic only; link-local addresses
  are no longer reported by CLI discovery.

## 0.2.1 - 2026-10-15

- Core pinned to stutters-mcp-core v0.1.1. It brings nested secret masking in the audit log and
  stops masking flag-like values. Startup now survives configuration errors (`cml_status`
  reports them).
- Added `.dockerignore` (from the core template), so `.env`, tests and git data stay out of the
  image build context.
- The Dockerfile now matches the core template (the template copies `LICENSE` itself now).

## 0.2.0 - 2026-10-15

- Device CLI through the CML console server (SSH to the controller, `open /lab/node/0`; new
  dependency `asyncssh`):
  - `cml_run_commands` (read): show, ping and traceroute on several nodes in parallel. Commands
    are allow-listed, and redirection and chaining are refused.
  - `cml_configure_node` (write, preview-first): configuration lines with per-line rejection
    reporting and an optional `write memory`.
  - Handles RETURN prompts, the setup dialog, login, enable, `--More--` paging, and late syslog
    output. Credentials come from the lab's pyATS testbed.
- New settings: `CML_CONSOLE_PORT`, `CML_CONSOLE_KNOWN_HOSTS`.

## 0.1.0 - 2026-10-15

First release, built on stutters-mcp-core 0.1.0 and tested against CML 2.10.0.

- 46 tools: 25 read, 15 write (preview-first), 6 dangerous.
- JWT login (`/api/v0/auth_extended`, falling back to `/authenticate`) with expiry taken from the
  token; `CML_TOKEN` for a pre-issued JWT.
- The controller's OpenAPI document powers `cml_search_spec`, `cml_get_definition` and `cml_api_call`.
- Name-or-id resolution for labs and nodes; links by id or `r1<->r2` endpoints.
- Task tools: `cml_build_lab` (compact spec -> lab, automatic interface allocation),
  `cml_wait_for_converged` (with progress), `cml_diff_lab` (lab vs lab or saved YAML).
- Console, VNC and pcap access keys are never returned. pyATS passwords are masked in nodes,
  exports and testbeds.
- Docker image (non-root, read-only rootfs) for the HTTP transport.
