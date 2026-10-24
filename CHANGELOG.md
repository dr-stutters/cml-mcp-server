# Changelog

## 0.12.2 - 2026-10-24

### Security
- fastmcp, fastmcp-slim and fastmcp-tasks 4.1.0 -> 4.1.3 (GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4). No tool changes.

## 0.12.1 - 2026-10-23

### Added
- **Recipes `cat-sdwan-controllers` and `cat-sdwan-fabric` (L60, cat-sdwan W0).** Catalyst SD-WAN 20.18.3: Manager,
  Validator and Controller with the lab AD CS root as their Enterprise root CA (cloud-init `zcloud.xml`, the admin
  password as `${LAB_SDWAN_ADMIN_HASH}`, organisation `${LAB_SDWAN_ORG}`), on an inet and an mpls transport joined
  by an Alpine router; the fabric adds hub1, br1 and br2 (cat-sdwan-edge 17.18.02, controller mode, colours mpls and
  biz-internet) and an Ubuntu host in VPN 10 behind each. Edges are activated after boot with a chassis number and
  the token the Manager mints at the serial file upload (no recipe can carry it). Verify contracts check BFD,
  control connections and host-to-host reachability over the overlay.

### Fixed
- `scripts/check_secrets.py` no longer reads the XML element `<last-password-change-time>` as a password value.

## 0.12.0 - 2026-10-22

### Added
- **`http` and `dns` verify probes, matching the CML Cookbook check types of the same names.** A recipe's
  `verify.probes` can now prove application-level verdicts from a Linux node's console:
  `{name, node, http: {url, method, insecure, expect: {status, pattern, not_pattern | no_response}}}` runs curl
  (else GNU wget) without following redirects; `{name, node, dns: {name, record, server, expect: {rcode, answers,
  not_answers | no_response}}}` runs dig (else drill, host or nslookup). Pass rules follow the Cookbook's
  `docs/recipe-format.md`: http passes on `status` (default any 2xx) and the body patterns, or with `no_response`
  only when the connection is refused, reset or times out; dns passes on `rcode` (default NOERROR) with every
  `answers` entry present and no `not_answers` entry (NOERROR with no `answers` needs one answer), or with
  `no_response` only when the query times out. Each is retried until it passes or its `timeout` (default 180 s)
  runs out; results carry the tool, what was seen, why it failed, the output tail and the number of tries. The
  commands are built from validated fields (`cml_mcp/appchecks.py`), never from caller input.

## 0.11.0 - 2026-10-21

### Fixed
- `labs/mcp-cml-wireless.yaml`: the WLC's RADIUS key and the hostapd AP's RADIUS shared secrets referenced
  `${LAB_FTD_REG_KEY}` instead of `${LAB_RADIUS_SECRET}` (the two held the same value until the lab rotated them).
  A unit test (`tests/unit/test_lab_secret_refs.py`) now checks that lab exports and recipes use
  `LAB_FTD_REG_KEY` only for FMC registration and `LAB_RADIUS_SECRET` never for it.

### Added
- **`cml_import_lab` fills `${LAB_*}` lab secrets on the server (part of L42, #17).** A topology YAML can carry
  `${LAB_*}` references in its nodes instead of the values, e.g. a CML Cookbook file rendered with
  `admin_password='${LAB_FTD_ADMIN_PASSWORD}'` (`"AdminPassword": "${LAB_FTD_ADMIN_PASSWORD}"` in the FTD day-0 JSON,
  and the pyATS login). They are filled from the `LAB_*` environment or `CML_LAB_SECRETS_FILE`, as for recipes, only in
  the YAML sent to CML (the parsed topology is filled and re-serialised, so values are YAML-quoted). The preview lists
  which secret goes into which node (`lab_secrets`), and a missing variable blocks it by name (also at confirm time).
  The tool call, preview, confirm token, result and audit log carry only the placeholders, and CML's warnings and
  errors are redacted. Lab notes and annotations keep their references, and YAML without node placeholders is sent
  unchanged.
- **`cml_build_lab` fills `${LAB_*}` lab secrets on the server (L42, #17).** A node's `config`, `files` and
  `credentials` can carry `${LAB_*}` references (`"username admin privilege 15 secret ${LAB_CLI_PASSWORD}"`), filled
  from the `LAB_*` environment or `CML_LAB_SECRETS_FILE` only in the topology sent to CML. The preview lists which
  secret goes into which node (`lab_secrets`) and a missing variable blocks the build by name (also at confirm
  time). The tool call, preview, confirm token, result and audit log carry only the references; CML's warnings and
  errors, and preview blockers and notes that quote a filled config (an external connector's name), are redacted.
  The lab description, labels and tags stay as written. The specs are validated with their references, so a
  validation error can't quote a value.
- **Recipes outside the package: `CML_RECIPE_DIRS` (L42, #17).** Comma- or `:`-separated directories of
  `<name>.yaml` recipes (e.g. a recipe checkout mounted read-only into the container), used by `cml_list_recipes`,
  `cml_build_recipe`, `cml_verify_recipe`, `cml_run_recipe_action` and `cml_plan_licences`, so a PR's new recipe can
  be built and verified from the running server with its secrets filled server-side. Read on every call (no
  restart). Trusted like the package: verify probes and actions run console commands, so only the operator names
  the directories and no tool takes recipe YAML. A packaged recipe wins on a name clash, and the first directory
  over a later one; `cml_list_recipes` shows an extra recipe's `source` file and lists unused files under `skipped`
  with why (a clash, invalid YAML by line number only, not a recipe, a missing directory).
- **Firewall SD-WAN recipes (fmc-mcp-server F52, #109).** `ftd-sdwan-single` (`mcp-sdwan-t1`: hub + 3 spokes),
  `ftd-sdwan-dual-hub` (`mcp-sdwan-t2`: primary + backup hub, 2 spokes) and `ftd-sdwan-ha-hub` (`mcp-sdwan-t3`: HA-pair
  hub, 2 spokes). Every FTDv has three WAN transports through IOL carrier routers (mpls, inet, lte) and an Alpine inside
  host; management 198.18.128.200-211 through the System Bridge; day 0 points each FTD at FMC 198.18.134.76 with
  `${LAB_FTD_REG_KEY}`. The verify contract checks each FTD's manager and management reachability and that every
  carrier's access links are up.
- **`cml-mcp-server check` preflight (L37, #4; core C21).** Runs without an MCP client: reachability and TLS
  trust of the controller API, the login (the client's own `/auth_extended` login, falling back to
  `/authenticate`; a CML 403 on login is reported as bad credentials), the CML version against the tested matrix
  (2.10; 2.7 minimum), the API user's admin flag (`GET /users/<id>`) against the enabled tiers (warns when an
  admin sits behind a read-only server, and when the dangerous tier is on for a regular user: image upload and
  other users' labs need an admin) and, with writes on, the node licences the account may start (its resource
  pool, else the controller licence; warns at 0 free or unknown). Text or `--json`, `--strict`, `--instance`;
  exit 1 on a failure; every `CML_INSTANCES` controller. `serve --http` / `serve --stdio`. README quickstart
  for a release wheel (`uvx --from`) and for the image, with Claude Code / Claude Desktop config. PyPI
  publishing stays open (deferred).
- **Published image (L36, #3; core C22).** `release.yml` calls core `publish-image.yml`:
  `ghcr.io/dr-stutters/cml-mcp-server` for amd64 and arm64, cosign keyless signature, SPDX SBOM attestation;
  `<version>` + `latest` on releases, `<version>-rcN` + `rc` on pre-release tags. `docker-compose.yml` pulls it
  (`MCP_IMAGE_TAG`; `--build` still builds locally).
- **Shared-host guide and example (L38, #5).** `docs/deploying.md` (read-only defaults, per-user tokens and the
  audit log, the least-privilege account step by step, the node-licence budget shared by everyone using the
  server, several controllers with `CML_INSTANCES`, console access, Caddy TLS, upgrades and verifying
  signatures) and `examples/shared-host/` (server + Caddy, and a test override with two mocked controllers).
  Contract tests pin the tier defaults (`tests/unit/test_tier_defaults.py`).

### Changed
- Bundled core v0.14.0.
- **stutters-mcp-core is bundled into the package (L35, #1; core C20 / ADR-005).** The wheel, sdist and image
  carry core v0.13.0 (with the `tasks` extra's dependencies) as `cml_mcp._core`, so installing needs no git
  dependency and Docker needs no `CORE_READ_TOKEN`. The pin is `[tool.bundle-core]` (tag + commit + extras) in
  `pyproject.toml`; core's runtime dependencies are listed in the server's own. `scripts/bundle_core.py` vendors it
  (`vendor`, after a clone), checks for drift (`check`) and moves the pin (`update --tag`). Code, tests and scripts
  import `cml_mcp._core`; importing the package without the bundle says how to fix it.
- `cml_status` reports the bundled core version (`server.core_version`).
- CI: the core `bundle-core.yml` job vendors, fails on drift, builds the wheel and sdist, installs the wheel
  with `pip install --no-index` in a clean venv and runs the unit + contract suite against it. The release
  builds the image from the bundled wheel.
- `recipes-verify.yml` builds the bundled wheel and runs `scripts/recipes.py` with it installed (no token).

- CI: the lab-secrets check (`ci.yml`) and `recipes-verify.yml` also get `LAB_DEFAULT_PASSWORD` (the lab's default
  node password, now long enough to be searched for).
- Docs: README "Live tests" lists the optional `CML_LIVE_*` / `CML_IMAGE_DIR` / least-privilege inputs (also in
  `.env.example`); lab-only paths in `labs/README.md`, `docs/least-privilege.md` and `.env.example` made generic.

### Removed
- The git source for stutters-mcp-core and `CORE_READ_TOKEN` (Dockerfile build secret, compose, workflows,
  `docs/ci-runner.md`).
- `scripts/identity_lab.py` (product side of the `ise-fmc-identity` recipe for one specific lab: fixed addresses,
  drives the ise/fmc servers through the suite's lab tooling). It moved to the suite's private lab repo; the
  recipe's `ise_side` / `fmc_side` and `src/cml_mcp/recipes/README.md` describe what must exist on ISE and FMC.

## 0.10.0 - 2026-10-16

Wave 3 theme A (user-based firewalling end to end), L34. 73 tools (+1 write).

### Added
- Recipe `ise-fmc-identity` (lab `mcp-cml-identity`): an Ubuntu 802.1X client (wpa_supplicant, PEAP-MSCHAPv2, validates ISE
  against mitchcloud-CA) logs in as AD user mcp-alice or mcp-bob on a cat9000v access switch (IBNS 2.0 dot1x, RADIUS + CoA to
  ISE, device tracking so ISE's session carries the framed IP); the client VLAN's gateway is an FMC-managed FTDv
  (`mcp-ftd-identity`, inside 10.10.34.1, outside 172.31.34.1, interface PAT) in front of an Ubuntu outside host with telnet (telnetd) and
  http. Verify (21 checks): ISE live session for the user from the switch, client address behind the FTD, telnet + http to the
  outside host through the FTD, FTD managed by FMC. `scripts/identity_lab.py up` creates the ISE NAD and the FMC side (zones,
  ACP + baseline rule, NAT policy, registration, interfaces, deploy) through the ise/fmc servers' own tools; `--delete` removes it.
- `cml_run_recipe_action` (write): run a recipe's packaged action, e.g. `ise-fmc-identity` `login-alice` / `login-bob` /
  `logoff`; the command always comes from the recipe. `scripts/recipes.py run <recipe> <action>`. `cml_list_recipes(recipe=...)`
  lists a recipe's actions.
- Verify probe `ise_session`: a live session in ISE's MnT ActiveList (user regex, NAS IP, framed IP regex), credentials as
  `${LAB_ISE_USERNAME}` / `${LAB_ISE_PASSWORD}`; never sent to a host substituted from lab notes. Console probes may run the
  recipe-installed read-only `mcp-check` helper.

## 0.9.2 - 2026-10-15

### Fixed
- `cml_set_link_condition` and `cml_apply_link_scenario`: the conditioning PATCH resets every impairment it isn't
  given, so the preview now has a `changes` diff (core 0.12.4 `field_changes(..., replace=True)`) listing those as
  `"removed": true` (e.g. loss when only latency is given, duplication when switching to `brownout`).

### Changed
- Core bumped to stutters-mcp-core 0.12.4. `cml_update_node` keeps its partial diff (its PATCH sends only the
  changed fields); `cml_set_node_config` keeps its unified config diff.
- Cross-server manifests (`tests/manifests/fmc.json`, `ise.json`, `catc.json`) refreshed from fmc 0.9.1, ise 0.7.2
  and catc 0.8.3.

## 0.9.1 - 2026-10-15

### Changed
- Core bumped to stutters-mcp-core 0.12.2 (0.11-0.12: per-instance write rules, audit log rotation, per-caller rate
  limit, `cml-mcp-server config`; list truncation warnings are kept next to a tool's own note).
- `cml_status`: the server version is now reported by core as `server.server_version`; the server's own
  `cml.server_version` (a stopgap until core had it) was removed.
- `cml_search_spec` / `cml_get_definition` descriptions use CML examples ('lab node', '/labs/{lab_id}/nodes/{node_id}')
  via the new `ServerSpec` options.

## 0.9.0 - 2026-10-15

Operator-eyes quality pass (L25-L33): 13 realistic tasks run through the MCP tools against the live controller; the
problems found are fixed. 71 -> 72 tools (read 39, write 25, dangerous 8 incl. `cml_api_call`).

### Fixed
- Recipe copies (L25): `cml_verify_recipe(recipe, lab=<copy>)` checked the recipe's *own* addresses (another lab's devices).
  `cml_build_recipe` now records `cml-mcp-recipe: {recipe, substitute}` in the lab notes and verify applies it; a lab built
  from another recipe is refused. Substitutions read from notes never redirect network probes (SNMP carries the real
  community): those are listed under `skipped` unless the caller passes `substitute`.
- Recipe hand-off (L26): `cml_list_recipes(recipe=...)` masked `${LAB_*}` reference names, prose ('(the') and node names
  ('eaptls-client'); references now come through, masking is whole-token.
- Config diffs (L27): `cml_diff_node_config` (default `view='changes'`) and `cml_diff_lab(running_configs=true)` report
  changes by section; IOS-rendered default sections and consumed day-0 commands are hidden (named in `hidden`), ACL /
  route-map / prefix-list / QoS / AAA server order still counts, nested blocks keep their path, vty ranges compare per line.
  Live: IOL +38/-4 -> +4/-0; a freshly booted cat9000v 208 added lines -> 1.
- RAM (L28): `cml_plan_licences`, `cml_start_lab` and `cml_build_lab` / `cml_build_recipe` previews compare the RAM needed
  with the controller's free memory and warn.

### Added
- `cml_stop_labs` (L33): several labs (or every running lab except `keep`) with one preview: owner, licences and RAM freed,
  protected labs refused; a failing stop doesn't stop the rest.
- `cml_get_resource_usage` (L30): `labs` (running labs by RAM) and `top_nodes`.
- Capture `findings` (L31): DHCP Discover without Offer (per client), unanswered ARP / ping (id/seq) / TCP SYN (per
  connection) / RADIUS request (NAS port + id), RST refusals, Access-Reject, EAP failures; computed on the whole capture,
  in-flight tail ignored, truncation noted. Repeated packets are one highlight row with a count.
- `cml_check_reachability(wait_seconds)` (L29): repeats the matrix until routing has converged (BOOTED isn't converged).

### Changed
- Token trims (L32): IOS route-code legend dropped from `cml_run_commands`; previews carry the full licence block only when
  blocked; the recipe list shows the boot time number only.
- Guidance (L29): wrong defaults in two parameter descriptions fixed (a test now checks every '(default X)'), server
  instructions name the newer workflows. Core request for product-neutral spec-tool examples: stutters-mcp-core#57.

## 0.8.0 - 2026-10-15

### Added
- Background tasks (L23): with `MCP_TASKS=true`, `cml_upload_image`, `cml_build_lab`, `cml_build_recipe`, `cml_start_lab`,
  `cml_wait_for_converged`, `cml_verify_recipe`, `cml_capture` and `cml_capture_wireless` run as MCP background tasks (core C12);
  clients without task support call them as before. Depends on `stutters-mcp-core[tasks]`.

## 0.7.0 - 2026-10-15

Later milestone (L13 wireless, L14 fmc-local, L16 site replica; L15 serial fix) and L24. 69 -> 71 tools (read 39, write 24,
dangerous 8 incl. `cml_api_call`) and a second prompt (`cml_replicate_site`).

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
