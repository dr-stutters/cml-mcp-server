# Changelog

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
