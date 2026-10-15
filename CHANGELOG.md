# Changelog

## Unreleased

### Changed
- Core pinned to stutters-mcp-core v0.3.0 (MCP prompts; the 0.2.0 event framework is gone, servers are pull-only).

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
