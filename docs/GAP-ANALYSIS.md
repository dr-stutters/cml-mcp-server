# CML 2.10 API gap analysis (Phase 2)

Source: the controller's own `GET /api/v0/openapi.json` (CML 2.10.0+build.13). **203 operations in
17 tags.** "Curated" means a dedicated tool does the job (often several operations behind one tool);
"api_call" means reachable through `cml_api_call` (GET in the read tier, other methods in the
dangerous tier); "not reachable" means neither works well.

## Coverage by area

| Area (tag) | Ops | Curated | api_call only | Notes |
|---|---:|---:|---:|---|
| Labs: lifecycle, import/export, state, events, testbed | 25 | 21 | 4 | `bootstrap`, `connector_mappings` PATCH, `find/node/*` (resolution does it), tiles |
| Labs: annotations / smart annotations | 8 | 0 | 8 | cosmetic; low operator value |
| Labs: sharing (groups, associations) | 4 | 0 | 4 | single-admin lab; licence forbids extra users |
| Labs: layer-3 addresses | 2 | 1 | 1 | + CLI discovery (new) |
| Labs: pcap | 3 | 1 | 2 | packet list curated; raw pcap download is binary (not useful through MCP) |
| Labs: sample labs | 3 | 3 | 0 | **new** `cml_list_sample_labs`, `cml_load_sample_lab` |
| Nodes | 17 | 14 | 3 | VNC/console keys deliberately hidden; `/nodes` (all labs) used for licence accounting |
| Interfaces | 6 + 1 | 4 | 3 | interface create via connect_nodes/add_node; PATCH/DELETE interface via api_call |
| Links (incl. conditioning, capture) | 14 | 13 | 1 | capture key hidden |
| Node definitions | 8 | 3 | 5 | upload/modify custom definitions: admin, rare, big YAML payloads |
| Image definitions & upload | 12 | 1 | 10 | `POST /images/upload` is a multipart binary upload: **not reachable** through MCP |
| System: external connectors | 5 | 1 | 4 | **new** `cml_list_external_connectors`; sync/patch admin-only |
| System: compute hosts, health, stats, info | 9 | 4 | 5 | health/usage/status curated; compute host admin changes via api_call |
| System: maintenance mode, notices, lab repos, archive, session timeout, reload | 17 | 0 | 17 | admin housekeeping |
| Licensing | 19 | 1 | 18 | registration/reservation flows: rare, one-off, and dangerous |
| Users / Groups / Resource pools | 22 | 0 | 22 | GET via api_call; writes refused by the EVAL licence here |
| Authentication / auth config | 11 | 0 (login internal) | 11 | `/authentication` echoes the token: never expose |
| Diagnostics, telemetry, runtime keys, AI, wireless pcap | 13 | 0 | 13 | keys hidden on purpose; others low value |
| **Total** | **203** | **~67 (33 %)** | **~134** | `POST /images/upload` (binary) is the only operation not usable at all |

Operations that matter day to day (lab build/run/inspect/troubleshoot, ~95 ops) are **~70 % curated**;
the remainder is administration, licensing and cosmetic canvas features.

## Device-side gaps (not in the REST API, but what operators and the next builders need)
The REST API stops at the node; the work FMC / Catalyst Center / ISE testing needs happens on the
device consoles. Before Phase 2:

| Need | Before | Phase 2 |
|---|---|---|
| FTD (CLISH `>` prompt) CLI | broken: sent `enable`, no `configure` mode | os-aware login (no enable for fxos), `mode='exec'` for `configure manager add ...` |
| Commands that ask questions | hung until timeout | detected; `answer_questions=true` answers `[confirm]`, `[yes/no]`, `(y/n)`, `continue?`, `[filename]?` |
| Commands that never end (FTD `ping system`) | left running on the console after timeout | `interrupt_after`; every timed-out command gets Ctrl-C |
| FTD forced password change | opaque "no working password" error | clear error (weak/dictionary day-0 password) |
| NX-OS POAP prompt | not handled | answered with `skip` |
| Day-0 for multi-file definitions | only the main file | `files` (e.g. cat9000v `conf/vswitch.xml`, ubuntu `network-config`) |
| Console login after day-0 changes it | manual PATCH of pyATS creds | `credentials` in `cml_build_lab`; `login_*` in `cml_update_node` |
| External network attachment | free-text config, typo = silent NAT | validated against `/system/external_connectors`; `cml_list_external_connectors` |
| FTDv `donotuse` slot | auto-wiring could pick it | skipped |
| Slow boots (FTDv 15-30 min) | `start` always blocked until booted | `wait=false` on build; `console_pattern` on `cml_wait_for_converged` |
| EVAL 5-node licence | raw 400 after the lab was half-created | preview blocker (`CML_NODE_LICENSE_LIMIT`) + error naming the labs holding licences |
| L3 address discovery | snooping only (external segments) | `source='cli'/'both'`: IOS/IOS-XE/NX-OS/ASA/FTD/Linux parsers |
| Reachability proof | hand-written pings per OS | `cml_check_reachability` matrix (per-OS ping syntax, VRF, FTD management) |
| Console log | raw ANSI escapes | escapes stripped, `grep` filter |

## Existing-tool review
- Names/ids: consistent `cml_<verb>_<noun>`, labs/nodes/links resolve by name. Kept.
- `cml_run_commands` read-tier allow-list: kept; FTD `show ...`/`ping` work under it.
- `cml_get_layer3_addresses`: description was misleading for bridged labs (it *does* work there); rewritten.
- `cml_build_lab`: spec was too thin for real platforms (no pyATS creds, no extra files, no params,
  no positions). Extended; the recipes are written in exactly this spec.
- Output size: reachability returns raw output only for failures; console logs can be grepped.

## Decided not to build (left to `cml_api_call`)
- Image upload / node-definition authoring: binary multipart or large YAML, admin-only, rare.
- Licensing registration/reservation: one-off, dangerous, needs Smart Account tokens.
- Users, groups, resource pools, lab sharing: writes refused by this controller's licence, so
  untestable; GET works through `cml_api_call`.
- Annotations / smart annotations: canvas cosmetics.
- System maintenance mode, notices, lab repos, telemetry, diagnostics: admin housekeeping; GET via api_call.
- pcap download: binary; `cml_list_capture_packets` gives decoded packets instead.
