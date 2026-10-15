# Least-privilege accounts for `cml-mcp-server`

The server needs one CML account. CML has no custom roles: an account is either an **admin** or a
**regular user**. A regular user owns the labs it creates and reaches other labs only through **lab
permissions** granted to it or to one of its **groups** (`lab_view`, `lab_exec`, `lab_edit`, `lab_admin`).
A **resource pool** caps what the account can start: node licences, CPUs and RAM. Use the smallest account
that covers the tiers you enable:

| Server tiers enabled | Account | CML rights |
|---|---|---|
| read only (default) | `mcp-cml-viewer` | regular user, group `mcp-cml-viewers`; labs shared with the group as `lab_view` + `lab_exec`; resource pool with **0** node licences |
| read + write (`MCP_ENABLE_WRITES=true`) | `mcp-cml-operator` | regular user, group `mcp-cml-operators`; owns the labs it builds; resource pool **12 licences / 24 CPUs / 64 GB** |
| + dangerous (`MCP_ENABLE_DANGEROUS=true`) | `mcp-cml-operator` for its own labs; an **admin** for `cml_upload_image` and anything on other users' labs | Deleting/wiping is allowed on labs the account owns or has `lab_admin` on; image upload and `/system` writes are admin-only in CML |

Never give a hosted server the controller's built-in `admin`. MCP-side roles (`MCP_ROLES`, core
docs/PRODUCTION.md) restrict *callers*; this guide restricts *the server itself*. Use both.

## 1. Read-only account: `mcp-cml-viewer`

| CML right | Why | Needed by |
|---|---|---|
| regular (non-admin) user | logs in, reads system information, node/image definitions, external connectors, system health and stats | `cml_status`, `cml_list_node_definitions`, `cml_get_node_definition`, `cml_list_image_definitions`, `cml_list_external_connectors`, `cml_get_system_health`, `cml_get_resource_usage`, `cml_list_sample_labs`, `cml_list_recipes`, `cml_search_spec`, `cml_get_definition` |
| `lab_view` on the shared labs (via the group) | lab, node, interface, link, annotation, event and capture data, exports | `cml_list_labs`, `cml_get_lab`, `cml_get_lab_topology`, `cml_list_nodes`, `cml_get_node`, `cml_list_interfaces`, `cml_list_links`, `cml_get_link`, `cml_list_lab_events`, `cml_export_lab`, `cml_export_topology`, `cml_get_pyats_testbed`, `cml_list_annotations`, `cml_get_link_scenarios`, `cml_list_capture_packets`, `cml_summarize_capture`, `cml_diff_lab`, `cml_wait_for_converged`, `cml_plan_licences` |
| `lab_exec` on the shared labs | **device consoles**: with `lab_view` alone CML opens the console read-only, so commands time out | `cml_run_commands`, `cml_get_node_console_log`, `cml_diff_node_config`, `cml_check_reachability`, `cml_get_layer3_addresses(source='cli')`, `cml_verify_recipe` |
| resource pool `mcp-cml-viewer-pool` (0 licences, 0 CPU, 0 RAM) | `lab_exec` also allows starting nodes in CML; the pool makes sure the read-only account can't start anything | - |

**What it deliberately does not allow:**
- `cml_get_licensing`: `/licensing` is admin-only in CML. The tool says so and points to `cml_plan_licences`.
- Other users' labs that aren't shared with the group are invisible. `cml_plan_licences` and the start
  previews count only the labs the account can see, and say so in `scope`. CML still enforces the controller
  licence and the account's pool on every start.
- `cml_api_call` is dangerous-tier for non-GET methods and stays off.

**Lab-level trade-off:** `lab_exec` also lets the account stop and wipe nodes in CML itself. The MCP `ro`
role hides those tools, and the 0-licence pool blocks starts. Without `lab_exec` the console tools return
an error per node, and the other read tools still work.

## 2. Write account: `mcp-cml-operator`

| CML right | Needed by |
|---|---|
| regular user (owns what it builds) | every write tool on its own labs: `cml_build_lab`, `cml_build_recipe`, `cml_import_lab`, `cml_create_lab`, `cml_add_node`, `cml_connect_nodes`, `cml_update_node`, `cml_set_node_config`, `cml_start_lab`/`cml_stop_lab`, `cml_set_node_state`, `cml_configure_node`, `cml_extract_node_configs`, link conditioning, scenarios, captures, `cml_annotate_lab`, `cml_load_sample_lab` |
| `lab_admin` on a lab it owns (implicit) | sharing its labs with the viewers group (`PATCH /labs/{id}/associations`) |
| resource pool `mcp-cml-operator-pool` (12 licences, 24 CPUs, 64 GB) | caps the blast radius on a shared controller. Previews use the pool as the limit when it is tighter than the controller licence (`cml_plan_licences` shows `resource_pool` and `limit_source`). Size it for your recipes: ftd-fmc 1 / catc-routers 2 / ise-access 3 / ftd-ha 3 licensed nodes; FTDv 8 GB each |

To let it change other people's labs, grant `lab_edit` + `lab_exec` (+ `lab_admin` to delete) on those labs
to `mcp-cml-operators`.

## 3. Users, groups and pools

| User | Group | Pool (template) | Password |
|---|---|---|---|
| `mcp-cml-viewer` | `mcp-cml-viewers` | `mcp-cml-viewer-pool` (`-template`) | `.env`: `CML_RO_PASSWORD` |
| `mcp-cml-operator` | `mcp-cml-operators` | `mcp-cml-operator-pool` (`-template`) | `.env`: `CML_RW_PASSWORD` |

CML quirk: a user's resource pool must be created from a **template pool** (`POST /resource_pools` with
`template`). The template carries the limits.

**Create them** (idempotent; uses the admin login in `.env`, passwords from `CML_RO_PASSWORD` /
`CML_RW_PASSWORD`):

```bash
uv run python scripts/seed_lab.py --least-privilege
```

GUI: *Tools > User Management* (users, groups, the user's resource pool) and *Tools > Resource Pools*; share a
lab under *Lab > Sharing*. The server then runs with `CML_USERNAME=mcp-cml-viewer` (or `-operator`) and the
password, which a hosted server should keep in `CML_PASSWORD_FILE` or `CML_PASSWORD_REF` (core secrets), not in `.env`.

Share a lab with the viewers group (as its owner or an admin):

```bash
# cml_api_call (dangerous tier) or curl: PATCH /api/v0/labs/<lab id>/associations
{"groups": [{"id": "<mcp-cml-viewers id>", "permissions": ["lab_view", "lab_exec"]}]}
```

## 4. Behaviour as a non-admin (built in, v0.6.0)

- `cml_status` reports `admin: false` and the account's `resource_pool` (licences, RAM, used/limit).
- `cml_plan_licences` and every start/build preview fall back to per-lab node lists when `GET /nodes`
  (admin-only) is refused, and use the account's pool when `/licensing` isn't readable or the pool is tighter.
  With the pool as the limit, only the account's own labs are offered as candidates to stop.
- Consoles: the CML console server lists only the account's own labs until `all` is toggled. The server
  toggles it when a shared lab's console is "not found" (verified on CML 2.10).

## 5. Verify (tested on CML 2.10.0+build.13, 2026-10-15)

Put both accounts in `.env` (`CML_RO_USERNAME`/`CML_RO_PASSWORD`, `CML_RW_USERNAME`/`CML_RW_PASSWORD`) and run:

```bash
uv run pytest -m live tests/live/test_least_privilege.py -v -s
```

The test seeds the accounts. Then the **operator** (MCP role `rw`) builds and starts a 2-router lab,
configures both routers over the console, conditions and clears a link, and annotates the lab. It shares
the lab with the viewers group: first `lab_view` (console commands must fail), then `lab_view` + `lab_exec`.
The **viewer** (MCP role `ro`) then calls every read tool via core's `read_tier_report`.

| Result (viewer, read tier) | Count | Tools |
|---|---|---|
| ok | 34 | every other read tool, consoles included |
| denied (expected) | 1 | `cml_get_licensing` (admin-only; checked separately for its clear message) |
| no data (not a permission) | 1 | `cml_summarize_capture` (no capture on the link) |
| skipped | 2 | `cml_api_call`; `cml_verify_recipe` (needs a recipe lab shared with the group) |
| write tools hidden from `ro` | all | e.g. `cml_build_lab`, `cml_configure_node` |

Write and dangerous tiers as the operator: the test above, plus the existing suites run as the operator, all
passed (2026-10-15): `CML_USERNAME=mcp-cml-operator CML_PASSWORD=... uv run pytest -m live
tests/live/test_live_write.py tests/live/test_live_dangerous.py tests/live/test_live_scenarios.py` (3 passed).

## 6. Lab rebuild

`scripts/seed_lab.py --least-privilege` recreates both users, groups and pools; `~/MCP-Suite/LAB-REBUILD.md`
lists it under CML, and `rebuild-lab.sh` step 7 runs it.
