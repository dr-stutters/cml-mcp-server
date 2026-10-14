# cml-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Modeling Labs (CML 2.x)**: explore,
build, run and troubleshoot network labs from an AI assistant. It's built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) and tested against CML 2.10.

> Not affiliated with or endorsed by Cisco Systems, Inc. "Cisco" and "Cisco Modeling Labs" are
> trademarks of Cisco Systems, Inc.

- **52 tools** in three tiers: 30 read, 17 write, 5 dangerous (plus `cml_api_call` for non-GET). Write and
  dangerous tools are off by default.
- **Names or ids everywhere.** Labs take a title or a UUID, nodes take a label, and links take
  `r1<->r2` or `r1:Ethernet0/0<->r2:Ethernet0/0`.
- **Preview-first writes.** A write call without `confirm` changes nothing. It returns a preview
  (diffs, chosen interfaces, blockers CML would reject) and a single-use confirm token.
- **Task tools.** `cml_build_lab` builds a whole lab from a compact spec (day-0 configs, extra
  config files, console logins, external connectors), `cml_wait_for_converged` reports boot progress
  (and can wait for a console message), `cml_check_reachability` proves what a lab can ping, and
  `cml_diff_lab` compares a lab with another lab or a saved export.
- **Real platforms on the console.** IOS/IOS-XE, NX-OS (POAP skipped), FTD CLISH (no `enable`,
  `mode='exec'` for `configure manager add ...`), Linux. Questions (`[confirm]`, `[yes/no]`) are
  answered on request, runaway commands get Ctrl-C.
- **Lab recipes.** `recipes/*.yaml` are ready-made `cml_build_lab` specs (FTDv for FMC, IOS-XE routers
  for Catalyst Center, a Cat9kv 802.1X switch for ISE); see [recipes/README.md](recipes/README.md).
- **Spec escape hatch.** `cml_search_spec` and `cml_get_definition` read the controller's own
  OpenAPI document. `cml_api_call` reaches any endpoint: GET in the read tier, other methods in the
  dangerous tier.

## Quick start

```bash
git clone https://github.com/dr-stutters/cml-mcp-server && cd cml-mcp-server
cp .env.example .env && chmod 600 .env      # set CML_URL, CML_USERNAME, CML_PASSWORD
uv sync
uv run cml-mcp-server check                 # connects and prints cml_status as JSON
```

### Claude Code: stdio (local)

```bash
claude mcp add cml -- uv --directory /path/to/cml-mcp-server run cml-mcp-server
# to allow changes:
claude mcp add cml -e MCP_ENABLE_WRITES=true -- uv --directory /path/to/cml-mcp-server run cml-mcp-server
```

### Claude Code: HTTP (shared container)

```bash
uv run cml-mcp-server token alice            # prints a bearer token + the MCP_AUTH_TOKENS entry
claude mcp add --transport http cml http://cortex:8032/mcp --header "Authorization: Bearer <token>"
```

or in `.mcp.json`:

```json
{
  "mcpServers": {
    "cml": {
      "type": "http",
      "url": "http://cortex:8032/mcp",
      "headers": { "Authorization": "Bearer ${CML_MCP_TOKEN}" }
    }
  }
}
```

## Tools

**Read** (always on)

| Tool | What it does |
|---|---|
| `cml_status` | Version, API user, compute/controller health problems, licence summary, server config |
| `cml_get_system_health` | Controller and compute health flags, with a problem list |
| `cml_get_resource_usage` | CPU, RAM and disk per compute host; running nodes and allocated resources; licence capacity |
| `cml_get_licensing` | Smart Licensing registration and authorization, features, expiry |
| `cml_list_labs` / `cml_get_lab` | Labs with state and counts; one lab with convergence, node states and resources in use |
| `cml_get_lab_topology` | Compact wiring summary (node interface -> peer, links, conditioning); `detail='full'` for everything |
| `cml_export_lab` | Topology YAML (pyATS passwords masked unless `include_credentials`) |
| `cml_list_lab_events` | Change and state history, newest first, with the fields that changed |
| `cml_get_pyats_testbed` | The pyATS testbed CML generates (passwords masked) |
| `cml_list_nodes` / `cml_get_node` | Nodes with state, image and resources (optionally live CPU/RAM); one node with interfaces, peers and config |
| `cml_get_node_console_log` | Recent serial console output, escape codes stripped, optional `grep` |
| `cml_run_commands` | Run show, ping and traceroute (or `ip addr` etc. on Linux nodes) on one or more booted nodes through the CML console server, in parallel. Only read-only commands are allowed |
| `cml_list_interfaces` | Interfaces with MAC, state and peer; filter free or connected |
| `cml_get_layer3_addresses` | IPs per interface: snooped by CML on external segments, or read from every node's CLI (`source='cli'`) |
| `cml_check_reachability` | Ping targets from nodes (per-OS syntax, VRF, FTD management) and return a pass/fail matrix |
| `cml_list_external_connectors` | Networks an `external_connector` node can join (NAT, System Bridge...) |
| `cml_list_sample_labs` | Sample labs on the controller (filter by text or node type) |
| `cml_list_links` / `cml_get_link` | Links as `node:interface` pairs; one link with conditioning and capture status |
| `cml_list_capture_packets` | Decoded packets from a link capture (filter by protocol or text) |
| `cml_list_node_definitions` / `cml_get_node_definition` | What can be built: interfaces, resources, boot markers, default configs |
| `cml_list_image_definitions` | Installed images |
| `cml_wait_for_converged` | Wait until a lab or node has booted, with progress notifications; `console_pattern` waits for a later console message |
| `cml_diff_lab` | Diff a lab with another lab or a saved YAML: nodes, interfaces, links, config diff |
| `cml_search_spec` / `cml_get_definition` / `cml_api_call` | OpenAPI search, operation and schema details, raw GET |

**Write** (`MCP_ENABLE_WRITES=true`, all preview-first)

| Tool | What it does |
|---|---|
| `cml_build_lab` | Build a lab from `nodes=[{label, definition, config?, files?, credentials?, ...}]` and `links=["r1 r2", "r1:Ethernet0/1 sw1"]`. Interfaces are picked automatically, external connectors and node licences are checked. Optionally start it (and wait) |
| `cml_load_sample_lab` | Create a lab from a sample lab |
| `cml_create_lab` / `cml_import_lab` | Create an empty lab, or create one from topology YAML (node definitions are checked) |
| `cml_start_lab` / `cml_stop_lab` | Start (waits for convergence) or stop a lab |
| `cml_add_node` / `cml_update_node` | Add a node; change its label, tags, position, resources or console login |
| `cml_set_node_config` | Replace a node's day-0 config; the preview shows a unified diff |
| `cml_set_node_state` | Start or stop one node |
| `cml_extract_node_configs` | Save running configs into the stored node configs |
| `cml_configure_node` | Push config lines to a running device over its console (`configure terminal` ... `end`, optionally `write memory`), or exec-mode lines (`mode='exec'`, e.g. FTD `configure manager add`). Rejected lines are reported |
| `cml_connect_nodes` | Link two nodes (first free interfaces, or the ones you name) |
| `cml_set_link_condition` | Add latency, jitter, loss, bandwidth limits, duplication or corruption to a link, or clear it |
| `cml_set_link_state` | Take a link down or bring it up (cable pull) |
| `cml_start_capture` / `cml_stop_capture` | Packet capture on a link |

**Dangerous** (`MCP_ENABLE_DANGEROUS=true` as well)

| Tool | What it does |
|---|---|
| `cml_wipe_lab` / `cml_wipe_node` | Erase node disks (`force=true` stops first) |
| `cml_delete_lab` / `cml_delete_node` / `cml_delete_link` | Delete (`force=true` stops and wipes first where CML requires it) |
| `cml_api_call` (non-GET) | Raw POST, PUT, PATCH or DELETE, preview-first |

Device CLI uses the controller's console server: SSH to the controller with the CML credentials,
then `open /<lab>/<node>/0`. This is the same path pyATS testbeds use. Device logins come from the
lab's pyATS testbed (node pyATS credentials, or the definition defaults).

CML only accepts config, RAM/CPU and new-interface changes while a node is **wiped**
(`DEFINED_ON_CORE`). It only deletes wiped nodes and labs. The previews say so and point to the
tool that fixes it.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CML_URL` | (required) | Controller URL, e.g. `https://cml.example.com` |
| `CML_USERNAME` / `CML_PASSWORD` | | API user (JWT login via `/api/v0/auth_extended`) |
| `CML_TOKEN` | | A pre-issued JWT instead of username/password |
| `CML_VERIFY_SSL` | `true` | `false` for self-signed lab controllers (logged as a warning) |
| `CML_CA_BUNDLE` | | CA file to verify the controller certificate |
| `CML_TIMEOUT` / `CML_RETRIES` | `30` / `2` | Per-request timeout (s) and retries for idempotent calls |
| `CML_RATE_LIMIT` / `CML_MAX_CONCURRENCY` | none / `8` | Client-side throttling |
| `CML_WAIT_TIMEOUT` | `600` | Default wait for start/stop/convergence (s) |
| `CML_NODE_LICENSE_LIMIT` | | Node-licence cap (the API doesn't report it; EVAL Personal = 5). Start/build previews then refuse to exceed it |
| `CML_CONSOLE_PORT` | `22` | SSH port of the CML console server (used for device CLI) |
| `CML_CONSOLE_KNOWN_HOSTS` | | known_hosts file for the console server's host key. When unset, the key is checked against `~/.ssh/known_hosts` if `CML_VERIFY_SSL=true`, and not checked otherwise |
| `MCP_TRANSPORT` | `stdio` | `http` for a network server |
| `MCP_HOST` / `MCP_PORT` / `MCP_PATH` | `0.0.0.0` / `8000` / `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | `name:sha256:<hex>` entries; HTTP refuses to start without one |
| `MCP_ENABLE_WRITES` / `MCP_ENABLE_DANGEROUS` | `false` | Register the write and dangerous tiers |
| `MCP_CONFIRM_TTL` | `600` | Confirm-token lifetime (s) |
| `MCP_CACHE_DIR` | `~/.cache/cml-mcp-server` | OpenAPI index cache (`""` disables it) |
| `MCP_MAX_RESPONSE_CHARS` | `40000` | Response size budget |
| `MCP_AUDIT_LOG` / `LOG_LEVEL` | `stderr` / `INFO` | Audit trail of previews and applied writes |

## Least-privilege account

Create a dedicated CML user (e.g. `mcp`) instead of using `admin`:

1. **Tools → User Management → Add user** with a long random password. Leave **Admin** unchecked.
2. A normal user sees and manages **its own labs**. To work on other people's labs, add the user to a
   **group** that has those labs with *read* (view only) or *read/write* permission.
3. For a read-only assistant, don't enable writes, and share labs with the group as *read*.
4. The system tools (`cml_get_licensing`, `cml_get_system_health`, `cml_get_resource_usage`) may
   need an admin account. `cml_status` and `cml_get_resource_usage` report the licensing part as
   unavailable instead of failing. This hasn't been tested with a non-admin user yet: the CML
   Personal licence on the test lab doesn't allow extra users.

## Docker (HTTP)

```bash
uv run cml-mcp-server token alice      # copy the "name:sha256:..." line into .env as MCP_AUTH_TOKENS
CORE_READ_TOKEN=$(gh auth token) docker compose up -d --build
curl -s http://localhost:8032/health   # {"status":"ok"}
```

The container runs as non-root on a read-only root filesystem with all capabilities dropped. The
spec cache lives in a named volume. `CORE_READ_TOKEN` is only needed while the core repo is private.

## Development

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
uv run pytest tests/live -m live           # against the lab in .env; creates and deletes mcp-test-* labs
uv run python scripts/capture_fixtures.py mcp-test-probe   # refresh redacted fixtures
```

`scripts/seed_lab.py [--start] [--recreate]` creates a reusable lab, `mcp-test-seed`. It has two
IOL-XE routers running OSPF, an IOL-L2 switch and two Alpine hosts (h1 10.0.10.10 and h2
10.0.20.10, which can ping each other). Device logins are cisco/cisco.

Note: the CML Personal/EVAL licence on the test controller allows **5 running nodes** in total, across
all labs. Unmanaged switches and external connectors don't count. A start beyond that fails with
"5 of 5 node licenses are in use".

Live tests build throwaway labs named `mcp-test-*` from fast-booting IOL nodes, run every tool,
and always delete what they created.

## Licence

MIT
