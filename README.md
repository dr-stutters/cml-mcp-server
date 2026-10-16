# cml-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Modeling Labs (CML 2.x)**: explore,
build, run and troubleshoot network labs from an AI assistant. It's built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) and tested against CML 2.10.

> Not affiliated with or endorsed by Cisco Systems, Inc. "Cisco" and "Cisco Modeling Labs" are
> trademarks of Cisco Systems, Inc.

- **72 tools** in three tiers: 39 read, 25 write, 8 dangerous (incl. `cml_api_call` for non-GET), and the
  prompt `cml_build_test_lab`. Write and dangerous tools (and the prompt) are off by default.
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
- **Lab recipes for the other suite servers.** FTDv for FMC, an unregistered FTDv HA pair, IOS-XE routers for
  Catalyst Center, a Cat9kv 802.1X switch (IBNS 2.0) with MAB and EAP-TLS clients for ISE, an AD-user 802.1X client behind an
  FMC-managed FTD for user-based firewalling: `cml_list_recipes`, `cml_build_recipe`, `cml_verify_recipe` (pass/fail contract,
  incl. ISE live sessions), `cml_run_recipe_action` (e.g. switch the logged-in user)
  and the prompt `cml_build_test_lab`; `cml_plan_licences` says which labs to stop. See
  [src/cml_mcp/recipes/README.md](src/cml_mcp/recipes/README.md).
- **Test oracles.** `cml_diff_node_config` shows what another server changed on a device;
  `cml_capture` / `cml_summarize_capture` decode RADIUS, EAPOL, OSPF, DHCP and more from a link capture.
- **Degraded networks and diagrams.** `cml_apply_link_scenario` puts named impairments on a link (wan-good,
  wan-satellite, lossy-wifi, brownout, or a timed `flap`); `cml_export_topology` draws a lab as Mermaid or
  draw.io with addresses, and `cml_annotate_lab` makes a lab self-describing.
- **Spec escape hatch.** `cml_search_spec` and `cml_get_definition` read the controller's own
  OpenAPI document. `cml_api_call` reaches any endpoint: GET in the read tier, other methods in the
  dangerous tier.

## Quickstart (5 minutes)

You need: a CML account for the server, a regular (non-admin) user is enough (read-only to start: labs shared
with it as `lab_view` + `lab_exec` and a resource pool with 0 node licences, see
[docs/least-privilege.md](docs/least-privilege.md)). Never the built-in `admin`.

**A. On your laptop (stdio), from a release wheel.** Every [GitHub release](https://github.com/dr-stutters/cml-mcp-server/releases)
has a wheel with stutters-mcp-core bundled in; it needs only PyPI dependencies.

```bash
WHEEL=https://github.com/dr-stutters/cml-mcp-server/releases/download/v0.11.0/cml_mcp_server-0.11.0-py3-none-any.whl
export CML_URL=https://cml.example.com CML_USERNAME=mcp-cml-viewer CML_PASSWORD='...'
uvx --from "$WHEEL" cml-mcp-server check            # preflight: reachability, TLS, login, version, admin flag
claude mcp add cml -e CML_URL=$CML_URL -e CML_USERNAME=$CML_USERNAME -e CML_PASSWORD="$CML_PASSWORD" \
  -- uvx --from "$WHEEL" cml-mcp-server              # stdio is the default transport
```

Claude Desktop (`claude_desktop_config.json`), same idea:

```json
{
  "mcpServers": {
    "cml": {
      "command": "uvx",
      "args": ["--from", "https://github.com/dr-stutters/cml-mcp-server/releases/download/v0.11.0/cml_mcp_server-0.11.0-py3-none-any.whl", "cml-mcp-server"],
      "env": {"CML_URL": "https://cml.example.com", "CML_USERNAME": "mcp-cml-viewer", "CML_PASSWORD": "..."}
    }
  }
}
```

**B. On a shared host (HTTP), from the image.** Multi-arch (amd64/arm64), signed, with an SBOM:
`ghcr.io/dr-stutters/cml-mcp-server:<version>` (or `:latest`).

```bash
docker run --rm -e CML_URL=https://cml.example.com -e CML_USERNAME=mcp-cml-viewer -e CML_PASSWORD='...' \
  ghcr.io/dr-stutters/cml-mcp-server cml-mcp-server check
docker run --rm ghcr.io/dr-stutters/cml-mcp-server cml-mcp-server token alice   # one token per person
cp .env.example .env && chmod 600 .env    # CML_*, MCP_AUTH_TOKENS=alice:sha256:...
docker compose up -d                      # pulls the image; http://localhost:8032/mcp
```

For a team, use [docs/deploying.md](docs/deploying.md): read-only by default, per-user tokens in the audit
log, several controllers, the shared node-licence budget, TLS with Caddy, upgrades.

**`check`** runs without an MCP client and exits 1 on a failure (`--json` for scripts, `--strict` to fail on
warnings, `--instance training` for one controller). It reports reachability and TLS trust of the controller
API, the login, the CML version against the tested matrix (2.10; 2.7 minimum), the API user's admin flag
against the enabled tiers (an admin behind a read-only server warns; a regular user with the dangerous tier on
warns that admin-only tools will fail) and, with writes on, the node licences the account may start (its
resource pool, else the controller licence):

```text
  OK    config                 https://cml.example.com; tiers enabled: read, write
  OK    reachability[api]      CML API answered; logged in as mcp-cml-operator (41 ms)
  OK    tls                    certificate verified against the system trust store
  OK    auth                   credentials accepted
  OK    role                   role 'mcp-cml-operator (regular user)' allows the enabled tier(s): read, write
  OK    version                Cisco Modeling Labs 2.10.0+build.13: tested
  WARN  licences               resource pool 'mcp-cml-operator-pool' leaves 0 node licences free (12 of 12 in use): ...
                               -> Raise the pool's licences (Tools > Resource Pools; ...) or stop labs (cml_plan_licences says which).
```

`cml-mcp-server serve --http` serves HTTP (needs `MCP_AUTH_TOKENS`); `cml-mcp-server config` shows the
effective settings and where each came from, without contacting CML.

### From source

```bash
git clone https://github.com/dr-stutters/cml-mcp-server && cd cml-mcp-server
python3 scripts/bundle_core.py vendor       # bundles the pinned stutters-mcp-core as cml_mcp._core (needs git)
cp .env.example .env && chmod 600 .env      # set CML_URL, CML_USERNAME, CML_PASSWORD
uv sync
uv run cml-mcp-server check
```

The shared [stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) library (with its `tasks` extra) is
**bundled** into the package as `cml_mcp._core` (core ADR-005): the wheel, the sdist and the Docker image need
nothing but their PyPI dependencies, with no git dependency and no token. `uv build` writes the wheel to `dist/`.
The pinned core tag is `[tool.bundle-core]` in `pyproject.toml` and `cml_status` reports it as `core_version`.
The vendored copy is generated, not committed: `scripts/bundle_core.py vendor` writes it, `check` reports drift,
and `update --tag vX.Y.Z` moves the pin (then `uv lock`). A plain git checkout has no `cml_mcp/_core`, so install
from a release wheel rather than `git+https://...`.

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
| `cml_check_reachability` | Ping targets from nodes (per-OS syntax, VRF, FTD management) and return a pass/fail matrix with average RTT |
| `cml_list_external_connectors` | Networks an `external_connector` node can join (NAT, System Bridge...) |
| `cml_list_sample_labs` | Sample labs on the controller (filter by text or node type) |
| `cml_list_links` / `cml_get_link` | Links as `node:interface` pairs; one link with conditioning and capture status |
| `cml_list_capture_packets` | Decoded packets from a link capture (filter by protocol or text) |
| `cml_list_node_definitions` / `cml_get_node_definition` | What can be built: interfaces, resources, boot markers, default configs |
| `cml_list_image_definitions` | Installed images |
| `cml_get_image_files` | Disk images in `CML_IMAGE_DIR` on the server host, and the controller's drop folder |
| `cml_wait_for_converged` | Wait until a lab or node has booted, with progress notifications; `console_pattern` waits for a later console message |
| `cml_diff_lab` | Diff a lab with another lab or a saved YAML: nodes, interfaces, links, config diff (`running_configs=true` for live configs) |
| `cml_diff_node_config` | Running config (from the console) vs day-0, startup, another node or a baseline; secrets masked |
| `cml_summarize_capture` | Decoded summary of a link capture: protocol mix, conversations, RADIUS/EAPOL/OSPF/DHCP/ARP/ICMP highlights |
| `cml_plan_licences` | Licences in use per lab, what a lab or recipe needs, which labs to stop |
| `cml_plan_replica` | Map a real site's devices (Catalyst Center / ISE / FMC inventories) to CML node definitions within a node/RAM budget: ready `cml_build_lab` spec, gaps, dropped devices |
| `cml_list_recipes` / `cml_verify_recipe` | Test-lab recipes (no secrets returned); pass/fail verify contract of a running recipe lab (or a copy: `lab`, `substitute`) |
| `cml_get_link_scenarios` | Named link scenarios with netem values and expected round-trip ping deltas; with a lab, its conditioned links and flap jobs |
| `cml_export_topology` | Mermaid, draw.io or JSON diagram of a lab with interface addresses (day-0 config, snooped or CLI) |
| `cml_list_annotations` | A lab's drawn annotations (text, shapes), marking the ones this server wrote |
| `cml_search_spec` / `cml_get_definition` / `cml_api_call` | OpenAPI search, operation and schema details, raw GET |

**Write** (`MCP_ENABLE_WRITES=true`, all preview-first)

| Tool | What it does |
|---|---|
| `cml_build_lab` | Build a lab from `nodes=[{label, definition, config?, files?, credentials?, ...}]` and `links=["r1 r2", "r1:Ethernet0/1 sw1"]`. Interfaces are picked automatically, external connectors and node licences are checked. Optionally start it (and wait) |
| `cml_load_sample_lab` | Create a lab from a sample lab |
| `cml_create_lab` / `cml_import_lab` | Create an empty lab, or create one from topology YAML (node definitions are checked) |
| `cml_start_lab` / `cml_stop_lab` | Start (waits for convergence) or stop a lab |
| `cml_stop_labs` | Stop several labs (a list, or every running lab except `keep`) with one preview: licences and RAM freed per lab, protected labs refused |
| `cml_add_node` / `cml_update_node` | Add a node; change its label, tags, position, resources or console login |
| `cml_set_node_config` | Replace a node's day-0 config; the preview shows a unified diff |
| `cml_set_node_state` | Start or stop one node |
| `cml_extract_node_configs` | Save running configs into the stored node configs |
| `cml_configure_node` | Push config lines to a running device over its console (`configure terminal` ... `end`, optionally `write memory`), or exec-mode lines (`mode='exec'`, e.g. FTD `configure manager add`). Rejected lines are reported |
| `cml_connect_nodes` | Link two nodes (first free interfaces, or the ones you name) |
| `cml_set_link_condition` | Add latency, jitter, loss, bandwidth limits, duplication or corruption to a link, or clear it |
| `cml_set_link_state` | Take a link down or bring it up (cable pull) |
| `cml_start_capture` / `cml_stop_capture` | Packet capture on a link |
| `cml_capture` | Capture for N seconds and return the decoded summary in one call |
| `cml_capture_wireless` | Capture the simulated 802.11 medium at a wireless-ap / wireless-client node and decode it (SSIDs, auth/assoc, deauth reasons, EAPOL 4-way handshake, EAP identity/method) |
| `cml_build_recipe` | Build a packaged test-lab recipe (optionally start it), with annotations; `title` + `substitute` build a copy on other addresses |
| `cml_run_recipe_action` | Run one of a recipe's packaged actions on its lab, e.g. `ise-fmc-identity` `login-alice` / `login-bob` / `logoff` (802.1X as another AD user); the command comes from the recipe, never the caller |
| `cml_apply_link_scenario` | Apply a named scenario to a link: wan-good, wan-satellite, lossy-wifi, brownout, or `flap` (timed down/up cycles in the background, link always restored) |
| `cml_clear_link_scenarios` | Stop flap jobs and remove conditioning from a lab's links |
| `cml_annotate_lab` | Add notes, per-node address labels and the recipe's purpose/credential references as text annotations (re-runnable) |
| `cml_create_image_definition` | Make an uploaded disk image usable by a node definition (admin) |

**Prompts** (write tier): `cml_replicate_site(site, fidelity, max_nodes)` - Catalyst Center site (+ FMC firewalls, ISE NADs)
-> `cml_plan_replica` -> licence check -> `cml_build_lab` -> report gaps. `cml_build_test_lab(recipe, reuse)` - recipe -> licence plan -> build/start ->
converge -> verify -> hand-off block for the FMC / Catalyst Center / ISE server.

**Dangerous** (`MCP_ENABLE_DANGEROUS=true` as well)

| Tool | What it does |
|---|---|
| `cml_wipe_lab` / `cml_wipe_node` | Erase node disks (`force=true` stops first) |
| `cml_delete_lab` / `cml_delete_node` / `cml_delete_link` | Delete (`force=true` stops and wipes first where CML requires it) |
| `cml_upload_image` | Stream a disk image from `CML_IMAGE_DIR` to the controller (never through MCP), SHA-256 and disk-space checked (admin) |
| `cml_delete_image` | Delete an image definition (refused while nodes use it) and/or a drop-folder file (admin) |
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
| `CML_INSTANCES` | | More controllers, each with `CML_<NAME>_URL`, `_USERNAME`, `_PASSWORD`...; tools take an `instance` argument ([docs/deploying.md](docs/deploying.md)) |
| `CML_VERIFY_SSL` | `true` | `false` for self-signed lab controllers (logged as a warning) |
| `CML_CA_BUNDLE` | | CA file to verify the controller certificate |
| `CML_TIMEOUT` / `CML_RETRIES` | `30` / `2` | Per-request timeout (s) and retries for idempotent calls |
| `CML_RATE_LIMIT` / `CML_MAX_CONCURRENCY` | none / `8` | Client-side throttling |
| `CML_WAIT_TIMEOUT` | `600` | Default wait for start/stop/convergence (s) |
| `CML_NODE_LICENSE_LIMIT` | detected | Running licensed-node cap. Detected from `/licensing` when unset (base licence nodes + `CML_NODE_COUNT` expansion; 5 in evaluation mode). Start/build previews refuse to exceed it; `cml_plan_licences` says which labs to stop |
| `CML_CONSOLE_PORT` | `22` | SSH port of the CML console server (used for device CLI) |
| `CML_CONSOLE_LOCK_WAIT` | `60` | Seconds a console call waits for another call on the same node before reporting it busy |
| `CML_LAB_SECRETS_FILE` | | dotenv file with the `LAB_*` values that recipes reference as `${LAB_*}` (device passwords, keys, communities). `LAB_*` environment variables override it. Recipe builds name any missing variable |
| `CML_IMAGE_DIR` | | The only directory `cml_upload_image` reads (images are streamed from it; uploads are off without it) |
| `CML_PROTECTED_LABS` / `CML_MANAGED_LABS` | | Safety rails ([docs/safety.md](docs/safety.md)): labs no change may touch; labs the dangerous tools may wipe/delete (title globs or ids) |
| `CML_CONFIG_DENY_DEFAULTS` / `CML_CONFIG_DENY` | `true` / | `cml_configure_node` refuses destructive device commands (write erase, reload, format, delete, ...); one extra regex |
| `CML_TLS_CHECK_HOSTNAME` | `true` | `false` only with `CML_CA_BUNDLE` = the controller's own certificate (pinned; `scripts/pin_controller.py`) |
| `CML_CONSOLE_KNOWN_HOSTS` | | known_hosts file for the console server's host key. When unset, the key is checked against `~/.ssh/known_hosts` if `CML_VERIFY_SSL=true`, and not checked otherwise |
| `MCP_TRANSPORT` | `stdio` | `http` for a network server |
| `MCP_HOST` / `MCP_PORT` / `MCP_PATH` | `0.0.0.0` / `8000` / `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | `name:sha256:<hex>` entries; HTTP refuses to start without one |
| `MCP_ENABLE_WRITES` / `MCP_ENABLE_DANGEROUS` | `false` | Register the write and dangerous tiers |
| `MCP_TASKS` / `MCP_TASKS_URL` | `false` / `memory://` | Run the long tools (image upload, builds/starts with wait, convergence waits, recipe verify, captures) as MCP background tasks for clients that support them; others still call them synchronously |
| `MCP_CONFIRM_TTL` | `600` | Confirm-token lifetime (s) |
| `MCP_CACHE_DIR` | `~/.cache/cml-mcp-server` | OpenAPI index cache (`""` disables it) |
| `MCP_MAX_RESPONSE_CHARS` | `40000` | Response size budget |
| `MCP_AUDIT_LOG` / `LOG_LEVEL` | `stderr` / `INFO` | Audit trail of previews and applied writes |

## Least-privilege account

Run the server as a regular (non-admin) CML user, never `admin`. Tested on CML 2.10 with two accounts, both
created by `scripts/seed_lab.py --least-privilege`. Full guide: [docs/least-privilege.md](docs/least-privilege.md).

- **Read tier:** `mcp-cml-viewer`, labs shared with its group as `lab_view` + `lab_exec` (consoles need
  `lab_exec`), and a resource pool with 0 node licences. Every read tool works except `cml_get_licensing`
  (admin-only in CML).
- **Write tier:** `mcp-cml-operator` owns the labs it builds; its resource pool caps licences, CPU and RAM,
  and the start previews respect the pool.
- As a non-admin, licence planning counts only the labs the account can see (`scope` says so), and consoles of
  shared labs work.

## Docker (HTTP)

```bash
docker compose up -d                   # pulls ghcr.io/dr-stutters/cml-mcp-server (MCP_IMAGE_TAG, default latest)
docker compose up -d --build           # or build from this checkout (no token: core is bundled)
curl -s http://localhost:8032/health   # {"status":"ok"}
```

The container runs as non-root on a read-only root filesystem with all capabilities dropped. The
spec cache lives in a named volume. Shared hosts (TLS, several controllers, per-user tokens, the shared licence
budget, upgrades): [docs/deploying.md](docs/deploying.md).

## Development

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
uv run pytest tests/live -m live           # against the lab in .env; creates and deletes mcp-test-* labs
uv run python scripts/capture_fixtures.py mcp-test-probe   # refresh redacted fixtures
```

`scripts/seed_lab.py [--start] [--recreate]` creates a reusable lab, `mcp-test-seed`. It has two
IOL-XE routers running OSPF, an IOL-L2 switch and two Alpine hosts (h1 10.0.10.10 and h2
10.0.20.10, which can ping each other). Device logins are cisco/cisco.

Note: CML caps running licensed nodes across all labs (an unregistered controller in evaluation
mode allows 5; the test controller is now Enterprise with 20 + 50 expansion = 70). Unmanaged
switches and external connectors don't count. `cml_plan_licences` shows the cap and which labs to stop.

Live tests build throwaway labs named `mcp-test-*` from fast-booting IOL nodes, run every tool,
and always delete what they created.

## Licence

MIT
