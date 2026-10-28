# cml-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Modeling Labs (CML 2.x)**: explore,
build, run and troubleshoot network labs from an AI assistant. It's built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) and tested against CML 2.10.

> **Disclaimer.** This is not an official Cisco product or repository, and it isn't supported or endorsed by
> Cisco. It's a personal project by [@dr-stutters](https://github.com/dr-stutters), for lab and learning use
> only: don't point it at production systems. It's provided as is, with no warranty (see the
> [license](LICENSE)). Cisco and Cisco Modeling Labs are trademarks of Cisco Systems, Inc.

- **76 tools** in three tiers: 39 read, 29 write, 8 dangerous (incl. `cml_api_call` for non-GET), and the
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
  and the prompt `cml_build_test_lab`; `cml_plan_licences` says which labs to stop. Recipes not yet released
  (a PR's checkout) load from `CML_RECIPE_DIRS`. See [src/cml_mcp/recipes/README.md](src/cml_mcp/recipes/README.md).
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
WHEEL=https://github.com/dr-stutters/cml-mcp-server/releases/download/v0.14.0/cml_mcp_server-0.14.0-py3-none-any.whl
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
      "args": ["--from", "https://github.com/dr-stutters/cml-mcp-server/releases/download/v0.14.0/cml_mcp_server-0.14.0-py3-none-any.whl", "cml-mcp-server"],
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
| `cml_export_lab` | Topology YAML, valid and re-importable when masked (pyATS passwords `'********'`, cloud-init passwords `${LAB_NODE_PASSWORD}`, unless `include_credentials`); large labs in pages (`offset` / `next_offset`) |
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
| `cml_diff_lab` | Diff a lab with another lab or a saved YAML: nodes, interfaces, links, config diff (`running_configs=true` for live configs); `against='day0'` or `'saved'` for lab-wide drift of every node's running config, `view='sections'` for changed sections per node, `nodes=[...]` to narrow it |
| `cml_diff_node_config` | Running config (from the console) vs day-0, startup, another node or a baseline; secrets masked |
| `cml_summarize_capture` | Decoded summary of a link capture: protocol mix, conversations, RADIUS/EAPOL/OSPF/DHCP/ARP/ICMP highlights |
| `cml_plan_licences` | Licences in use per lab, what a lab or recipe needs, which labs to stop |
| `cml_plan_replica` | Map a real site's devices (Catalyst Center / ISE / FMC inventories) to CML node definitions within a node/RAM budget: ready `cml_build_lab` spec, gaps, dropped devices |
| `cml_list_recipes` / `cml_verify_recipe` | Test-lab recipes, packaged and from `CML_RECIPE_DIRS` (no secrets returned; a recipe built on another shows it as `extends`; unused files under `skipped`); pass/fail verify contract of a running recipe lab (or a copy: `lab`, `substitute`; a lab built from a recipe's `extends:` base or a subset of it verifies too, with `built_from`) |
| `cml_get_link_scenarios` | Named link scenarios with netem values and expected round-trip ping deltas; with a lab, its conditioned links and flap jobs |
| `cml_export_topology` | Mermaid, draw.io or JSON diagram of a lab with interface addresses (day-0 config, snooped or CLI) |
| `cml_list_annotations` | A lab's drawn annotations (text, shapes), marking the ones this server wrote |
| `cml_search_spec` / `cml_get_definition` / `cml_api_call` | OpenAPI search, operation and schema details, raw GET |

**Write** (`MCP_ENABLE_WRITES=true`, all preview-first)

| Tool | What it does |
|---|---|
| `cml_build_lab` | Build a lab from `nodes=[{label, definition, config?, files?, credentials?, macs?, ...}]` and `links=["r1 r2", "r1:Ethernet0/1 sw1"]`. Interfaces are picked automatically, external connectors and node licences are checked; `${LAB_*}` lab secrets in config, files and credentials are filled in on the server (see below). Optionally start it (and wait) |
| `cml_load_sample_lab` | Create a lab from a sample lab |
| `cml_create_lab` / `cml_import_lab` | Create an empty lab, or create one from topology YAML (node definitions are checked; `${LAB_*}` lab secrets in its nodes are filled in on the server, see below) |
| `cml_start_lab` / `cml_stop_lab` | Start (waits for convergence) or stop a lab |
| `cml_stop_labs` | Stop several labs (a list, or every running lab except `keep`) with one preview: licences and RAM freed per lab, protected labs refused |
| `cml_add_node` / `cml_update_node` | Add a node; change its label, tags, position, resources or console login |
| `cml_set_node_config` | Replace a node's day-0 config; the preview shows a unified diff |
| `cml_set_node_state` | Start or stop one node |
| `cml_extract_node_configs` | Save running configs into the stored node configs |
| `cml_configure_node` | Push config lines to a running device over its console (`configure terminal` ... `end`, optionally `write memory`), or exec-mode lines (`mode='exec'`, e.g. FTD `configure manager add`). Rejected lines are reported |
| `cml_configure_nodes` | Push the same config lines to up to 20 running devices in one preview: templates with `{label}`, `{mgmt_ip}` and per-node `vars`, the rendered lines per node and `blast_radius` in the preview, the deny-list checked on every rendered line, `${LAB_*}` refused; a failing node doesn't stop the others |
| `cml_connect_nodes` | Link two nodes (first free interfaces, or the ones you name; a picked port is held for its preview, so parallel previews to one switch get different ports) |
| `cml_set_link_condition` | Add latency, jitter, loss, bandwidth limits, duplication or corruption to a link, or clear it |
| `cml_set_link_state` | Take a link down or bring it up (cable pull) |
| `cml_set_interface_state` | Take one interface down or up on a running node: only that end loses carrier, the peer stays up (FTD HA monitored interface, SD-WAN dead-WAN tests) |
| `cml_update_interface` | Pin an interface MAC (52:54:00:xx:xx:xx) or clear the pin (`auto`) so ISE MAB endpoints and DHCP bindings survive wipes and re-imports; the preview names the old MAC and what keys on it |
| `cml_start_capture` / `cml_stop_capture` | Packet capture on a link |
| `cml_capture` | Capture for N seconds and return the decoded summary in one call |
| `cml_save_capture` | Write a link's capture to a pcap file under `CML_CAPTURE_DIR` on the server host (Wireshark, TAC, evidence packs); returns only the path, SHA-256, size and packet count, never the bytes. `redact='radius'` blanks RADIUS authenticators, passwords, State/Class, secret AV-pairs and other vendors' VSA values first (IPv4 and IPv6) |
| `cml_capture_wireless` | Capture the simulated 802.11 medium at a wireless-ap / wireless-client node and decode it (SSIDs, auth/assoc, deauth reasons, EAPOL 4-way handshake, EAP identity/method) |
| `cml_build_recipe` | Build a test-lab recipe, packaged or from `CML_RECIPE_DIRS` (optionally start it), with annotations; `title` + `substitute` build a copy on other addresses; `extend=true` grows an existing lab into a superset recipe in place (adds only the missing nodes, links and notes, never changes an existing node) |
| `cml_run_recipe_action` | Run one of a recipe's actions on its lab, e.g. `ise-fmc-identity` `login-alice` / `login-bob` / `logoff` (802.1X as another AD user); the command comes from the recipe, never the caller |
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

**Lab files and specs with secrets.** A topology YAML for `cml_import_lab` can carry `${LAB_*}` references
instead of passwords and keys, e.g. a CML Cookbook file rendered with
`cookbook render <recipe> --input admin_password='${LAB_FTD_ADMIN_PASSWORD}'`. The server fills them in from the
same `LAB_*` variables or `CML_LAB_SECRETS_FILE` as recipes, only inside `nodes` (day-0 configs, pyATS logins) and
only in the YAML it sends to CML. The tool call, the preview, the confirm token, the result and the audit log
carry only the placeholders, and lab notes and annotations keep them as written. The preview's `lab_secrets`
lists which secret goes into which node. A variable the server doesn't have blocks the import, and the blocker
names it. The filled topology is re-serialised, so YAML quoting is handled, but a value lands in a config's text
as it is: keep `"` and `\` out of values used inside JSON day-0 configs. Unlike a recipe, the YAML comes from
the caller, and a node's day-0 config can do anything with the value it gets, so check `lab_secrets` before
you confirm. YAML without placeholders in its nodes is sent unchanged.

**Restoring a masked export.** `cml_export_lab` masks pyATS passwords as `'********'` and replaces a
`password:` / `plain_text_passwd:` line in a node file (cloud-init user-data) with `${LAB_NODE_PASSWORD}`. Set
`LAB_NODE_PASSWORD` on the server (or in `CML_LAB_SECRETS_FILE`) and `cml_import_lab` fills it into those nodes;
without it the import is blocked by name. Set the pyATS logins again after a restore (or export with
`include_credentials`). A lab bigger than one response comes back in pages: call again with
`offset=next_offset` until `complete`, join the `yaml` of every page in order, and check `sha256`.

`cml_build_lab` does the same for a node's `config`, `files` and `credentials`, e.g.
`"config": "username admin privilege 15 secret ${LAB_CLI_PASSWORD}"` with
`"credentials": {"username": "admin", "password": "${LAB_CLI_PASSWORD}"}`: the preview's `lab_secrets` names
the nodes per secret, a missing variable blocks the build by name, CML's warnings and errors come back with the
reference, and the lab description, labels and tags stay as written.

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
| `CML_LAB_SECRETS_FILE` | | dotenv file with the `LAB_*` values that recipes, `cml_import_lab` files and `cml_build_lab` specs reference as `${LAB_*}` (device passwords, keys, communities). `LAB_*` environment variables override it. Recipe builds, imports and lab builds name any missing variable |
| `CML_RECIPE_DIRS` | | More recipe directories (comma- or `:`-separated), e.g. a recipe checkout mounted read-only into the container, for `cml_list_recipes` / `cml_build_recipe` / `cml_verify_recipe` / `cml_run_recipe_action`. Read on every call (no restart). Trusted like the package (verify probes and actions run console commands). A packaged recipe wins on a name clash; `cml_list_recipes` lists unused files under `skipped` ([recipes README](src/cml_mcp/recipes/README.md#recipes-outside-the-package-cml_recipe_dirs)) |
| `CML_IMAGE_DIR` | | The only directory `cml_upload_image` reads (images are streamed from it; uploads are off without it) |
| `CML_CAPTURE_DIR` | | The only directory `cml_save_capture` writes pcap files to (`<lab>/<link>-<UTC time>.pcap`, mode 0600; saving is off without it) |
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

### Live tests

Live tests build throwaway labs named `mcp-test-*` from fast-booting IOL nodes, run every tool,
and always delete what they created. They read the controller from `.env` (`CML_URL` plus a login) and skip
without one. Optional inputs (commented in `.env.example`); the tests that need them skip when they are unset:

| Variable | Example | Used by |
|---|---|---|
| `CML_IMAGE_DIR` | `/srv/cml-images` | `test_live_images.py`: local directory the image is uploaded from |
| `CML_LIVE_IMAGE_FILE` | `cat8000v-universalk9_16G_serial.17.16.01a.qcow2` | `test_live_images.py`: a disk image file in `CML_IMAGE_DIR` |
| `CML_LIVE_IMAGE_NODE_DEFINITION` | `cat8000v` (the default) | `test_live_images.py`: node definition for that image |
| `CML_RO_USERNAME` / `CML_RO_PASSWORD`, `CML_RW_USERNAME` / `CML_RW_PASSWORD` | `mcp-cml-viewer`, `mcp-cml-operator` | `test_least_privilege.py` (`scripts/seed_lab.py --least-privilege`) |

`-m live_recipes` verifies only recipe labs that are already running on the controller.

## Licence

MIT
