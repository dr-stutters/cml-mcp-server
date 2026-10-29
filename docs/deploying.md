# Deploying cml-mcp-server on a shared host

One container serves a team: each person gets their own token, the server is read-only until you decide
otherwise, TLS ends at a reverse proxy, and one server can reach several CML controllers. Everything below is
in [`examples/shared-host/`](../examples/shared-host/); a laptop (stdio) setup is in the README quickstart.

## 1. What is safe by default

| Setting | Default | What it means |
|---|---|---|
| `MCP_ENABLE_WRITES` | `false` | write tools (build/start/stop labs, add nodes, configure devices, link conditioning, captures...) are **not registered** |
| `MCP_ENABLE_DANGEROUS` | `false` | wipe/delete labs and nodes, image upload, non-GET `cml_api_call`: not registered; needs writes on too |
| `MCP_AUTH_TOKENS` | none | the HTTP transport **refuses to start** without at least one token (or OAuth) |
| `MCP_DEFAULT_ROLE` | `ro` | once `MCP_ROLES` is set, a caller with no entry gets read tools only (without `MCP_ROLES` every token can use every enabled tier) |
| `CML_VERIFY_SSL` | `true` | the controller's certificate is checked; set `CML_CA_BUNDLE` for a private CA (or pin the controller's own certificate, `scripts/pin_controller.py`) |
| `CML_PROTECTED_LABS` / `CML_MANAGED_LABS` | none | safety rails once writes are on ([safety.md](safety.md)): labs no change may touch; labs the dangerous tools may wipe/delete |

Turning on writes is two decisions: the server (`MCP_ENABLE_WRITES=true`) and who may use them (`MCP_ROLES`).
Every write tool is preview-first: nothing changes until the caller repeats the call with the confirm token.
The contract tests (`tests/unit/test_tier_defaults.py`) fail if a default or a shipped config turns writes on.

## 2. The CML account (least privilege, step by step)

Give each server instance its **own** CML account, sized to the tiers you enable, and never the controller's
built-in `admin`. CML has no custom roles: an account is an admin or a regular user, and a **resource pool**
caps what it may start. Full mapping and the reasons: [least-privilege.md](least-privilege.md).

1. **Tools > Resource Pools**: create a template pool, then a pool from it (CML only assigns pools created from a
   template):
   - read-only server: `mcp-cml-viewer-pool` with **0** node licences, 0 CPUs, 0 RAM (a regular user with
     `lab_exec` could otherwise start nodes in CML itself);
   - writes on: `mcp-cml-operator-pool`, e.g. 12 licences / 24 CPUs / 64 GB (size it for your recipes:
     FTDv needs 8 GB each).
2. **Tools > User Management > Groups**: `mcp-cml-viewers` (or `mcp-cml-operators`).
3. **Tools > User Management > Users > Add**: `mcp-cml-viewer` (or `mcp-cml-operator`), **not** an admin, in
   that group, with that resource pool.
4. Share the labs the team should see with the group (**Lab > Sharing**, as the lab's owner or an admin):
   `lab_view` + `lab_exec` (`lab_exec` is needed for device consoles: with `lab_view` alone `cml_run_commands`
   times out). For writes on other people's labs add `lab_edit` (+ `lab_admin` to delete).
5. Dangerous tier: a regular user can wipe/delete its own labs; only `cml_upload_image` and changes to other
   users' labs need an admin. Create a separate admin account for that only if you need it.
6. Keep the password out of `.env`: `CML_PASSWORD_FILE=/run/secrets/cml_password` (Docker secret) or
   `CML_PASSWORD_REF=vault:...` (core `docs/PRODUCTION.md`, "Secrets").
7. Run the preflight; it compares the account with the enabled tiers:

   ```bash
   docker compose exec cml-mcp-server cml-mcp-server check
   ```

   `role` warns when an admin account sits behind a read-only server (least privilege) and when the dangerous
   tier is on for a regular user (admin-only tools will fail). With writes on, `licences` shows the node
   licences the account may start and warns when its pool leaves 0 free or the number is unknown.

`scripts/seed_lab.py --least-privilege` (in a clone, with an admin login in `.env`) creates both users, groups
and pools idempotently.

## 3. Per-user tokens (names in the audit log)

Give each person their own token; the token's name is the caller identity in previews, the audit log and
roles. Never share one token.

```bash
docker run --rm ghcr.io/dr-stutters/cml-mcp-server cml-mcp-server token alice
# prints the token (give it to alice) and the line for the server:  alice:sha256:<hex>
```

Collect the lines in `MCP_AUTH_TOKENS=alice:sha256:...,bob:sha256:...` (or one per line in a file named by
`MCP_AUTH_TOKENS_FILE`). Revoke a person by deleting their entry and restarting. With writes on, say who may
use them:

```bash
MCP_ROLES=alice:rw,bob:ro,oncall-*:admin    # ro = read, rw = + write, admin = + dangerous
```

The example writes the audit log to `/cache/cml-audit.log` (rotated at 50 MB, 5 files): one JSON line per
call, e.g. `{"audit": {"event": "tool_call", "tool": "cml_status", "caller": "alice", "args": {...},
"outcome": "ok"}}`, plus `preview` / `applied` events for writes. Ship it to your log platform, or set
`MCP_AUDIT_LOG=stderr` and use the container log driver.

Everyone acts on CML as the server's account: CML's own logs show that account, the audit log shows who asked.

## 4. The node-licence budget is shared

CML caps running licensed nodes per controller (external connectors and unmanaged switches don't count), and
every user of the server draws from the same account's resource pool. One person starting a large recipe can
leave nothing for the next.

- Size the account's pool for what the team runs at once; the start/build previews refuse to start more
  licensed nodes than are free (the pool or the controller licence, whichever is tighter).
- `cml_plan_licences(target)` says which labs to stop first (test labs before other people's) and whether RAM
  suffices; `cml_get_resource_usage` shows what is running; `cml_stop_labs` stops several at once.
- `/licensing` is admin-only: for a regular account the cap comes from its pool. Set `CML_NODE_LICENSE_LIMIT`
  if neither tells the server.
- Different teams with separate budgets: run one server instance (and one CML account with its own pool) per
  team.

## 5. Several CML controllers from one host

```bash
CML_URL=https://cml.corp.example            # the default instance
CML_USERNAME=mcp-cml-viewer
CML_PASSWORD_FILE=/run/secrets/cml_password
CML_INSTANCES=training                      # more controllers, each with its own variables:
CML_TRAINING_URL=https://cml-training.corp.example
CML_TRAINING_USERNAME=mcp-cml-viewer
CML_TRAINING_PASSWORD_FILE=/run/secrets/cml_training_password
CML_TRAINING_CA_BUNDLE=/certs/training-ca.pem   # URL, credentials and TLS are never inherited
CML_TRAINING_READ_ONLY=true                 # optional: block writes on this controller only
```

Every tool then takes an optional `instance` argument (`default` or `training`); `check` reports each
controller. Other settings are inherited from the default instance unless set with the instance's prefix, so set
`CML_TRAINING_NODE_LICENSE_LIMIT`, `CML_TRAINING_CONSOLE_KNOWN_HOSTS` and `CML_TRAINING_TLS_CHECK_HOSTNAME`
explicitly when that controller differs.

**Device consoles:** `cml_run_commands`, `cml_configure_node` and the other console tools reach the controller's
console server over SSH (`CML_CONSOLE_PORT`, 22) with the same account. Allow that port from the shared host to
every controller, and pin the host keys (`CML_CONSOLE_KNOWN_HOSTS`, a known_hosts file mounted read-only),
because the container has no `~/.ssh/known_hosts`. One console session per node per server process: concurrent
calls on the same node wait up to `CML_CONSOLE_LOCK_WAIT` seconds. The SSH transport (`transport='ssh'`, or
`'auto'` when a console is silent) connects from the server host to the node's own management address with its
pyATS credentials and checks the device's host key against the same known_hosts file, so add the lab devices'
keys there too when pinning is on.

## 6. TLS with a reverse proxy (Caddy)

The server speaks plain HTTP inside the compose network; Caddy terminates TLS on 443:

```bash
cd examples/shared-host
cp .env.example .env && chmod 600 .env       # fill in CML, tokens, MCP_HOSTNAME
docker compose up -d
curl https://mcp-cml.corp.example/health     # {"status":"ok"}
```

- `MCP_HOSTNAME=mcp-cml.corp.example` and `CADDY_TLS=you@corp.example`: a public name gets a Let's Encrypt
  certificate (ports 80/443 reachable from the internet).
- An internal name: `CADDY_TLS=internal` (Caddy's own CA; copy `/data/caddy/pki/authorities/local/root.crt`
  from the `caddy-data` volume to clients) or mount your own certificate and put
  `tls /certs/mcp.crt /certs/mcp.key` in the `Caddyfile`.
- The MCP server port is not published; only Caddy is. `flush_interval -1` keeps streamed responses flowing.

Clients then use `https://mcp-cml.corp.example/mcp` with `Authorization: Bearer <their token>`.

**Try it first without CML:** `docker compose -f docker-compose.yml -f docker-compose.mock.yml up -d` starts two
mocked controllers (`default`, `training`) and a demo token; `docker compose -f docker-compose.yml -f
docker-compose.mock.yml exec cml-mcp-server cml-mcp-server check` checks both, and
`curl -k https://localhost:8443/health` goes through Caddy.

## 7. Upgrades

- Images: `ghcr.io/dr-stutters/cml-mcp-server:<version>` (and `:latest`); release candidates are `:<version>-rcN`
  and `:rc`, never `:latest`. Pin a version on a shared host (`MCP_IMAGE_TAG=0.11.0`), read the
  [CHANGELOG](../CHANGELOG.md), then `docker compose pull && docker compose up -d`.
- Verify what you run (keyless cosign signature from the release workflow, plus a signed SBOM):

  ```bash
  cosign verify ghcr.io/dr-stutters/cml-mcp-server:0.11.0 \
    --certificate-identity-regexp '^https://github.com/dr-stutters/stutters-mcp-core/.github/workflows/publish-image.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository dr-stutters/cml-mcp-server
  ```

- After an upgrade run `check` again; a release that needs a new CML permission says so in the CHANGELOG.
- Roll back by setting `MCP_IMAGE_TAG` to the previous version. The server keeps no state besides the spec
  cache and the audit log (both in the `/cache` volume), so a rollback needs nothing else. Link flaps started
  by `cml_apply_link_scenario` are brought back up when the server stops.
- Upgrading CML: run `check`; `version` warns on a release outside the tested matrix (2.10 today; 2.7+ should
  work) and fails below 2.7.
