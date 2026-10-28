# Safety rails for `cml-mcp-server`

Production controllers hold other people's labs. These rails sit on top of core's G7 rails (`MCP_DRY_RUN`,
`MCP_CHANGE_WINDOW`, `MCP_MAX_BLAST_RADIUS`, `MCP_DENY_TOOLS`, `MCP_TWO_PERSON_TOOLS`; core docs/PRODUCTION.md).
All are off or permissive by default except the device-command deny-list and TLS verification. A refused change
is a preview with `status: "blocked"` and no confirm token; the blocker names the setting.

| Setting | Effect |
|---|---|
| `CML_PROTECTED_LABS=customer-*,prod-*,<lab id>` | No write or dangerous tool changes a matching lab (title glob, case-insensitive, or lab id). Reads work |
| `CML_MANAGED_LABS=mcp-*` | The dangerous tools (`cml_wipe_lab`, `cml_delete_lab`, `cml_wipe_node`, `cml_delete_node`, `cml_delete_link`) only act on matching labs |
| `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES="cml_build_*=20,cml_*_lab=30"` | Every CML change reports `blast_radius` = nodes affected (lab start/stop/wipe/delete/extract: all nodes of the lab; builds: nodes built; node tools: 1) and core blocks it above the limit. This is the "maximum nodes per build" rail |
| `CML_CONFIG_DENY_DEFAULTS` (default `true`) | `cml_configure_node` and `cml_configure_nodes` (every rendered line) refuse destructive device commands: `write erase`, `erase`, `reload`, `format`, `delete`, `crypto key zeroize`, FTD `configure manager delete` / `configure factory-default`, `system support reset/reboot`, Linux `reboot`/`halt`/`poweroff`/`shutdown -h|-r`, `rm -r`, `mkfs`, `dd if=` (also with `do `) |
| `CML_CONFIG_DENY='clear\s+ip\s+ospf\|debug\s+all'` | One extra regex (use `\|` for several), matched at the start of each line |
| `CML_VERIFY_SSL` (default `true`), `CML_CA_BUNDLE`, `CML_TLS_CHECK_HOSTNAME` | TLS to the API. A self-signed CML certificate is pinned with `CML_CA_BUNDLE=<its PEM>`; when its name doesn't match `CML_URL` (CN=cml-controller, URL by IP) add `CML_TLS_CHECK_HOSTNAME=false` (refused unless the CA bundle holds exactly one certificate: a pin, not a CA list) |
| `CML_CONSOLE_KNOWN_HOSTS` | Pinned SSH host key of the console server (device CLI). Without it, `~/.ssh/known_hosts` is used when TLS is verified; with `CML_VERIFY_SSL=false` the key isn't checked (lab mode) |

The deny-list guards against accidents (a model typing `reload` or `wr er`), including the CLI's abbreviations and
`sudo`/path variants on Linux nodes. It is not a security boundary: device aliases or scripts can still run such
commands. Control characters inside a line (a second command after `\r`) are refused.

`cml_status` → `cml.security` shows the TLS and console host-key mode, the protected/managed patterns and the
number of deny rules.

**Pinning a controller** (trust on first use; compare the fingerprints with the controller's):

```bash
uv run python scripts/pin_controller.py https://cml.example.com --out ~/.config/cml-mcp-server
# prints the certificate and SSH host-key fingerprints and the CML_* lines to add
```

Not covered: `cml_api_call` with a non-GET method (core's raw escape hatch, dangerous tier and admin role only).

Tested (CML 2.10, 2026-10-15): unit tests in `tests/unit/test_safety.py`; live `tests/live/test_live_safety.py`
(pinned certificate + host key: status and console commands work; a wrong host key is refused; the pinned
certificate with host-name checking on is refused; a protected lab's stop/delete previews are blocked).
