"""CML safety rails (L20) on top of core's G7 rails (dry-run, change windows, blast radius, two-person).

Every write and dangerous tool goes through `guarded_preview_or_apply`, which adds these CML-specific checks
to the plan before core's preview/confirm logic runs:

- **Protected labs** (`CML_PROTECTED_LABS`): comma-separated title globs (case-insensitive) or lab ids. No
  write or dangerous tool may change a matching lab; reads are unaffected.
- **Managed labs** (`CML_MANAGED_LABS`): when set, the dangerous tools (wipe/delete of labs, nodes, links)
  only act on labs whose title matches one of these globs, e.g. `mcp-*`. Everything else is somebody else's.
- **Blast radius**: the number of nodes a change touches (whole-lab start/stop/wipe/delete: every node in the
  lab; builds: the nodes built; node tools: 1), so `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES`
  (core) can cap e.g. `cml_build_*=20`.
- **Device command deny-list** for `cml_configure_node` / `cml_configure_nodes`: `write erase`, `erase`,
  `reload`, `format`, `delete`, `crypto key zeroize`, FTD `configure manager delete`, ...
  (`CML_CONFIG_DENY` adds one regex, `|` for several; `CML_CONFIG_DENY_DEFAULTS=false` drops the defaults).

A blocked preview has `status: "blocked"` and no confirm token; the blocker says which setting caused it.
`cml_api_call` (dangerous tier, admin role) is core's raw escape hatch and is not covered by these rails.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context

from cml_mcp._core import NotFound, Plan, get_client, get_settings, preview_or_apply
from cml_mcp.client import RESOLVED_LABS, CmlApp

# Tools that act on every node of a lab (blast radius = node count).
LAB_WIDE = {
    "cml_start_lab",
    "cml_stop_lab",
    "cml_wipe_lab",
    "cml_delete_lab",
    "cml_extract_node_configs",
    "cml_clear_link_scenarios",
}
DANGEROUS = {"cml_wipe_lab", "cml_delete_lab", "cml_wipe_node", "cml_delete_node", "cml_delete_link"}

# Device commands that destroy state or take a node down. Matched per line, case-insensitive, after
# leading whitespace and an optional 'do '.
DEFAULT_CONFIG_DENY = (
    # IOS/IOS-XE/NX-OS, with the abbreviations the CLI accepts ('wr er', 'rel', 'del flash:')
    r"w(?:r(?:i(?:t(?:e)?)?)?)?\s+e(?:r(?:a(?:s(?:e)?)?)?)?\b",
    r"era(?:s(?:e)?)?\b",
    r"rel(?:o(?:a(?:d)?)?)?\b",
    r"form(?:a(?:t)?)?\b",
    r"del(?:e(?:t(?:e)?)?)?\b",
    r"cry\w*\s+key\s+zer\w*",
    # FTD / ASA
    r"conf\w*\s+manager\s+del\w*",
    r"conf\w*\s+factory-default",
    r"clear\s+conf\w*\s+all\b",
    r"sys\w*\s+support\s+(?:reset|reboot)",
    # Linux nodes
    r"(?:sudo\s+)?(?:\S*/)?(?:reboot|halt|poweroff)\b",
    r"(?:sudo\s+)?(?:\S*/)?init\s+[06]\b",
    r"(?:sudo\s+)?(?:\S*/)?shutdown\s+(?:-|now\b|\+)",
    r"(?:sudo\s+)?systemctl\s+(?:reboot|poweroff|halt)\b",
    r"(?:sudo\s+)?(?:\S*/)?rm\s+(?:.*\s)?(?:-[a-zA-Z]*[rR]|--recursive)",
    r"(?:sudo\s+)?(?:mkfs\S*|dd\s+if=)",
    r"(?:sudo\s+)?(?:ba|z)?sh\s+-c\b",
)


def _patterns(raw: str | None) -> list[str]:
    return [p.strip() for p in (raw or "").split(",") if p.strip()]


def lab_matches(lab: dict[str, Any], patterns: list[str]) -> str | None:
    """The first pattern matching the lab (title glob, case-insensitive, or the lab id), else None."""
    title = str(lab.get("lab_title") or "").lower()
    lab_id = str(lab.get("id") or "").lower()
    for p in patterns:
        if p.lower() == lab_id or fnmatch.fnmatchcase(title, p.lower()):
            return p
    return None


def config_deny_rules(settings: Any) -> list[re.Pattern[str]]:
    rules = list(DEFAULT_CONFIG_DENY) if getattr(settings, "config_deny_defaults", True) else []
    extra = (getattr(settings, "config_deny", None) or "").strip()
    if extra:
        rules.append(extra)
    return [deny_rule(r) for r in rules]


def deny_rule(pattern: str) -> re.Pattern[str]:
    """A deny pattern anchored at the start of a line (after blanks and an optional IOS 'do ')."""
    return re.compile(r"^\s*(?:do\s+)?(?:" + pattern + ")", re.IGNORECASE)


def denied_lines(lines: list[str], settings: Any) -> list[str]:
    """The lines a cml_configure_node call may not send (deny-list), in order."""
    rules = config_deny_rules(settings)
    return [line for line in lines if any(r.search(line) for r in rules)]


async def _lab_of(app: CmlApp, args: dict[str, Any]) -> dict[str, Any] | None:
    ref = args.get("lab")
    if not isinstance(ref, str) or not ref.strip():
        return None
    seen = RESOLVED_LABS.get()
    if seen and ref in seen:  # the lab this tool call resolved (and its apply acts on)
        return seen.pop(ref)
    try:
        return await app.resolve_lab(ref, exact=True)
    except NotFound:
        return None  # the tool reports the missing lab itself


async def lab_blockers(
    ctx: Context, tool: str, args: dict[str, Any], lab: dict[str, Any] | None
) -> list[str]:
    settings = get_settings(ctx)
    if lab is None:
        return []
    out: list[str] = []
    title = lab.get("lab_title") or lab.get("id")
    if p := lab_matches(lab, _patterns(getattr(settings, "protected_labs", None))):
        out.append(
            f"Lab {title!r} is protected (CML_PROTECTED_LABS matches {p!r}): no changes through this server."
        )
    managed = _patterns(getattr(settings, "managed_labs", None))
    if tool in DANGEROUS and managed and not lab_matches(lab, managed):
        out.append(
            f"Lab {title!r} is not managed by this server (CML_MANAGED_LABS={','.join(managed)!r}): "
            f"{tool} only wipes or deletes managed labs."
        )
    return out


async def blast_radius(
    app: CmlApp, tool: str, args: dict[str, Any], lab: dict[str, Any] | None
) -> int | None:
    if tool in LAB_WIDE and lab is not None:
        count = lab.get("node_count")
        if not isinstance(count, int):
            count = len(await app.list_nodes(str(lab["id"])))
        return count
    nodes = args.get("nodes")
    if isinstance(nodes, list) and nodes:
        return len(nodes)
    if isinstance(args.get("node"), str) or tool in ("cml_delete_link", "cml_set_link_state"):
        return 1
    return None


async def guarded_preview_or_apply(
    ctx: Context,
    *,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
    plan: Plan,
    apply: Callable[[], Awaitable[Any]],
) -> dict[str, Any]:
    """core.preview_or_apply with the CML rails added to `plan` (see the module docstring)."""
    app: CmlApp = get_client(ctx)
    lab = await _lab_of(app, args)
    plan.blockers = [*plan.blockers, *await lab_blockers(ctx, tool, args, lab)]
    if plan.blast_radius is None:
        plan.blast_radius = await blast_radius(app, tool, args, lab)
    return await preview_or_apply(ctx, tool=tool, args=args, confirm=confirm, plan=plan, apply=apply)


def security_status(settings: Any) -> dict[str, Any]:
    """What cml_status reports about the rails and transport security."""
    if settings.ca_bundle is not None:
        tls = "verified against CML_CA_BUNDLE" + (
            ""
            if getattr(settings, "tls_check_hostname", True)
            else " (pinned certificate; host name not checked)"
        )
    else:
        tls = "verified (system CAs)" if settings.verify_ssl else "NOT verified (CML_VERIFY_SSL=false)"
    if settings.console_known_hosts:
        console = "host key checked against CML_CONSOLE_KNOWN_HOSTS"
    elif settings.verify_ssl or settings.ca_bundle is not None:
        console = "host key checked against ~/.ssh/known_hosts"
    else:
        console = "host key NOT checked"
    return {
        "tls": tls,
        "console_ssh": console,
        "protected_labs": _patterns(getattr(settings, "protected_labs", None)) or None,
        "managed_labs": _patterns(getattr(settings, "managed_labs", None)) or None,
        "config_deny": len(config_deny_rules(settings)),
    }
