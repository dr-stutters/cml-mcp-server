"""Lab archives on the server host (L71, cml_archive_lab).

An archive is one directory under CML_ARCHIVE_DIR, named <lab title>-<UTC time>:

- topology.yaml: the lab's export (GET /labs/{id}/download), masked like cml_export_lab (pyATS passwords
  '********', node-file passwords ${LAB_NODE_PASSWORD}) and with every known lab secret value replaced by
  its ${LAB_*} reference, so cml_import_lab restores it with the server's own values
- configs/<node>.txt: each node's stored configuration from that YAML (one file per config file when a
  node has several), masked the same way
- README.md: purpose, date, source lab, recipe marker, node list and the restore steps
- archive.json: what cml_delete_lab / cml_wipe_lab read back (lab id, title, the lab's `modified` time,
  when it was archived)

No disk images. Files are mode 0600, directories 0700, nothing is ever overwritten, and nothing is written
outside CML_ARCHIVE_DIR (symlinks are resolved and refused).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cml_mcp._core import InvalidRequest
from cml_mcp.capture_files import inside, safe_component

MANIFEST = "archive.json"
STAMP = "%Y%m%dT%H%M%SZ"


def archive_root(archive_dir: str | None) -> Path:
    if not archive_dir:
        raise InvalidRequest(
            "Archiving labs is off: set CML_ARCHIVE_DIR to a directory on the server host (the archive is "
            "written there, never sent through MCP)."
        )
    root = Path(os.path.expanduser(archive_dir)).resolve()
    if not root.is_dir():
        raise InvalidRequest(f"CML_ARCHIVE_DIR {str(root)!r} is not a directory")
    return root


def optional_root(archive_dir: str | None) -> Path | None:
    """The archive root, or None when it is unset or not a directory (delete/wipe previews only warn)."""
    try:
        return archive_root(archive_dir)
    except InvalidRequest:
        return None


def node_files(node: dict[str, Any]) -> list[tuple[str, str]]:
    """[(file name, text)] for a node's stored configuration in export YAML (a string, or a list of
    {name, content} since CML 2.7)."""
    label = safe_component(str(node.get("label") or node.get("id") or "node"), "node")
    cfg = node.get("configuration")
    if isinstance(cfg, str):
        return [(f"{label}.txt", cfg)] if cfg.strip() else []
    if isinstance(cfg, dict) and cfg.get("content") is not None:
        cfg = [cfg]
    if not isinstance(cfg, list):
        return []
    files = [f for f in cfg if isinstance(f, dict) and f.get("content") is not None]
    if len(files) == 1:
        return [(f"{label}.txt", str(files[0]["content"]))]
    out: list[tuple[str, str]] = []
    for i, f in enumerate(files):
        name = safe_component(str(f.get("name") or f"file{i}"), f"file{i}").removesuffix(".txt")
        out.append((f"{label}--{name}.txt", str(f["content"])))
    return out


def _write(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def _new_dir(root: Path, stem: str, ts: str) -> Path:
    for n in range(1, 100):
        folder = root / (f"{stem}-{ts}" if n == 1 else f"{stem}-{ts}-{n}")
        if not inside(root, folder):
            raise InvalidRequest(f"{stem!r} resolves outside CML_ARCHIVE_DIR")
        try:
            folder.mkdir(mode=0o700)
        except FileExistsError:
            continue
        if not inside(root, folder) or folder.is_symlink() or not folder.resolve().is_dir():
            raise InvalidRequest(f"{stem!r} resolves outside CML_ARCHIVE_DIR")  # swapped after mkdir
        return folder
    raise InvalidRequest("Too many archives of this lab this second; try again")


def write_archive(
    root: Path,
    title: str,
    lab_id: str,
    topology_yaml: str,
    configs: list[tuple[str, str]],
    readme: str,
    manifest: dict[str, Any],
    now: datetime,
) -> Path:
    """Write one archive directory (module docstring) and return it."""
    folder = _new_dir(root, safe_component(title, lab_id), now.strftime(STAMP))
    _write(folder / "topology.yaml", topology_yaml)
    cfg_dir = folder / "configs"
    cfg_dir.mkdir(mode=0o700)
    for name, text in configs:
        _write(cfg_dir / name, text if text.endswith("\n") else text + "\n")
    _write(folder / "README.md", readme)
    _write(folder / MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return folder


def readme_text(
    *,
    title: str,
    lab_id: str,
    purpose: str | None,
    archived_at: datetime,
    description: str | None,
    recipe: dict[str, Any] | None,
    nodes: list[dict[str, Any]],
    extracted: list[str],
    not_extracted: dict[str, str],
    config_files: list[str],
) -> str:
    lines = [
        f"# Lab archive: {title}",
        "",
        f"- Purpose: {purpose or '(not given)'}",
        f"- Archived: {archived_at.strftime('%Y-%m-%d %H:%M:%S UTC')} by cml_archive_lab",
        f"- Source lab: {title} ({lab_id})",
    ]
    if description:
        lines.append(f"- Description: {description}")
    if recipe:
        sub = recipe.get("substitute") or {}
        lines.append(
            f"- Recipe: {recipe['recipe']}"
            + (f" (substitute: {json.dumps(sub, sort_keys=True)})" if sub else "")
        )
    else:
        lines.append("- Recipe: none (no cml-mcp-recipe marker in the lab notes)")
    lines += [
        "",
        "## Nodes",
        "",
        "| Node | Definition | State at archive | Running config |",
        "|---|---|---|---|",
    ]
    for n in nodes:
        label = str(n.get("label"))
        how = (
            "extracted"
            if label in extracted
            else f"not extracted: {not_extracted[label]}"
            if label in not_extracted
            else "stored config only"
        )
        lines.append(f"| {label} | {n.get('node_definition')} | {n.get('state')} | {how} |")
    lines += [
        "",
        "## Files",
        "",
        "- `topology.yaml`: the CML topology export with the node configurations (no disk images).",
        "  pyATS passwords are '********' and node-file passwords `${LAB_NODE_PASSWORD}`; lab secret values",
        "  are `${LAB_*}` references. Other secrets inside device configs (enable secrets, keys) are kept as",
        "  the device had them: keep this directory private.",
        "- `configs/`: each node's stored configuration, one file per node"
        + (f" ({len(config_files)} files)." if config_files else " (none had one)."),
        f"- `{MANIFEST}`: what cml_delete_lab / cml_wipe_lab previews compare with the lab.",
        "",
        "## Restore",
        "",
        "1. cml_import_lab(topology=<contents of topology.yaml>, title='<new title>'): `${LAB_*}` references",
        "   are filled from the server's LAB_* values (CML_LAB_SECRETS_FILE); missing ones block the import.",
        "2. cml_start_lab, then cml_wait_for_converged.",
        "3. Check it: cml_diff_node_config(node, against='day0') on the copy, or cml_verify_recipe(recipe,",
        "   lab=<copy>) for a recipe lab. A pyATS password shown as '********' must be set again",
        "   (cml_update_node) before cml_run_commands can log in with it.",
        "",
    ]
    return "\n".join(lines)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def latest_archive(root: Path, lab: dict[str, Any]) -> dict[str, Any] | None:
    """The newest archive of `lab` under `root` (matched by lab id in archive.json): {path, archived_at,
    lab_modified}. Unreadable or foreign entries are skipped."""
    best: tuple[datetime, dict[str, Any]] | None = None
    try:
        entries = list(root.iterdir())
    except OSError:
        return None
    for d in entries:
        try:
            if d.is_symlink() or not d.is_dir():
                continue
            data = json.loads((d / MANIFEST).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get("lab_id") != lab.get("id"):
            continue
        at = _parse_time(data.get("archived_at"))
        if at is None:
            continue
        if best is None or at > best[0]:
            best = (
                at,
                {
                    "path": str(d),
                    "archived_at": data["archived_at"],
                    "lab_modified": data.get("lab_modified"),
                },
            )
    return best[1] if best else None


def archive_check(archive_dir: str | None, lab: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """(details for a delete/wipe preview, a warning or None): is there an archive of this lab at least as
    new as its last change?"""
    root = optional_root(archive_dir)
    if root is None:
        why = "CML_ARCHIVE_DIR is not set" if not archive_dir else "CML_ARCHIVE_DIR is not a directory"
        return {"latest": None, "note": why}, (
            f"WARNING: no lab archive can be checked ({why}); running configs that were never extracted are "
            "lost. Archive first with cml_archive_lab where it is set, or export with cml_export_lab."
        )
    latest = latest_archive(root, lab)
    if latest is None:
        return {"latest": None}, (
            "WARNING: this lab has never been archived; configs that were never extracted are lost. "
            "Archive it first: cml_archive_lab."
        )
    details: dict[str, Any] = {"latest": latest["archived_at"], "path": latest["path"]}
    modified = _parse_time(lab.get("modified"))
    archived = _parse_time(latest["archived_at"])
    unchanged = latest.get("lab_modified") is not None and latest.get("lab_modified") == lab.get("modified")
    if modified is not None and archived is not None and archived < modified and not unchanged:
        details["lab_modified"] = lab.get("modified")
        return details, (
            f"WARNING: the latest archive ({latest['archived_at']}) is older than the lab's last change "
            f"({lab.get('modified')}). Archive it again first: cml_archive_lab."
        )
    if str(lab.get("state")) in ("STARTED", "QUEUED", "BOOTED"):
        details["note"] = (
            "The lab is running: device configs changed since the archive are not in it (cml_archive_lab "
            "extracts them)"
        )
    return details, None
