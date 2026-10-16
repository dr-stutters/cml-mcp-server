"""Lab recipes: ready-made `cml_build_lab` specs shipped with the package (`<name>.yaml` here).

A recipe has a `build:` section (exactly the cml_build_lab arguments), a `verify:` contract, and
descriptive fields (summary, address plan, credentials, what to configure on the other product).
"""

from __future__ import annotations

import json
import os
import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from cml_mcp._core import InvalidRequest
from cml_mcp.build import UNLICENSED_DEFINITIONS

RECIPE_DIR = Path(__file__).resolve().parent


@cache
def _load_all() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(RECIPE_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        if isinstance(data, dict) and isinstance(data.get("build"), dict):
            out[str(data.get("name") or path.stem)] = data
    return out


# Secrets in recipes are references: ${LAB_CLI_PASSWORD} etc., the same names as cml-mcp-server/labs/*.yaml.
PLACEHOLDER = re.compile(r"\$\{(LAB_[A-Z0-9_]+)\}")


def placeholders(value: Any) -> set[str]:
    """Every ${LAB_*} name used anywhere in `value`."""
    if isinstance(value, dict):
        return set().union(*(placeholders(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(placeholders(v) for v in value)) if value else set()
    return set(PLACEHOLDER.findall(value)) if isinstance(value, str) else set()


def lab_secrets(secrets_file: str | None) -> dict[str, str]:
    """LAB_* values: the dotenv-style `secrets_file` (if given and present), overridden by LAB_* env vars."""
    values: dict[str, str] = {}
    if secrets_file:
        path = Path(os.path.expanduser(secrets_file))
        if path.is_file():
            from dotenv import dotenv_values

            values.update({k: v for k, v in dotenv_values(path).items() if k.startswith("LAB_") and v})
    values.update({k: v for k, v in os.environ.items() if k.startswith("LAB_") and v})
    return values


# Values shorter than this are too generic to redact by value (e.g. a vendor default like 'cisco').
MIN_REDACT_LEN = 6


def secret_names_by_value(secrets_file: str | None) -> dict[str, str]:
    """{value: '${LAB_NAME}'} for every LAB_* value long enough to redact by value, longest first."""
    values = lab_secrets(secrets_file)
    pairs = sorted(
        ((v, f"${{{k}}}") for k, v in values.items() if len(v) >= MIN_REDACT_LEN), key=lambda p: -len(p[0])
    )
    return dict(pairs)


def redact_values(value: Any, mapping: dict[str, str]) -> Any:
    """`value` (str/dict/list) with every known lab secret value replaced by its ${LAB_*} reference."""
    if not mapping:
        return value
    if isinstance(value, str):
        for secret, ref in mapping.items():
            if secret in value:
                value = value.replace(secret, ref)
        return value
    if isinstance(value, dict):
        return {k: redact_values(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_values(v, mapping) for v in value]
    return value


def resolve_secrets(value: Any, secrets_file: str | None, *, what: str = "this recipe") -> Any:
    """`value` with every ${LAB_*} placeholder filled in. Raises InvalidRequest naming the missing
    variables (never any value). Only call this on what is sent to CML or used by a probe; previews,
    listings and annotations keep the placeholders."""
    names = placeholders(value)
    if not names:
        return value
    values = lab_secrets(secrets_file)
    missing = sorted(n for n in names if n not in values)
    multiline = sorted(n for n in names if n in values and ("\n" in values[n] or "\r" in values[n]))
    if multiline:
        raise InvalidRequest(f"Lab secret(s) {', '.join(multiline)} contain a line break; one line each.")
    if missing:
        raise InvalidRequest(
            f"{what} needs the lab secret(s) {', '.join(missing)}: set them as environment variables of "
            "the cml-mcp-server process or in the file named by CML_LAB_SECRETS_FILE (dotenv format, e.g. "
            "/path/to/lab-secrets.env). Recipes never store the values."
        )

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return PLACEHOLDER.sub(lambda m: values[m.group(1)], v)
        return v

    return walk(value)


def recipe_names() -> list[str]:
    return list(_load_all())


def get_recipe(name: str) -> dict[str, Any]:
    recipes = _load_all()
    if name not in recipes:
        raise InvalidRequest(f"No recipe {name!r}; available: {', '.join(recipes) or 'none'}")
    return recipes[name]


def recipe_for_lab(title: str) -> str | None:
    """The recipe whose build title is `title`, if any."""
    for name, r in _load_all().items():
        if r["build"].get("title") == title:
            return name
    return None


def recipe_licensed_nodes(recipe: dict[str, Any]) -> int:
    """Licensed nodes the recipe's lab runs (external connectors and unmanaged switches are free)."""
    return sum(
        1 for n in recipe["build"].get("nodes") or [] if n.get("definition") not in UNLICENSED_DEFINITIONS
    )


# Substitutions are for addresses and names (a copy on another IP, another hostname): plain tokens only,
# never secret keywords, so a mapping can't rename e.g. 'secret' to hide a value from the scrubbers or
# smuggle spaces/newlines into probe commands.
SUBST_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
SUBST_DENY = re.compile(r"(?i)secret|password|passwd|key|community|psk|cred|token")


def check_substitute(mapping: dict[str, str] | None) -> None:
    """Raise InvalidRequest unless every key and value is a plain address/name token."""
    for k, v in (mapping or {}).items():
        for part in (k, v):
            if not SUBST_TOKEN.fullmatch(part):
                raise InvalidRequest(
                    f"substitute {k!r} -> {v!r}: keys and values must be addresses or names "
                    "(letters, digits, . _ : / -; no spaces), 1-64 characters"
                )
            if SUBST_DENY.search(part) or "LAB_" in part.upper():
                raise InvalidRequest(f"substitute {k!r} -> {v!r}: credential keywords can't be substituted")


def substituted(value: Any, mapping: dict[str, str] | None) -> Any:
    """`value` (a recipe or part of one) with each key of `mapping` replaced by its value in every
    string, in one pass (a replacement is never replaced again) - e.g. {'198.18.128.154':
    '198.18.128.194'} to build or verify a copy of a recipe on another address. Longer keys win."""
    if not mapping:
        return value
    check_substitute(mapping)
    rx = re.compile("|".join(re.escape(k) for k in sorted(mapping, key=len, reverse=True)))

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return rx.sub(lambda m: mapping[m.group(0)], v)
        return v

    return walk(value)


# A recipe build records itself in the lab's notes, so cml_verify_recipe can verify a copy with the
# substitutions it was built with (L25). Substitutions are address/name tokens only, never secrets.
RECIPE_MARKER = "cml-mcp-recipe:"
_MARKER_LINE = re.compile(r"^cml-mcp-recipe:\s*(\{.*\})\s*$", re.M)


def recipe_marker(name: str, substitute: dict[str, str] | None) -> str:
    """The notes line a recipe's lab is built with."""
    return f"{RECIPE_MARKER} " + json.dumps({"recipe": name, "substitute": substitute or {}}, sort_keys=True)


def read_recipe_marker(notes: Any) -> dict[str, Any] | None:
    """{'recipe': name, 'substitute': {...}} from a lab's notes, or None."""
    m = _MARKER_LINE.search(notes) if isinstance(notes, str) else None
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except ValueError:
        return None
    sub = data.get("substitute")
    if not isinstance(data.get("recipe"), str) or not isinstance(sub, dict):
        return None
    return {"recipe": data["recipe"], "substitute": {str(k): str(v) for k, v in sub.items()}}


# Recipe actions (L34): named, packaged console commands that change a recipe lab's state the way a
# test needs (e.g. log the 802.1X client in as another user). Callers pick an action by name; the
# command itself always comes from the packaged recipe, never from tool input.
def recipe_actions(recipe: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{name: {description, node, command, expect, timeout}} of a recipe, validated."""
    raw = recipe.get("actions") or {}
    if not isinstance(raw, dict):
        raise ValueError(f"recipe {recipe.get('name')!r}: actions must be a mapping")
    labels = {n.get("label") for n in recipe["build"].get("nodes") or []}
    out: dict[str, dict[str, Any]] = {}
    for name, a in raw.items():
        if not isinstance(a, dict) or not isinstance(a.get("command"), str) or not a["command"].strip():
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} needs a command")
        if a.get("node") not in labels:
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} names an unknown node")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in a["command"]):
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} has control characters")
        if PLACEHOLDER.search(a["command"]):  # actions are sent as written: no secrets in them
            raise ValueError(
                f"recipe {recipe.get('name')!r}: action {name!r} must not carry ${{LAB_*}} references"
            )
        if a.get("expect"):
            re.compile(a["expect"])
        timeout = float(a.get("timeout") or 60)
        if not 1 <= timeout <= 600:
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} timeout must be 1-600 s")
        out[str(name)] = {
            "description": str(a.get("description") or ""),
            "node": a["node"],
            "command": a["command"],
            "expect": a.get("expect"),
            "timeout": timeout,
        }
    return out
