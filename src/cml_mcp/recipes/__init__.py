"""Lab recipes: ready-made `cml_build_lab` specs shipped with the package (`<name>.yaml` here).

A recipe has a `build:` section (exactly the cml_build_lab arguments), a `verify:` contract, and
descriptive fields (summary, address plan, credentials, what to configure on the other product).
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from stutters_mcp_core import InvalidRequest

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
            if SUBST_DENY.search(part):
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
