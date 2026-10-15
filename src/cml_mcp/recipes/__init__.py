"""Lab recipes: ready-made `cml_build_lab` specs shipped with the package (`<name>.yaml` here).

A recipe has a `build:` section (exactly the cml_build_lab arguments), a `verify:` contract, and
descriptive fields (summary, address plan, credentials, what to configure on the other product).
"""

from __future__ import annotations

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
