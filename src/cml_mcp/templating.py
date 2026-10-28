"""Per-node line templates for cml_configure_nodes (L49): `{label}`, `{mgmt_ip}` and caller variables.

A template is a configuration line with `{name}` placeholders; `{{` and `}}` stand for literal braces.
Values are plain single-line text. Lab secrets (`${LAB_*}`) are never filled in here: recipes and
lab files carry them, and this tool refuses them in lines and variables alike (the recipe loader's
rule for substitutions).
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER = re.compile(r"\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_]*)\}")
VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
LAB_REF = re.compile(r"\$\{\s*LAB_", re.IGNORECASE)
BUILTINS = ("label", "mgmt_ip")
MAX_VALUE = 512


def placeholders(lines: list[str]) -> set[str]:
    """Every `{name}` used in `lines` (escaped braces excluded)."""
    return {m.group(1) for line in lines for m in PLACEHOLDER.finditer(line) if m.group(1)}


def vars_problems(node: str, values: dict[str, Any]) -> list[str]:
    """Why a node's variables can't be used (bad names, multi-line values, lab-secret references)."""
    out = []
    for name, value in values.items():
        text = str(value)
        if not VAR_NAME.fullmatch(name):
            out.append(f"{node}: variable name {name!r}: letters, digits and '_', not starting with a digit")
        elif name.upper().startswith("LAB_") or LAB_REF.search(text):
            out.append(
                f"{node}: variable {name!r} refers to a lab secret (${{LAB_*}}); lab secrets are filled in "
                "only by recipes and lab files (cml_build_recipe, cml_build_lab), never by caller variables"
            )
        elif any(ch < " " and ch != "\t" for ch in text):
            out.append(f"{node}: variable {name!r} must be a single line (no newlines or control characters)")
        elif len(text) > MAX_VALUE:
            out.append(f"{node}: variable {name!r} is longer than {MAX_VALUE} characters")
    return out


def render(lines: list[str], values: dict[str, str]) -> tuple[list[str], list[str]]:
    """(`lines` with every placeholder filled in, names that have no value)."""
    missing: list[str] = []

    def fill(m: re.Match[str]) -> str:
        token = m.group(0)
        if token in ("{{", "}}"):
            return token[0]
        name = m.group(1)
        if name in values:
            return values[name]
        if name not in missing:
            missing.append(name)
        return token

    return [PLACEHOLDER.sub(fill, line) for line in lines], missing
