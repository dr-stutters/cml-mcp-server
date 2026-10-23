"""Fail when lab secrets appear in tracked files (L21). Run in CI and before committing recipe changes.

    uv run python scripts/check_secrets.py                       # values from LAB_* environment variables
    uv run python scripts/check_secrets.py --secrets-file /path/to/lab-secrets.env

Two checks over `git ls-files`:
1. **Known values**: every LAB_* value (from the environment and/or the dotenv file) must not occur in any
   tracked file. Values are only held in memory; findings name the variable, never the value. Values shorter
   than 6 characters (vendor defaults such as the IOL login) are too generic to search for and are skipped.
2. **Patterns** in recipe and lab-export YAML (`src/cml_mcp/recipes/`, `labs/`): a credential keyword
   (`secret`, `password`, `key`, `community`, `AdminPassword`, `FmcRegKey`, `server-key`, ...) followed by a
   literal value instead of a `${LAB_*}` reference. Vendor defaults and masks are allowed (see ALLOWED).

Exit status 1 on any finding.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

MIN_VALUE_LEN = 6
PATTERN_SCOPE = ("src/cml_mcp/recipes/", "labs/")
# keyword (not followed by "-": <last-password-change-time> is an element name), optional IOS encryption
# type digit, then the value
PATTERN = re.compile(
    r"""(?ix)
    (?:\b(?:secret|password|passwd|server-key|key|community|psk|regkey|fmcregkey|adminpassword)\b)(?!-)
    ["'`]?\s*[:=]?\s*["'`]?
    (?:[0-9]\s+)?
    (?P<value>[A-Za-z0-9!@#$%^&*+=_./-][^\s"'`,}]*)
    """
)
# values that are not secrets: references, masks, vendor defaults of fast lab images, and words that follow
# a keyword in ordinary text or config syntax
ALLOWED = re.compile(
    r"""(?x)^(
        \$\{?LAB_[A-Z0-9_]+\}?.* | \*+ | <[^>]+> | \$[0-9]\$.* | [0-9a-f]{32,} | [0-9]+ |
        [\w./-]+\.(?:key|pem|csr|crt|der|p12|pub)[;:,)]? | -{1,2}[a-zA-Z][\w-]* |
        (?i:cisco|admin|none|null|true|false|same|ro|rw|string|config|chain|generate|exchange|value|values|
            name|names|file|files|version|encryption|rsa|ipv4|ipv6|type|types|timeout|used|mode|for|is|was|
            are|the|in|of|to|from|with|on|and|or|as|at|by|reference|references|server|group|private|public|
            authentication|authorization|auth|dhcp|default|local|login|policy|chain-file|string-only)
    )$"""
)


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    return [root / p for p in out.decode().split("\0") if p]


def secret_values(secrets_file: str | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if secrets_file:
        from dotenv import dotenv_values

        path = Path(os.path.expanduser(secrets_file))
        if not path.is_file():
            sys.exit(f"secrets file not found: {path}")
        values.update({k: v for k, v in dotenv_values(path).items() if k.startswith("LAB_") and v})
    values.update({k: v for k, v in os.environ.items() if k.startswith("LAB_") and v})
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--secrets-file", help="dotenv file with LAB_* values")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument(
        "--require-values",
        action="store_true",
        help="fail when no LAB_* values are given",
    )
    args = parser.parse_args()
    root = Path(args.root)
    values = secret_values(args.secrets_file)
    searchable = {k: v for k, v in values.items() if len(v) >= MIN_VALUE_LEN}
    skipped = sorted(set(values) - set(searchable))
    if args.require_values and not searchable:
        print("check_secrets: no LAB_* values given (--require-values): set the LAB_* secrets")
        return 1
    findings: list[str] = []
    for path in tracked_files(root):
        rel = path.relative_to(root).as_posix()
        if rel == "scripts/check_secrets.py" or not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for name, value in searchable.items():
            if value.encode() in data:
                line = data[: data.index(value.encode())].count(b"\n") + 1
                findings.append(f"{rel}:{line}: the value of {name}")
        if rel.startswith(PATTERN_SCOPE) and rel.endswith((".yaml", ".yml")):
            text = data.decode(errors="replace")
            for n, line_text in enumerate(text.splitlines(), 1):
                for m in PATTERN.finditer(line_text):
                    if not ALLOWED.match(m.group("value")):
                        findings.append(f"{rel}:{n}: literal credential after {m.group(0).split()[0]!r}")
    print(
        f"check_secrets: {len(searchable)} LAB_* values searched"
        + (f" (too short to search: {', '.join(skipped)})" if skipped else "")
        + (" - none given: set LAB_* or --secrets-file to check values" if not values else "")
    )
    for f in findings:
        print(f"  {f}")
    if findings:
        print(f"{len(findings)} finding(s): replace the values with ${{LAB_*}} references (see docs).")
        return 1
    print("no secrets found in tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
