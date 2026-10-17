"""Lab exports and recipes only set interface MACs CML accepts.

CML 2.x refuses a lab import (HTTP 400) when any custom interface mac_address has an OUI other than
52:54:00. IOL exports carried aa:bb:cc:xx:xx:xx MACs, so mcp-cml-ftd and mcp-test-seed failed to import
on a fresh controller; leave mac_address null (CML assigns one) or use 52:54:00:xx:xx:xx.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = sorted([*ROOT.glob("labs/*.yaml"), *ROOT.glob("src/cml_mcp/recipes/*.yaml")])
MAC_KEY = re.compile(r"^\s*-?\s*mac_address:\s*(.*?)\s*(#.*)?$")
ALLOWED = re.compile(r"(?i)52:54:00(:[0-9a-f]{2}){3}")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_custom_macs_use_cml_oui(path: Path) -> None:
    bad = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        m = MAC_KEY.match(line)
        if not m:
            continue
        value = m.group(1).strip("'\"")
        if value.lower() not in ("", "null", "~") and not ALLOWED.fullmatch(value):
            bad.append((n, value))
    assert not bad, f"{path.name}: mac_address outside 52:54:00 (CML import rejects it): {bad}"


def test_files_found() -> None:
    assert len(FILES) > 5
