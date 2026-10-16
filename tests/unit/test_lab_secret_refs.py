"""Lab exports and recipes use the right ${LAB_*} reference for each kind of key.

LAB_RADIUS_SECRET (RADIUS/TACACS+ shared secrets toward ISE) and LAB_FTD_REG_KEY (the FTD's FMC
registration key) used to hold the same value, so a mix-up went unnoticed. They now differ, and a
wrong reference breaks the lab.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = sorted([*ROOT.glob("labs/*.yaml"), *ROOT.glob("src/cml_mcp/recipes/*.yaml")])
REF = re.compile(r"\$\{LAB_[A-Z0-9_]+\}")
# FMC registration: the FTD day-0 JSON field, or prose naming the registration / manager
REG_CONTEXT = re.compile(r"(?i)FmcRegKey|reg(istration)? key|configure manager|points at FMC|managed by FMC")
# RADIUS/TACACS+ keys: IOS 'key'/'server-key', hostapd/recipe shared secrets
AAA_CONTEXT = re.compile(r"(?i)server-key|shared_secret|^\s*key\s|radius|tacacs")


def refs(path: Path, name: str) -> list[tuple[int, str]]:
    """(line number, line without its ${LAB_*} references) for lines that reference LAB_<name>."""
    return [
        (n, REF.sub("", line))
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if "${LAB_" + name + "}" in line
    ]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_reg_key_only_for_fmc_registration(path: Path) -> None:
    bad = [
        n for n, text in refs(path, "FTD_REG_KEY") if not REG_CONTEXT.search(text) or AAA_CONTEXT.search(text)
    ]
    assert not bad, f"{path.name}: LAB_FTD_REG_KEY outside an FMC registration on lines {bad}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_radius_secret_not_for_fmc_registration(path: Path) -> None:
    bad = [n for n, text in refs(path, "RADIUS_SECRET") if REG_CONTEXT.search(text)]
    assert not bad, f"{path.name}: LAB_RADIUS_SECRET used as an FMC registration key on lines {bad}"


def test_files_found() -> None:
    assert len(FILES) > 5
