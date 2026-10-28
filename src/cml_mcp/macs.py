"""Interface MAC addresses: parse, normalise to CML's Linux format, and check CML's import rule.

CML stores an interface MAC as 'aa:bb:cc:dd:ee:ff'. A lab export carries it as `mac_address`, and CML's
import rejects any MAC outside the QEMU/KVM locally administered block 52:54:00 (tests/unit/test_lab_macs.py),
so a MAC this server pins must sit in that block or the next re-import of the lab fails.
"""

from __future__ import annotations

import re

CML_OUI = "52:54:00"
_HEX = re.compile(r"[0-9a-f]{12}")


def normalise_mac(raw: str) -> str:
    """'52-54-00-AB-CD-EF', '5254.00ab.cdef' or '52:54:00:ab:cd:ef' -> '52:54:00:ab:cd:ef'.
    ValueError when it isn't a 48-bit MAC."""
    digits = re.sub(r"[\s:.\-]", "", raw.strip().lower())
    if not _HEX.fullmatch(digits):
        raise ValueError(f"{raw!r} is not a MAC address (12 hex digits, e.g. 52:54:00:12:34:56)")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def mac_problem(raw: str) -> str | None:
    """Why CML would not keep this MAC across an export/import, or None when it is fine."""
    try:
        mac = normalise_mac(raw)
    except ValueError as e:
        return str(e)
    if not mac.startswith(CML_OUI + ":"):
        return (
            f"MAC {mac} is outside {CML_OUI}:xx:xx:xx; CML's lab import rejects it, so the lab could not be "
            f"re-imported. Use {CML_OUI}:xx:xx:xx (or leave it unset and CML assigns one)"
        )
    return None
