"""Saving a link capture to a file on the server host (L78, cml_save_capture).

The pcap bytes never reach the model: they go to a file under CML_CAPTURE_DIR, and the tool returns the
path, SHA-256, size and packet count only. `redact_radius` overwrites the RADIUS fields that carry or
expose secrets in place (lengths kept, so Wireshark still decodes the exchange):

- the 16-byte Authenticator (with a request/response pair it allows an offline attack on the shared secret)
- User-Password, CHAP-Password, CHAP-Challenge, State, Class, Tunnel-Password, Message-Authenticator
- Cisco AV-pair values outside the allow-list the decoder shows (pcap.SAFE_AVPAIRS): masked with '*'
- the payload of later IPv4 fragments of a RADIUS datagram (big EAP-TLS messages), which can't be parsed

The UDP checksum of a changed datagram is set to 0 (no checksum, valid for IPv4).
"""

from __future__ import annotations

import os
import re
import struct
from datetime import UTC, datetime
from pathlib import Path

from cml_mcp._core import InvalidRequest
from cml_mcp.pcap import LINKTYPE_ETHERNET, PCAP_MAGIC, RADIUS_PORTS, RADIUS_SECRET, SAFE_AVPAIRS

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
AVPAIR_BYTES = re.compile(rb"[=*]")  # the decoder's AVPAIR_SPLIT, on the raw bytes


def safe_component(text: str, fallback: str) -> str:
    """One path component from a lab title or link label: safe characters only, never '.' or '..'."""
    out = UNSAFE.sub("_", text).strip("._-")[:64]
    return out or fallback


def capture_root(capture_dir: str | None) -> Path:
    if not capture_dir:
        raise InvalidRequest(
            "Saving captures is off: set CML_CAPTURE_DIR to a directory on the server host (the pcap is "
            "written there, never sent through MCP)."
        )
    root = Path(os.path.expanduser(capture_dir)).resolve()
    if not root.is_dir():
        raise InvalidRequest(f"CML_CAPTURE_DIR {str(root)!r} is not a directory")
    return root


def check_name(name: str | None) -> None:
    if name is not None and not NAME_RE.fullmatch(name):
        raise InvalidRequest(
            f"File name {name!r}: letters, digits, '.', '_' and '-' only, up to 64 characters (no paths)"
        )


def inside(root: Path, path: Path) -> bool:
    """`path` (resolved, so symlinks count) is strictly below `root`."""
    try:
        resolved = path.resolve()
    except (OSError, ValueError):
        return False
    return resolved != root and root in resolved.parents


def write_capture(root: Path, lab_dir: str, stem: str, data: bytes, now: datetime | None = None) -> Path:
    """Write `data` to <root>/<lab_dir>/<stem>-<UTC timestamp>.pcap (mode 0600, never overwriting) and
    return the path. Refuses anything that resolves outside `root` (e.g. a symlinked lab directory)."""
    folder = root / lab_dir
    if not inside(root, folder):
        raise InvalidRequest(f"{lab_dir!r} resolves outside CML_CAPTURE_DIR")
    folder.mkdir(mode=0o700, exist_ok=True)
    if not inside(root, folder) or not folder.resolve().is_dir():  # re-check after mkdir (symlink swap)
        raise InvalidRequest(f"{lab_dir!r} resolves outside CML_CAPTURE_DIR")
    ts = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 100):
        path = folder / (f"{stem}-{ts}.pcap" if n == 1 else f"{stem}-{ts}-{n}.pcap")
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path
    raise InvalidRequest("Too many captures saved this second; try again")


# --- RADIUS redaction --------------------------------------------------------------------------------


class Redaction:
    def __init__(self) -> None:
        self.packets = 0
        self.attributes = 0
        self.fragments = 0

    def as_dict(self) -> dict[str, int]:
        return {"packets": self.packets, "attributes": self.attributes, "fragments": self.fragments}


def _redact_radius(buf: bytearray, start: int, end: int, stats: Redaction) -> bool:
    """Overwrite the secret-bearing parts of the RADIUS message in buf[start:end]; True if it changed."""
    if end - start < 4:
        return False
    if end - start < 20:  # cut inside the header (a first fragment): blank what there is of the Authenticator
        buf[start + 4 : end] = b"\x00" * (end - start - 4)
        return True
    length = struct.unpack("!H", buf[start + 2 : start + 4])[0]
    stop = min(start + max(length, 20), end)
    buf[start + 4 : start + 20] = b"\x00" * 16  # Authenticator
    i = start + 20
    while i + 2 <= stop:
        t, ln = buf[i], buf[i + 1]
        if ln < 2:
            break
        last = min(i + ln, stop)  # an attribute cut by a fragment boundary is redacted up to the cut
        if t in RADIUS_SECRET:
            buf[i + 2 : last] = b"\x00" * (last - i - 2)
            stats.attributes += 1
        elif t == 26 and last - i >= 8 and struct.unpack("!I", buf[i + 2 : i + 6])[0] == 9:
            j = i + 6  # Cisco VSA: sub-attributes
            while j + 2 <= last and buf[j + 1] >= 2:
                sub_end = min(j + buf[j + 1], last)
                if buf[j] == 1:  # Cisco-AVPair "key=value" / "key*value"
                    raw = bytes(buf[j + 2 : sub_end])
                    m = AVPAIR_BYTES.search(raw)
                    key = raw[: m.start()].decode("utf-8", "replace").strip().lower() if m else ""
                    if not m or key not in SAFE_AVPAIRS:
                        cut = j + 2 + (m.end() if m else 0)
                        buf[cut:sub_end] = b"*" * (sub_end - cut)
                        stats.attributes += 1
                j += buf[j + 1]
        i += ln
    return True


def redact_radius(data: bytes) -> tuple[bytes, Redaction]:
    """A copy of the classic Ethernet pcap `data` with RADIUS secrets overwritten (module docstring)."""
    if len(data) < 24 or data[:4] not in PCAP_MAGIC:
        raise InvalidRequest("Not a classic pcap file; can't redact it")
    endian = PCAP_MAGIC[data[:4]][0]
    if struct.unpack(endian + "I", data[20:24])[0] != LINKTYPE_ETHERNET:
        raise InvalidRequest("redact='radius' needs an Ethernet capture")
    buf = bytearray(data)
    stats = Redaction()
    radius_frags: set[tuple[bytes, bytes, int]] = set()  # (src, dst, IP id) of fragmented RADIUS datagrams
    off = 24
    while off + 16 <= len(buf):
        incl = struct.unpack(endian + "I", buf[off + 8 : off + 12])[0]
        start, end = off + 16, min(off + 16 + incl, len(buf))
        off += 16 + incl
        try:
            if _redact_frame(buf, start, end, radius_frags, stats):
                stats.packets += 1
        except (IndexError, struct.error):
            continue  # a malformed frame: nothing recognisable to redact
    return bytes(buf), stats


def _redact_frame(
    buf: bytearray, start: int, end: int, frags: set[tuple[bytes, bytes, int]], stats: Redaction
) -> bool:
    p = start + 12
    etype = struct.unpack("!H", buf[p : p + 2])[0]
    p += 2
    while etype in (0x8100, 0x88A8):  # 802.1Q / QinQ
        etype = struct.unpack("!H", buf[p + 2 : p + 4])[0]
        p += 4
    if etype != 0x0800 or end - p < 20 or buf[p] >> 4 != 4:
        return False
    ihl = (buf[p] & 0x0F) * 4
    total = struct.unpack("!H", buf[p + 2 : p + 4])[0]
    ip_end = min(p + total, end) if total >= ihl else end
    frag = struct.unpack("!H", buf[p + 6 : p + 8])[0]
    more, offset = bool(frag & 0x2000), frag & 0x1FFF
    ident = struct.unpack("!H", buf[p + 4 : p + 6])[0]
    key = (bytes(buf[p + 12 : p + 16]), bytes(buf[p + 16 : p + 20]), ident)
    if buf[p + 9] != 17:
        return False
    body = p + ihl
    if offset:  # a later fragment: no UDP header to read; blank it when it belongs to RADIUS
        if key in frags:
            buf[body:ip_end] = b"\x00" * (ip_end - body)
            stats.fragments += 1
            return True
        return False
    if ip_end - body < 8:
        return False
    sport, dport = struct.unpack("!HH", buf[body : body + 4])
    if not {sport, dport} & RADIUS_PORTS:
        return False
    if more:
        frags.add(key)
    if not _redact_radius(buf, body + 8, ip_end, stats):
        return False
    buf[body + 6 : body + 8] = b"\x00\x00"  # UDP checksum: none (the payload changed)
    return True
