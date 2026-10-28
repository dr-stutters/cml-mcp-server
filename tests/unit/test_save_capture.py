"""L78: cml_save_capture writes the pcap under CML_CAPTURE_DIR and returns no bytes; redact='radius'."""

import hashlib
import json
import os
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cml_mcp._core import InvalidRequest
from cml_mcp.capture_files import redact_radius, safe_component, write_capture
from cml_mcp.pcap import read_pcap
from cml_mcp.server import create_server

from .conftest import LID, LINK, make_settings
from .test_pcap import attr, eth, frames, pcap, radius, udp

RW = {"mcp_enable_writes": True}
DATA = pcap(*frames())


@pytest.fixture
def capture_api(lab_api: respx.MockRouter) -> respx.MockRouter:
    lab_api.get(f"/pcap/{LINK}").mock(return_value=httpx.Response(200, content=DATA))
    stopped = {"config": {"maxpackets": 30}, "starttime": None, "packetscaptured": 8}
    lab_api.get(f"/labs/{LID}/links/{LINK}/capture/status").mock(
        return_value=httpx.Response(200, json=stopped)
    )
    return lab_api


async def _save(settings: Any, **args: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    args = {"lab": LID, "link": LINK, **args}
    async with Client(create_server(settings)) as c:
        preview = (await c.call_tool("cml_save_capture", args)).structured_content
        assert preview is not None and preview["status"] == "preview", preview
        applied = (
            await c.call_tool("cml_save_capture", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert applied is not None
    return preview, applied


async def test_writes_file_under_capture_dir_and_returns_no_bytes(
    capture_api: respx.MockRouter, tmp_path: Path
) -> None:
    preview, applied = await _save(make_settings(**RW, capture_dir=str(tmp_path)))
    assert preview["preview"]["packets"] == 8 and preview["preview"]["size_bytes"] == len(DATA)
    res = applied["result"]
    path = Path(res["path"])
    assert path.parent == tmp_path / "mcp-test-probe" and path.suffix == ".pcap"
    assert path.name.startswith("r1-Ethernet0_0_-_r2-Ethernet0_0-20")
    assert path.read_bytes() == DATA
    assert res["sha256"] == hashlib.sha256(DATA).hexdigest() and res["size_bytes"] == len(DATA)
    assert res["packets"] == 8
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert set(res) == {"lab", "link", "path", "sha256", "size_bytes", "packets"}
    text = json.dumps(applied)
    assert "SuperSecret1" not in text and "CLASSDATA" not in text and "alice" not in text
    assert len(text) < 2000  # metadata only, nothing of the capture itself


async def test_missing_capture_dir_is_refused(capture_api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(**RW))) as c:
        res = await c.call_tool("cml_save_capture", {"lab": LID, "link": LINK}, raise_on_error=False)
    assert res.is_error and "CML_CAPTURE_DIR" in res.content[0].text  # type: ignore[union-attr]


async def test_path_traversal_name_is_refused(capture_api: respx.MockRouter, tmp_path: Path) -> None:
    settings = make_settings(**RW, capture_dir=str(tmp_path / "caps"))
    (tmp_path / "caps").mkdir()
    async with Client(create_server(settings)) as c:
        for bad in ("../evil", "a/b", ".hidden", "x\x00y"):
            res = await c.call_tool(
                "cml_save_capture", {"lab": LID, "link": LINK, "name": bad}, raise_on_error=False
            )
            assert res.is_error, bad
    assert list(tmp_path.rglob("*.pcap")) == []


def test_lab_titles_cannot_escape(tmp_path: Path) -> None:
    root = (tmp_path / "caps").resolve()
    root.mkdir()
    assert safe_component("..", "lab-id") == "lab-id" and safe_component("../../etc", "x") == "etc"
    # a symlinked lab directory pointing outside the root is refused
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "evil").symlink_to(outside)
    with pytest.raises(InvalidRequest, match="outside CML_CAPTURE_DIR"):
        write_capture(root, "evil", "link", b"x")
    with pytest.raises(InvalidRequest, match="outside CML_CAPTURE_DIR"):
        write_capture(root, "..", "link", b"x")
    assert list(outside.iterdir()) == []


def test_never_overwrites(tmp_path: Path) -> None:
    now = datetime(2026, 10, 28, 1, 2, 3, tzinfo=UTC)
    a = write_capture(tmp_path, "lab", "link", b"one", now)
    b = write_capture(tmp_path, "lab", "link", b"two", now)
    assert a != b and a.read_bytes() == b"one" and b.read_bytes() == b"two"
    assert a.name == "link-20261028T010203Z.pcap" and b.name == "link-20261028T010203Z-2.pcap"


async def test_running_capture_blocks(capture_api: respx.MockRouter, tmp_path: Path) -> None:
    capture_api.get(f"/labs/{LID}/links/{LINK}/capture/status").mock(
        return_value=httpx.Response(200, json={"starttime": "2026-10-28T00:00:00Z"})
    )
    async with Client(create_server(make_settings(**RW, capture_dir=str(tmp_path)))) as c:
        res = (await c.call_tool("cml_save_capture", {"lab": LID, "link": LINK})).structured_content
    assert res is not None and res["status"] == "blocked" and "still running" in res["blockers"][0]


async def test_redact_radius(capture_api: respx.MockRouter, tmp_path: Path) -> None:
    preview, applied = await _save(make_settings(**RW, capture_dir=str(tmp_path)), redact="radius")
    res = applied["result"]
    saved = Path(res["path"]).read_bytes()
    assert len(saved) == len(DATA) and res["sha256"] == hashlib.sha256(saved).hexdigest()
    for secret in (b"SuperSecret1", b"CLASSDATA", b"\x01" * 16, b"\x02" * 16):
        assert secret in DATA and secret not in saved
    assert res["redacted"]["packets"] == 2 and res["redacted"]["attributes"] >= 4
    assert preview["preview"]["redact"] == res["redacted"]
    # the exchange still decodes: same RADIUS packets, User-Name and the allow-listed AV-pair kept
    pkts = [p for p in read_pcap(saved) if p.protocol == "RADIUS"]
    assert [p.detail["code"] for p in pkts] == ["Access-Request", "Access-Accept"]
    assert pkts[0].detail["User-Name"] == "52-54-00-61-3D-9E" and b"service-type=Call Check" in saved
    assert b"tunnel-password=************" in saved
    # authenticators zeroed, UDP checksum cleared; non-RADIUS frames untouched
    assert read_pcap(saved)[0].row() == read_pcap(DATA)[0].row()


def _ip(proto: int, body: bytes, ident: int, frag: int) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(body),
        ident,
        frag,
        64,
        proto,
        0,
        b"\xc0\x00\x02\x01",
        b"\xc0\x00\x02\x02",
    )
    return hdr + body


def test_redact_blanks_later_fragments_of_radius() -> None:
    msg = radius(1, 3, attr(1, b"bob") + attr(24, b"STATEDATA" * 4))
    dgram = udp(50000, 1812, msg)
    first, rest = dgram[:40], dgram[40:]
    other = udp(40000, 9999, b"KEEPME" * 4)
    data = pcap(
        eth(0x0800, _ip(17, first, 77, 0x2000)),  # MF, offset 0
        eth(0x0800, _ip(17, rest, 77, 5)),  # offset 40 bytes
        eth(0x0800, _ip(17, other[:16], 78, 0x2000)),
        eth(0x0800, _ip(17, other[16:], 78, 2)),
    )
    out, stats = redact_radius(data)
    assert b"STATEDATA" in data and b"STATEDATA" not in out and b"STATE" not in out
    assert stats.fragments == 1 and b"KEEPME" in out


def test_redact_refuses_non_ethernet() -> None:
    wireless = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    with pytest.raises(InvalidRequest, match="Ethernet"):
        redact_radius(wireless)
