"""L70: overlay, SGT, routing, VPN and telemetry decoders (synthetic frames, documentation addresses only)."""

import struct

import httpx
import respx

from cml_mcp._core.testing import call_tool
from cml_mcp.pcap import Packet, findings, mask_syslog, matches, read_pcap, summarise
from cml_mcp.server import create_server

from .conftest import LID, LINK, make_settings

MAC_A, MAC_B = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
R1, R2, H1, H2 = "192.0.2.1", "192.0.2.2", "198.51.100.10", "198.51.100.20"


def a(x: str) -> bytes:
    return bytes(int(p) for p in x.split("."))


def pcap(*frames: bytes | tuple[float, bytes]) -> bytes:
    """A classic pcap; a bare frame comes one second after the previous one, (time, frame) at `time`."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    t = 0.0
    for f in frames:
        if isinstance(f, tuple):
            t, f = f
        else:
            t += 1
        out += struct.pack("<IIII", 1000 + int(t), int((t % 1) * 1e6), len(f), len(f)) + f
    return out


def eth(etype: int, payload: bytes) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", etype) + payload


def ipv4(proto: int, src: str, dst: str, body: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0, 64, proto, 0, a(src), a(dst))
    return hdr + body


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return eth(0x0800, ipv4(17, src, dst, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload))


def tcp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, flags, 1024, 0, 0)
    return eth(0x0800, ipv4(6, src, dst, tcp + payload))


ICMP = struct.pack("!BBHHH", 8, 0, 0, 7, 1) + b"x" * 8


def decode(*frames: bytes | tuple[float, bytes]) -> list[Packet]:
    return read_pcap(pcap(*frames))


# --- VXLAN-GPO and CMD: the SGT ------------------------------------------------------------------


def vxlan(vni: int, sgt: int | None) -> bytes:
    inner = eth(0x0800, ipv4(1, H1, H2, ICMP))
    if sgt is None:
        hdr = struct.pack("!BBH", 0x08, 0, 0) + vni.to_bytes(3, "big") + b"\x00"
    else:  # G + I flags, A (policy applied), group policy ID
        hdr = struct.pack("!BBH", 0x88, 0x08, sgt) + vni.to_bytes(3, "big") + b"\x00"
    return udp_frame(R1, R2, 65000, 4789, hdr + inner)


def test_vxlan_gpo_carries_the_sgt() -> None:
    (p,) = decode(vxlan(8190, 17))
    assert p.protocol == "VXLAN" and p.sgt == 17 and p.sgt_carrier == "VXLAN"
    assert p.detail["vni"] == 8190 and p.detail["policy_applied"] is True
    assert p.detail["inner"]["src"] == H1 and p.detail["inner"]["protocol"] == "ICMP"
    assert p.info.startswith("VNI 8190 SGT 17 inner 198.51.100.10 -> 198.51.100.20 ICMP")
    assert p.row()["sgt"] == 17
    s = summarise([p])
    assert s["sgt"] == [{"carrier": "VXLAN", "vni": 8190, "sgt": 17, "packets": 1}]
    assert "highlights" in s and "VXLAN" in s["highlights"]


def cmd(sgt: int, inner_etype: int, payload: bytes) -> bytes:
    return struct.pack("!BBHHH", 1, 1, 0x0001, sgt, inner_etype) + payload


def test_cmd_inline_tag_carries_the_sgt() -> None:
    plain = eth(0x8909, cmd(23, 0x0800, ipv4(1, H1, H2, ICMP)))
    tagged_vlan = eth(0x8100, struct.pack("!HH", 10, 0x8909) + cmd(24, 0x0800, ipv4(1, H1, H2, ICMP)))
    p1, p2 = decode(plain, tagged_vlan)
    assert p1.protocol == "ICMP" and p1.sgt == 23 and p1.sgt_carrier == "CMD"
    assert p2.vlan == 10 and p2.sgt == 24 and p2.src == H1
    assert matches(p1, protocol="CMD") and not matches(p1, protocol="VXLAN")
    assert summarise([p1, p2])["sgt"] == [
        {"carrier": "CMD", "sgt": 23, "packets": 1},
        {"carrier": "CMD", "sgt": 24, "packets": 1},
    ]


# --- LISP --------------------------------------------------------------------------------------------


def lcaf_iid(iid: int, ip: str) -> bytes:
    inner = struct.pack("!I", iid) + struct.pack("!H", 1) + a(ip)
    return struct.pack("!HBBBBH", 16387, 0, 0, 2, 0, len(inner)) + inner


def record(eid: bytes, masklen: int, rlocs: list[str], act: int = 0) -> bytes:
    out = struct.pack("!IBBBBH", 1440, len(rlocs), masklen, act << 5, 0, 0) + eid
    for r in rlocs:
        out += struct.pack("!BBBBHH", 1, 100, 255, 0, 0x0005, 1) + a(r)  # L + R (reachable)
    return out


def test_lisp_map_register_request_reply() -> None:
    register = (
        struct.pack("!BBBB", 0x30, 0, 0x01, 1)
        + b"\x11" * 8
        + struct.pack("!HH", 1, 20)
        + b"\xaa" * 20  # authentication data: never read
        + record(lcaf_iid(4099, H1), 32, [R1])
    )
    request = (
        struct.pack("!BBBB", 0x10, 0, 0, 1)
        + b"\x22" * 8
        + struct.pack("!H", 0)
        + struct.pack("!H", 1)
        + a(R1)
        + struct.pack("!BB", 0, 32)
        + lcaf_iid(4099, H2)
    )
    reply = struct.pack("!BBBB", 0x20, 0, 0, 1) + b"\x22" * 8 + record(lcaf_iid(4099, H2), 32, [], act=1)
    ecm = b"\x80\x00\x00\x00" + ipv4(
        17, H1, H2, struct.pack("!HHHH", 4342, 4342, 8 + len(request), 0) + request
    )
    reg, req, rep, enc = decode(
        udp_frame(R1, R2, 4342, 4342, register),
        udp_frame(R1, R2, 4342, 4342, request),
        udp_frame(R2, R1, 4342, 4342, reply),
        udp_frame(R1, R2, 4342, 4342, ecm),
    )
    assert reg.protocol == "LISP" and reg.detail["type"] == "Map-Register"
    assert reg.detail["records"] == [{"eid": "[4099] 198.51.100.10/32", "rlocs": [R1], "ttl_minutes": 1440}]
    assert reg.info == "Map-Register 1 record: [4099] 198.51.100.10/32 RLOC 192.0.2.1"
    assert "aa" * 4 not in str(reg.detail)
    assert req.info == "Map-Request for [4099] 198.51.100.20/32 from ITR 192.0.2.1"
    assert rep.detail["records"][0]["action"] == "natively-forward" and "negative" in rep.info
    assert enc.detail["encapsulated"] is True and enc.detail["type"] == "Map-Request"
    assert enc.detail["eid_source"] == H1 and enc.info.endswith("(encapsulated)")
    assert summarise([reg, req, rep, enc])["lisp"] == {"Map-Request": 2, "Map-Register": 1, "Map-Reply": 1}


# --- BGP ---------------------------------------------------------------------------------------------


def bgp(typ: int, body: bytes) -> bytes:
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), typ) + body


def bgp_open(asn: int) -> bytes:
    caps = bytes([65, 4]) + struct.pack("!I", asn) + bytes([1, 4]) + struct.pack("!HBB", 1, 0, 1)
    params = bytes([2, len(caps)]) + caps
    return bgp(1, struct.pack("!BHH4sB", 4, 23456, 180, a(R1), len(params)) + params)


def bgp_update() -> bytes:
    withdrawn = bytes([24]) + a("203.0.113.0")[:3]
    attrs = bytes([0x40, 1, 1, 0])  # ORIGIN IGP
    nlri = bytes([24]) + a(H1)[:3] + bytes([32]) + a(H2)
    return bgp(
        2, struct.pack("!H", len(withdrawn)) + withdrawn + struct.pack("!H", len(attrs)) + attrs + nlri
    )


def notification(code: int, subcode: int) -> bytes:
    return bgp(3, bytes([code, subcode]))


def test_bgp_open_update_keepalive_notification() -> None:
    eor = bgp(2, struct.pack("!HH", 0, 0))
    op, upd, end, note = decode(
        tcp_frame(R1, R2, 40000, 179, bgp_open(4200000001)),
        tcp_frame(R1, R2, 40000, 179, bgp_update() + bgp(4, b"")),
        tcp_frame(R1, R2, 40000, 179, eor),
        tcp_frame(R2, R1, 179, 40000, notification(6, 4)),
    )
    assert op.protocol == "BGP" and op.info == "OPEN AS 4200000001 hold 180s id 192.0.2.1"
    assert (
        op.detail["bgp"][0]["families"] == ["ipv4-unicast"]
        and "4-octet-as" in op.detail["bgp"][0]["capabilities"]
    )
    assert upd.info == "UPDATE ipv4-unicast +2 -1 prefixes; KEEPALIVE"
    assert upd.detail["bgp"][0]["families"] == {"ipv4-unicast": {"announced": 2, "withdrawn": 1}}
    assert upd.detail["flags"] == ["ACK", "PSH"]  # TCP findings still see the flags
    assert end.info == "UPDATE End-of-RIB (ipv4-unicast)" and end.detail["bgp"][0]["end_of_rib"]
    assert note.info == "NOTIFICATION Cease / Administrative Reset"
    assert summarise([op, upd, end, note])["bgp"] == {
        "UPDATE": 2,
        "OPEN": 1,
        "KEEPALIVE": 1,
        "NOTIFICATION": 1,
    }
    found = findings([op, upd, end, note])
    assert any("BGP: NOTIFICATION Cease / Administrative Reset 192.0.2.2 -> 192.0.2.1" in f for f in found)


def test_bgp_segment_split_and_empty_ack() -> None:
    full = bgp_update()
    cut, ack = decode(
        tcp_frame(R1, R2, 40000, 179, full[:30]),
        tcp_frame(R2, R1, 179, 40000, b"", flags=0x10),
    )
    assert "continues in the next segment" in cut.info and "bgp" not in cut.detail
    assert ack.protocol == "BGP" and ack.info == "179 -> 40000 [ACK]"


def test_finding_bgp_hold_timer_expired() -> None:
    pkts = decode(tcp_frame(R2, R1, 179, 40000, notification(4, 0)))
    assert pkts[0].info == "NOTIFICATION Hold Timer Expired"
    (f,) = findings(pkts)
    assert f.startswith("BGP: NOTIFICATION hold timer expired from 192.0.2.2 -> 192.0.2.1 (1x)")


# --- BFD ---------------------------------------------------------------------------------------------


def bfd(state: int, diag: int = 0) -> bytes:
    return struct.pack("!BBBBIIIII", 0x20 | diag, state << 6, 3, 24, 1, 2, 300000, 300000, 50000)


def test_bfd_state_and_timers() -> None:
    (p,) = decode(udp_frame(R1, R2, 49152, 3784, bfd(3)))
    assert p.protocol == "BFD" and p.info == "Up diag none tx 300ms rx 300ms x3"
    assert p.detail["state"] == "Up" and p.detail["my_discriminator"] == 1
    assert summarise([p])["bfd"] == {"Up": 1} and not findings([p])


def test_finding_bfd_down() -> None:
    pkts = decode(udp_frame(R1, R2, 49152, 4784, bfd(1, diag=1)))
    assert pkts[0].detail["multihop"] is True
    (f,) = findings(pkts)
    assert f.startswith(
        "BFD: sessions reported down: 192.0.2.1 -> 192.0.2.2 Down (Control Detection Time Expired)"
    )


# --- IKEv2 / ESP -------------------------------------------------------------------------------------


def ike(
    spi_i: bytes, exchange: int, flags: int, payloads: bytes = b"", first: int = 0, spi_r: bytes = bytes(8)
) -> bytes:
    hdr = spi_i + spi_r + struct.pack("!BBBBII", first, 0x20, exchange, flags, 0, 28 + len(payloads))
    return hdr + payloads


def notify(ntype: int) -> bytes:
    return struct.pack("!BBHBBH", 0, 0, 8, 0, 0, ntype)


def test_ikev2_exchanges_and_esp() -> None:
    spi = b"\x01" * 8
    req = ike(spi, 34, 0x08)
    resp = ike(spi, 34, 0x20, notify(14), first=41)
    auth = ike(spi, 35, 0x08, struct.pack("!BBH", 0, 0, 8) + b"\x00" * 4, first=46, spi_r=b"\x02" * 8)
    esp = struct.pack("!II", 0xC0FFEE01, 5) + b"\x00" * 16
    p_req, p_resp, p_auth, p_esp, p_udp_esp, p_keep = decode(
        udp_frame(R1, R2, 500, 500, req),
        udp_frame(R2, R1, 500, 500, resp),
        udp_frame(R1, R2, 4500, 4500, b"\x00" * 4 + auth),
        eth(0x0800, ipv4(50, R1, R2, esp)),
        udp_frame(R1, R2, 4500, 4500, esp),
        udp_frame(R1, R2, 4500, 4500, b"\xff"),
    )
    assert p_req.protocol == "IKEv2" and p_req.info == "IKE_SA_INIT request" and p_req.detail["initiator"]
    assert p_resp.info == "IKE_SA_INIT response: NO_PROPOSAL_CHOSEN"
    assert p_resp.detail["errors"] == ["NO_PROPOSAL_CHOSEN"]
    assert p_auth.info == "IKE_AUTH request" and p_auth.detail["encrypted"] is True
    assert p_esp.protocol == "ESP" and p_esp.detail["spi"] == "0xc0ffee01"
    assert p_udp_esp.protocol == "ESP" and p_udp_esp.detail["udp_encapsulated"] is True
    assert p_keep.info == "NAT-T keepalive"
    s = summarise([p_req, p_resp, p_auth, p_esp, p_udp_esp, p_keep])
    assert s["ike"] == {
        "IKEv2 IKE_SA_INIT request": 1,
        "IKEv2 IKE_SA_INIT response": 1,
        "IKEv2 IKE_AUTH request": 1,
    }
    assert s["esp"] == [{"spi": "0xc0ffee01", "src": R1, "dst": R2, "packets": 2}]
    found = findings([p_req, p_resp, p_auth])
    assert not any("without response" in f for f in found)  # the response answered the request
    assert any(
        f.startswith("IKE: error notifications: NO_PROPOSAL_CHOSEN 192.0.2.2 -> 192.0.2.1") for f in found
    )
    assert any("the proposals (encryption, integrity, PRF, DH group) don't match" in f for f in found)


def test_finding_ike_sa_init_without_response() -> None:
    pkts = decode(
        (0.0, udp_frame(R1, R2, 500, 500, ike(b"\x03" * 8, 34, 0x08))),
        (1.0, udp_frame(R1, R2, 500, 500, ike(b"\x03" * 8, 34, 0x08))),
        (9.0, eth(0x0800, ipv4(1, H1, H2, struct.pack("!BBHHH", 0, 0, 0, 7, 1)))),
    )
    (f,) = findings(pkts)
    assert f.startswith("IKEv2: IKE_SA_INIT without response from 192.0.2.1 -> 192.0.2.2 (2x)")


def test_ike_request_still_in_flight_is_not_a_finding() -> None:
    assert not findings(decode(udp_frame(R1, R2, 500, 500, ike(b"\x03" * 8, 34, 0x08))))


# --- NetFlow v9 / IPFIX ------------------------------------------------------------------------------


def v9(*flowsets: bytes, seq: int = 1) -> bytes:
    return struct.pack("!HHIIII", 9, len(flowsets), 1000, 1700000000, seq, 0) + b"".join(flowsets)


def v9_template(tid: int) -> bytes:
    fields = [(8, 4), (12, 4), (2, 4)]  # src addr, dst addr, packets: 12-byte records
    body = struct.pack("!HH", tid, len(fields)) + b"".join(struct.pack("!HH", t, n) for t, n in fields)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def v9_data(tid: int, records: int) -> bytes:
    body = b"".join(a(H1) + a(H2) + struct.pack("!I", 10) for _ in range(records))
    return struct.pack("!HH", tid, 4 + len(body)) + body


def test_netflow_v9_templates_and_records() -> None:
    p1, p2 = decode(
        udp_frame(R1, R2, 50000, 2055, v9(v9_template(256), v9_data(256, 2))),
        udp_frame(R1, R2, 50000, 2055, v9(v9_data(256, 3), seq=2)),
    )
    assert p1.protocol == "NetFlow" and p1.detail["templates"] == [
        {"id": 256, "fields": 3, "record_bytes": 12}
    ]
    assert p1.info == "v9 source 0: templates 256; data 256 (24 bytes)"
    s = summarise([p1, p2])
    assert s["netflow"] == [
        {
            "exporter": R1,
            "source_id": 0,
            "version": 9,
            "packets": 2,
            "data_records": 5,
            "templates": [256],
        }
    ]
    assert not findings([p1, p2])


def test_ipfix_and_v5() -> None:
    # IPFIX: one enterprise-specific field (4 more bytes in the specifier)
    tmpl_body = struct.pack("!HH", 300, 2) + struct.pack("!HH", 8, 4) + struct.pack("!HHI", 0x8001, 2, 9)
    tmpl = struct.pack("!HH", 2, 4 + len(tmpl_body)) + tmpl_body
    data = struct.pack("!HH", 300, 4 + 12) + (a(H1) + b"\x00\x01") * 2
    msg = tmpl + data
    ipfix = struct.pack("!HHIII", 10, 16 + len(msg), 1700000000, 1, 7) + msg
    v5 = struct.pack("!HHIIIIBBH", 5, 2, 0, 0, 0, 9, 0, 0, 0) + b"\x00" * 96
    p_ipfix, p_v5 = decode(udp_frame(R1, R2, 50000, 4739, ipfix), udp_frame(R2, R1, 50000, 9996, v5))
    assert p_ipfix.protocol == "IPFIX" and p_ipfix.detail["source_id"] == 7
    assert p_ipfix.detail["templates"] == [{"id": 300, "fields": 2, "record_bytes": 6}]
    assert p_v5.protocol == "NetFlow" and p_v5.info == "v5 2 records"
    rows = {r["version"]: r for r in summarise([p_ipfix, p_v5])["netflow"]}
    assert rows[10]["data_records"] == 2 and rows[5]["data_records"] == 2


def test_finding_netflow_data_before_template() -> None:
    pkts = decode(
        udp_frame(R1, R2, 50000, 2055, v9(v9_data(256, 2))),
        udp_frame(R1, R2, 50000, 2055, v9(v9_template(256), seq=2)),
    )
    (f,) = findings(pkts)
    assert f.startswith("NetFlow: data before template from 192.0.2.1 source 0 template 256 (1x)")
    (row,) = summarise(pkts)["netflow"]
    assert row["data_sets_without_template"] == 1 and row["data_records"] == 0


# --- VXLAN without SGT -------------------------------------------------------------------------------


def test_finding_vxlan_without_sgt() -> None:
    pkts = decode(vxlan(8190, None), vxlan(8190, None), vxlan(8191, 0), vxlan(8192, 17))
    assert pkts[0].sgt is None and "no SGT" in pkts[0].info
    assert pkts[2].info.startswith("VNI 8191 SGT 0 (unknown)")
    (f,) = findings(pkts)
    assert f.startswith(
        "VXLAN: packets without an SGT: VNI 8190 no group-policy header (2x), VNI 8191 SGT 0 (1x)"
    )
    assert "8192" not in f


# --- syslog ------------------------------------------------------------------------------------------


def test_syslog_severity_facility_and_masking() -> None:
    msg = b"<189>42: *Oct 29 10:00:00: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.0.2.9)"
    secret = b"<187>43: %PARSER-3-CFG: username bob password 0 Hunter2xyz and snmp community PubLic99"
    p1, p2 = decode(udp_frame(R1, R2, 51000, 514, msg), udp_frame(R1, R2, 51000, 514, secret))
    assert p1.protocol == "Syslog" and p1.detail["facility"] == "local7" and p1.detail["severity"] == "notice"
    assert p1.detail["mnemonic"] == "%SYS-5-CONFIG_I" and p1.info.startswith("local7.notice 42:")
    assert p2.detail["severity"] == "error"
    blob = str(summarise([p1, p2], highlights=10))
    assert "Hunter2xyz" not in blob and "PubLic99" not in blob and "password 0 ********" in blob
    assert summarise([p1, p2])["syslog"] == {"severity": {"notice": 1, "error": 1}, "senders": {R1: 2}}
    assert mask_syslog("key-string: abc123 secret=xyz") == "key-string: ******** secret=********"
    # IOS IKEv2 keyrings: the key follows a local/remote (or hex) keyword
    assert mask_syslog("pre-shared-key local Kx1 remote") == "pre-shared-key local ******** remote"
    assert mask_syslog("pre-shared-key remote 6 Kx2") == "pre-shared-key remote 6 ********"


# --- DNS ---------------------------------------------------------------------------------------------


def dns_q(ident: int, name: str) -> bytes:
    qname = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def dns_r(ident: int, name: str, rcode: int = 0) -> bytes:
    q = dns_q(ident, name)
    head = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, 0 if rcode else 2, 0, 0)
    if rcode:
        return head + q[12:]
    cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 6) + b"\x03www\xc0\x10"
    addr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + a("203.0.113.5")
    return head + q[12:] + cname + addr


def test_dns_query_and_answer() -> None:
    q, r = decode(
        udp_frame(H1, R1, 53001, 53, dns_q(7, "app.example.com")),
        udp_frame(R1, H1, 53, 53001, dns_r(7, "app.example.com")),
    )
    assert q.protocol == "DNS" and q.info == "query A app.example.com"
    assert r.detail["answers"] == ["app.example.com CNAME www.example.com", "app.example.com A 203.0.113.5"]
    assert r.info == "response A app.example.com -> www.example.com, 203.0.113.5 (NOERROR)"
    assert not findings([q, r])


def test_findings_dns_unanswered_and_errors() -> None:
    pkts = decode(
        (0.0, udp_frame(H1, R1, 53001, 53, dns_q(8, "lost.example.com"))),
        (0.5, udp_frame(H1, R1, 53002, 53, dns_q(9, "nosuch.example.com"))),
        (0.6, udp_frame(R1, H1, 53, 53002, dns_r(9, "nosuch.example.com", rcode=3))),
        (9.0, eth(0x0800, ipv4(1, H1, H2, struct.pack("!BBHHH", 0, 0, 0, 7, 1)))),
    )
    found = findings(pkts)
    assert any(
        f.startswith("DNS: queries without a response: A lost.example.com 198.51.100.10") for f in found
    )
    assert "DNS: error answers: NXDOMAIN for A nosuch.example.com (1x)." in found


# --- robustness and the tool -------------------------------------------------------------------------


def test_malformed_payloads_are_named_not_raised() -> None:
    bad = decode(
        udp_frame(R1, R2, 49152, 3784, b"\x20"),  # short BFD
        udp_frame(R1, R2, 500, 500, b"\x00" * 10),  # short IKE
        udp_frame(R1, R2, 4342, 4342, b"\x30\x00\x00\x05" + b"\x00" * 6),  # LISP records past the end
    )
    assert [p.info for p in bad] == ["BFD (malformed)", "IKE (malformed)", "LISP (malformed)"]


async def test_summarize_capture_tool_shows_sgt_and_findings(lab_api: respx.MockRouter) -> None:
    data = pcap(vxlan(8190, 17), vxlan(8191, None), tcp_frame(R2, R1, 179, 40000, notification(4, 0)))
    lab_api.get(f"/pcap/{LINK}").mock(return_value=httpx.Response(200, content=data))
    out = await call_tool(create_server(make_settings()), "cml_summarize_capture", {"lab": LID, "link": LINK})
    assert {"carrier": "VXLAN", "vni": 8190, "sgt": 17, "packets": 1} in out["sgt"]
    assert any(f.startswith("VXLAN: packets without an SGT") for f in out["findings"])
    assert any(f.startswith("BGP: NOTIFICATION hold timer expired") for f in out["findings"])
