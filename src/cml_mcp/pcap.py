"""A small pcap reader and protocol decoder for CML link captures (no third-party dependencies).

CML serves a capture as a classic libpcap file (`GET /pcap/{link_id}`), Ethernet link type. This
module decodes what lab tests need to prove: ARP, IPv4 with ICMP/TCP/UDP, OSPF, DHCP, RADIUS
(including CoA and the EAP inside it) and EAPOL; and for overlay, SGT and VPN proofs (L70) VXLAN with
the group-policy (GPO) SGT, Cisco MetaData inline SGT tags, LISP control messages, BGP, BFD, IKE and
ESP, NetFlow v5/v9 and IPFIX, syslog and DNS. Secrets never leave it: RADIUS passwords, State,
Class, Message-Authenticator and similar attributes are dropped, AV-pairs that look like secrets
are masked, LISP authentication data is never read, and syslog text has password/key values masked.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
}
LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_RADIOTAP = 127
MAX_PACKETS = 100_000


class PcapError(ValueError):
    pass


@dataclass
class Packet:
    no: int
    time: float  # seconds since the first packet
    length: int
    src: str = ""
    dst: str = ""
    protocol: str = "ETH"
    info: str = ""
    transport: str = ""
    sport: int | None = None
    dport: int | None = None
    vlan: int | None = None
    sgt: int | None = None  # Security Group Tag carried by the frame (CMD inline tag or VXLAN-GPO)
    sgt_carrier: str = ""  # "CMD" or "VXLAN"
    detail: dict[str, Any] = field(default_factory=dict)

    def row(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "no": self.no,
            "time": round(self.time, 3),
            "src": f"{self.src}:{self.sport}" if self.sport is not None else self.src,
            "dst": f"{self.dst}:{self.dport}" if self.dport is not None else self.dst,
            "protocol": self.protocol,
            "info": self.info,
        }
        if self.vlan is not None:
            out["vlan"] = self.vlan
        if self.sgt is not None:
            out["sgt"] = self.sgt
        if self.detail:
            out["detail"] = self.detail
        return out


def pcap_truncated(packets: list[Packet]) -> bool:
    return len(packets) >= MAX_PACKETS


def read_pcap(data: bytes) -> list[Packet]:
    """Decode every frame of a classic pcap file (at most MAX_PACKETS; see pcap_truncated)."""
    if len(data) < 24 or data[:4] not in PCAP_MAGIC:
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            raise PcapError("pcapng captures aren't supported (CML serves classic pcap)")
        raise PcapError("not a pcap file")
    endian, scale = PCAP_MAGIC[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    packets: list[Packet] = []
    off, first = 24, None
    while off + 16 <= len(data) and len(packets) < MAX_PACKETS:
        sec, frac, incl, orig = struct.unpack(endian + "IIII", data[off : off + 16])
        frame = data[off + 16 : off + 16 + incl]
        off += 16 + incl
        ts = sec + frac * scale
        first = ts if first is None else first
        pkt = Packet(no=len(packets) + 1, time=ts - first, length=orig)
        if linktype in (LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11, LINKTYPE_RADIOTAP):
            try:
                if linktype == LINKTYPE_ETHERNET:
                    decode_ethernet(pkt, frame)
                elif linktype == LINKTYPE_RADIOTAP:
                    decode_80211(pkt, strip_radiotap(frame))
                else:
                    decode_80211(pkt, frame)
            except Exception:  # noqa: BLE001 - one bad frame must never abort the whole capture
                pkt.info = pkt.info or "malformed"
        else:
            pkt.protocol, pkt.info = f"LINKTYPE{linktype}", "not decoded"
        packets.append(pkt)
    return packets


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip4(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


ETHERTYPES = {0x88CC: "LLDP", 0x9000: "LOOP", 0x86DD: "IPv6", 0x8809: "LACP"}
ETHERTYPE_CMD = 0x8909


def decode_cmd(pkt: Packet, p: bytes) -> tuple[int, bytes]:
    """Cisco MetaData (TrustSec inline tagging): version, length (in 4-byte options), options - the SGT
    option carries the tag - then the ethertype of the frame inside. Returns (inner ethertype, payload)."""
    length = p[1] or 1
    end = 2 + 4 * length
    if len(p) < end + 2:
        raise ValueError("short CMD header")
    pkt.sgt, pkt.sgt_carrier = struct.unpack("!H", p[4:6])[0], "CMD"
    return struct.unpack("!H", p[end : end + 2])[0], p[end + 2 :]


def decode_ethernet(pkt: Packet, frame: bytes) -> None:
    pkt.dst, pkt.src = mac(frame[0:6]), mac(frame[6:12])
    etype = struct.unpack("!H", frame[12:14])[0]
    payload = frame[14:]
    while etype in (0x8100, 0x88A8, ETHERTYPE_CMD):  # 802.1Q / QinQ / Cisco MetaData (inline SGT)
        if etype == ETHERTYPE_CMD:
            etype, payload = decode_cmd(pkt, payload)
            continue
        pkt.vlan = struct.unpack("!H", payload[0:2])[0] & 0x0FFF
        etype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]
    if etype < 0x0600:  # 802.3 length field: LLC (CDP, STP ...)
        if payload[:3] == b"\x42\x42\x03":
            pkt.protocol, pkt.info = "STP", "spanning tree BPDU"
        elif payload[:8] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
            pkt.protocol, pkt.info = "CDP", "Cisco Discovery Protocol"
        else:
            pkt.protocol, pkt.info = "LLC", f"802.3 length {etype}"
        return
    if etype == 0x0806:
        decode_arp(pkt, payload)
    elif etype == 0x0800:
        decode_ipv4(pkt, payload)
    elif etype == 0x888E:
        decode_eapol(pkt, payload)
    else:
        pkt.protocol = ETHERTYPES.get(etype, f"0x{etype:04x}")


# --- 802.11 (CML wireless captures: radiotap + 802.11) ------------------------------------------------

MGMT_SUBTYPES = {
    0: "assoc-request",
    1: "assoc-response",
    2: "reassoc-request",
    3: "reassoc-response",
    4: "probe-request",
    5: "probe-response",
    8: "beacon",
    10: "disassociation",
    11: "authentication",
    12: "deauthentication",
    13: "action",
}
CTRL_SUBTYPES = {8: "block-ack-request", 9: "block-ack", 11: "rts", 12: "cts", 13: "ack"}
REASONS = {
    1: "unspecified",
    2: "previous auth no longer valid",
    3: "station leaving",
    4: "inactivity",
    8: "station leaving BSS",
    15: "4-way handshake timeout",
    23: "802.1X authentication failed",
}


def strip_radiotap(frame: bytes) -> bytes:
    """The 802.11 frame after a radiotap header. CML 2.10 labels its wireless captures radiotap (127) but
    writes bare 802.11 frames: a first byte other than the radiotap version 0 means there is no header.
    (A bare 802.11 frame starting with 0x00 is an association request, whose next byte is its flags.)"""
    if len(frame) >= 10 and frame[0] == 0 and frame[1] == 0:
        length = struct.unpack("<H", frame[2:4])[0]
        present = struct.unpack("<I", frame[4:8])[0]
        # radiotap: a plausible length, some present flags, and a valid 802.11 frame control after it
        # (a bare association request also starts 00 00, followed by its duration, typically 314)
        if 8 <= length <= len(frame) - 2 and present and frame[length] & 3 == 0 and length < 128:
            return frame[length:]
    return frame


def _ssid(ies: bytes) -> str | None:
    off = 0
    while off + 2 <= len(ies):
        eid, ln = ies[off], ies[off + 1]
        if eid == 0:
            raw = ies[off + 2 : off + 2 + min(ln, 32)]
            if not raw.strip(b"\x00"):
                return ""
            return "".join(c if c.isprintable() else "?" for c in raw.decode(errors="replace"))
        off += 2 + ln
    return None


def decode_80211(pkt: Packet, f: bytes) -> None:
    """802.11 frame: management (SSID, auth/assoc, deauth reasons), control, and data (LLC/SNAP payload
    decoded like Ethernet: EAPOL, IPv4, ARP); protected data is reported as such."""
    if len(f) < 10:
        pkt.protocol, pkt.info = "802.11", "malformed (short frame)"
        return
    fc0, fc1 = f[0], f[1]
    ftype, subtype = (fc0 >> 2) & 3, fc0 >> 4
    to_ds, from_ds, protected = bool(fc1 & 1), bool(fc1 & 2), bool(fc1 & 0x40)
    order = bool(fc1 & 0x80)  # HT Control present on QoS data and management frames
    pkt.dst = mac(f[4:10])
    if ftype == 1:  # control frames carry 1-2 addresses
        pkt.protocol, pkt.info = "802.11-CTRL", CTRL_SUBTYPES.get(subtype, f"subtype {subtype}")
        if len(f) >= 16:
            pkt.src = mac(f[10:16])
        return
    pkt.src = mac(f[10:16])
    if ftype == 0:
        name = MGMT_SUBTYPES.get(subtype, f"subtype {subtype}")
        pkt.protocol, pkt.info = "802.11-MGMT", name
        if protected:  # 802.11w: the body starts with a CCMP header
            pkt.info = f"{name} (protected)"
            return
        body = f[24 + (4 if order else 0) :]
        if subtype in (8, 5):  # beacon / probe response: 12 fixed bytes, then IEs
            if (ssid := _ssid(body[12:])) is not None:
                pkt.info, pkt.detail = f"{name} SSID {ssid or '<hidden>'}", {"ssid": ssid}
        elif subtype == 4:
            if (ssid := _ssid(body)) is not None:
                pkt.info, pkt.detail = f"{name} SSID {ssid or '<any>'}", {"ssid": ssid}
        elif subtype in (0, 2):  # (re)assoc request: capability + interval (+ current AP) then IEs
            ssid = _ssid(body[4 if subtype == 0 else 10 :])
            if ssid is not None:
                pkt.info, pkt.detail = f"{name} SSID {ssid}", {"ssid": ssid}
        elif subtype in (1, 3) and len(body) >= 4:
            status = struct.unpack("<H", body[2:4])[0]
            pkt.info, pkt.detail = f"{name} status {status}", {"status": status}
        elif subtype == 11 and len(body) >= 6:
            alg, seq, status = struct.unpack("<HHH", body[0:6])
            method = {0: "open", 1: "shared-key", 3: "SAE"}.get(alg, f"alg {alg}")
            pkt.info = f"{name} {method} seq {seq} status {status}"
        elif subtype in (10, 12) and len(body) >= 2:
            reason = struct.unpack("<H", body[0:2])[0]
            pkt.info = f"{name} reason {reason} ({REASONS.get(reason, 'see 802.11 reason codes')})"
            pkt.detail = {"reason": reason}
        return
    if ftype == 2:
        qos = bool(subtype & 8)
        hdr = 24 + (6 if to_ds and from_ds else 0) + (2 if qos else 0) + (4 if qos and order else 0)
        # addresses by DS bits: report the real sender/receiver, not the BSSID
        a1, a2, a3 = mac(f[4:10]), mac(f[10:16]), mac(f[16:22])
        if to_ds and from_ds:
            pkt.dst, pkt.src = a3, mac(f[24:30])
        elif to_ds:
            pkt.dst, pkt.src = a3, a2
        elif from_ds:
            pkt.dst, pkt.src = a1, a3
        if subtype & 4:  # null / QoS null: no payload
            pkt.protocol, pkt.info = "802.11-DATA", "null (power save)"
            return
        if protected:
            pkt.protocol, pkt.info = "802.11-DATA", "protected (encrypted) data"
            return
        payload = f[hdr:]
        if payload[:6] == b"\xaa\xaa\x03\x00\x00\x00":
            etype = struct.unpack("!H", payload[6:8])[0]
            inner = payload[8:]
            if etype == 0x888E:
                decode_eapol(pkt, inner)
            elif etype == 0x0800:
                decode_ipv4(pkt, inner)
            elif etype == 0x0806:
                decode_arp(pkt, inner)
            else:
                pkt.protocol = ETHERTYPES.get(etype, f"0x{etype:04x}")
            return
        pkt.protocol, pkt.info = "802.11-DATA", "data"
        return
    pkt.protocol, pkt.info = "802.11", f"type {ftype}"


def decode_arp(pkt: Packet, p: bytes) -> None:
    pkt.protocol = "ARP"
    if p[0:6] != b"\x00\x01\x08\x00\x06\x04":
        pkt.info = "ARP (not Ethernet/IPv4)"
        return
    op = struct.unpack("!H", p[6:8])[0]
    sha, spa, tpa = mac(p[8:14]), ip4(p[14:18]), ip4(p[24:28])
    pkt.protocol = "ARP"
    if op == 1:
        pkt.info = f"Who has {tpa}? Tell {spa}" if spa != tpa else f"Gratuitous ARP for {spa}"
    elif op == 2:
        pkt.info = f"{spa} is at {sha}"
    else:
        pkt.info = f"ARP op {op}"
    pkt.detail = {
        "op": "request" if op == 1 else "reply" if op == 2 else op,
        "sender_ip": spa,
        "target_ip": tpa,
    }


ICMP_TYPES = {
    0: "Echo reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo request",
    11: "Time exceeded",
}
TCP_PORTS = {
    22: "SSH",
    179: "BGP",
    23: "Telnet",
    49: "TACACS+",
    80: "HTTP",
    443: "HTTPS",
    830: "NETCONF",
    8305: "sftunnel",
}
UDP_PORTS = {
    53: "DNS",
    123: "NTP",
    161: "SNMP",
    162: "SNMP-trap",
    514: "Syslog",
    69: "TFTP",
    4341: "LISP-data",
}
RADIUS_PORTS = {1812, 1813, 1645, 1646, 1700, 3799}


def decode_ipv4(pkt: Packet, p: bytes) -> None:
    ihl = (p[0] & 0x0F) * 4
    if p[0] >> 4 != 4 or ihl < 20 or len(p) < ihl:
        raise ValueError("bad IPv4 header")
    proto = p[9]
    pkt.src, pkt.dst = ip4(p[12:16]), ip4(p[16:20])
    frag = struct.unpack("!H", p[6:8])[0] & 0x1FFF
    total = struct.unpack("!H", p[2:4])[0]
    body = p[ihl:total] if total >= ihl else p[ihl:]
    if frag:
        pkt.protocol, pkt.info = "IPv4", f"fragment (offset {frag * 8})"
        return
    if proto == 1:
        t, c = body[0], body[1]
        pkt.protocol = "ICMP"
        pkt.info = ICMP_TYPES.get(t, f"type {t}") + (f" (code {c})" if t in (3, 5, 11) else "")
        pkt.detail = {"type": t, "code": c}
        if t in (0, 8) and len(body) >= 8:
            ident, seq = struct.unpack("!HH", body[4:8])
            pkt.info += f" id={ident} seq={seq}"
            pkt.detail.update(id=ident, seq=seq)
    elif proto == 6:
        decode_tcp(pkt, body)
    elif proto == 17:
        decode_udp(pkt, body)
    elif proto == 89:
        decode_ospf(pkt, body)
    elif proto == 112:
        pkt.protocol, pkt.info = "VRRP", "VRRP advertisement"
    elif proto == 50:
        decode_esp(pkt, body)
    else:
        pkt.protocol, pkt.info = "IPv4", f"protocol {proto}"


def decode_tcp(pkt: Packet, b: bytes) -> None:
    pkt.transport = "TCP"
    pkt.sport, pkt.dport = struct.unpack("!HH", b[0:4])
    flags = b[13]
    names = [
        n
        for bit, n in (
            (0x02, "SYN"),
            (0x10, "ACK"),
            (0x01, "FIN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x20, "URG"),
        )
        if flags & bit
    ]
    app = TCP_PORTS.get(pkt.dport) or TCP_PORTS.get(pkt.sport)
    pkt.protocol = app or "TCP"
    pkt.info = f"{pkt.sport} -> {pkt.dport} [{','.join(names)}]"
    pkt.detail = {"flags": names}
    payload = b[(b[12] >> 4) * 4 :]
    if 179 in (pkt.sport, pkt.dport) and payload:
        decode_bgp(pkt, payload)


def decode_udp(pkt: Packet, b: bytes) -> None:
    pkt.transport = "UDP"
    pkt.sport, pkt.dport = struct.unpack("!HH", b[0:4])
    payload = b[8:]
    ports = {pkt.sport, pkt.dport}
    if ports & {67, 68}:
        decode_dhcp(pkt, payload)
    elif ports & RADIUS_PORTS:
        decode_radius(pkt, payload)
    elif (app := udp_app(pkt, payload)) is not None:
        name, decoder = app
        try:
            decoder(pkt, payload)
        except (IndexError, ValueError, struct.error):  # one malformed field: name it, keep the rest
            pkt.protocol, pkt.info = name, f"{name} (malformed)"
    else:
        pkt.protocol = UDP_PORTS.get(pkt.dport) or UDP_PORTS.get(pkt.sport) or "UDP"
        pkt.info = f"{pkt.sport} -> {pkt.dport} len={len(payload)}"


OSPF_TYPES = {1: "Hello", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Ack"}


def decode_ospf(pkt: Packet, b: bytes) -> None:
    version, typ = b[0], b[1]
    router, area = ip4(b[4:8]), ip4(b[8:12])
    pkt.protocol = "OSPF" if version == 2 else f"OSPFv{version}"
    pkt.info = f"{OSPF_TYPES.get(typ, typ)} from {router} area {area}"
    pkt.detail = {"type": OSPF_TYPES.get(typ, typ), "router_id": router, "area": area}
    if version == 2 and typ == 1 and len(b) >= 44:
        pkt.detail["hello_interval"] = struct.unpack("!H", b[28:30])[0]
        pkt.detail["dead_interval"] = struct.unpack("!I", b[32:36])[0]
        pkt.detail["dr"], pkt.detail["bdr"] = ip4(b[36:40]), ip4(b[40:44])
        length = struct.unpack("!H", b[2:4])[0]
        pkt.detail["neighbors"] = [ip4(b[i : i + 4]) for i in range(44, min(length, len(b)) - 3, 4)]


DHCP_TYPES = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "ACK",
    6: "NAK",
    7: "Release",
    8: "Inform",
}


def decode_dhcp(pkt: Packet, b: bytes) -> None:
    pkt.protocol = "DHCP"
    xid = struct.unpack("!I", b[4:8])[0]
    yiaddr, chaddr = ip4(b[16:20]), mac(b[28:34])
    msg = None
    opts: dict[str, Any] = {}
    i = 240 if b[236:240] == b"\x63\x82\x53\x63" else len(b)
    while i < len(b):
        code = b[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        ln = b[i + 1]
        val = b[i + 2 : i + 2 + ln]
        if code == 53 and val:
            msg = val[0]
        elif code == 50 and ln == 4:
            opts["requested_ip"] = ip4(val)
        elif code == 54 and ln == 4:
            opts["server"] = ip4(val)
        elif code == 12:
            opts["hostname"] = safe_text(val)
        i += 2 + ln
    name = DHCP_TYPES.get(msg or 0, f"type {msg}" if msg is not None else "BOOTP")
    pkt.info = f"DHCP {name} xid=0x{xid:08x} client {chaddr}" + (
        f" -> {yiaddr}" if yiaddr != "0.0.0.0" else ""
    )
    pkt.detail = {"type": name, "xid": f"0x{xid:08x}", "client_mac": chaddr, **opts}
    if yiaddr != "0.0.0.0":
        pkt.detail["your_ip"] = yiaddr


RADIUS_CODES = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    11: "Access-Challenge",
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
}
RADIUS_TEXT = {
    1: "User-Name",
    11: "Filter-Id",
    18: "Reply-Message",
    30: "Called-Station-Id",
    31: "Calling-Station-Id",
    32: "NAS-Identifier",
    44: "Acct-Session-Id",
    87: "NAS-Port-Id",
}
RADIUS_INT = {
    5: "NAS-Port",
    6: "Service-Type",
    27: "Session-Timeout",
    40: "Acct-Status-Type",
    61: "NAS-Port-Type",
    101: "Error-Cause",
}
RADIUS_IP = {4: "NAS-IP-Address", 8: "Framed-IP-Address"}
# Never shown, not even masked: credentials and opaque session state.
RADIUS_SECRET = {
    2: "User-Password",
    3: "CHAP-Password",
    24: "State",
    25: "Class",
    60: "CHAP-Challenge",
    69: "Tunnel-Password",
    80: "Message-Authenticator",
}
SERVICE_TYPES = {
    1: "Login",
    2: "Framed",
    5: "Outbound",
    6: "Administrative",
    8: "Authenticate-Only",
    10: "Call-Check",
}
ACCT_STATUS = {1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off"}
# Cisco AV-pairs whose values are shown; every other pair keeps its name with the value masked.
SAFE_AVPAIRS = frozenset(
    {
        "audit-session-id",
        "method",
        "service-type",
        "client-iif-id",
        "cts:security-group-tag",
        "acs:ciscosecure-defined-acl",
        "ip:inacl",
        "ip:outacl",
        "ipv6:inacl",
        "url-redirect",
        "url-redirect-acl",
        "subscriber:command",
        "subscriber:reauthenticate-type",
        "device-traffic-class",
        "profile-name",
        "shell:priv-lvl",
        "aaa:service",
        "aaa:event",
        "linksec-policy",
        "dc-profile-name",
        "dc-device-name",
        "dc-device-class-tag",
        "dc-certainty-metric",
        "dc-opaque",
        "lldp-tlv",
        "cdp-tlv",
        "dhcp-option",
        "http-tlv",
        "connect-progress",
        "disc-cause",
        "disc-cause-ext",
        "vlan-id",
        "interface-template-name",
        "nas-update",
        "termination-action-modifier",
        "acct-session-id",
    }
)
AVPAIR_SPLIT = re.compile(r"[=*]")
MAX_TEXT = 128


def safe_text(raw: bytes | str, limit: int = MAX_TEXT) -> str:
    """Wire text for the model: printable characters only, length-capped (it can carry anything)."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text if len(text) <= limit else text[:limit] + "..."


def avpair(text: str) -> str:
    m = AVPAIR_SPLIT.search(text)
    if not m:
        return safe_text(text)
    key = text[: m.start()]
    if key.strip().lower() in SAFE_AVPAIRS:
        return safe_text(text, 256)
    return f"{safe_text(key)}{m.group(0)}********"


def decode_radius(pkt: Packet, b: bytes) -> None:
    code, ident = b[0], b[1]
    length = struct.unpack("!H", b[2:4])[0]
    name = RADIUS_CODES.get(code, f"code {code}")
    attrs: dict[str, Any] = {}
    avpairs: list[str] = []
    eap = bytearray()
    hidden: list[str] = []
    i = 20
    end = min(length, len(b))
    while i + 2 <= end:
        t, ln = b[i], b[i + 1]
        if ln < 2:
            break
        if i + ln > end:
            break  # runs past the RADIUS length: padding or a truncated packet
        val = b[i + 2 : i + ln]
        i += ln
        if t in RADIUS_SECRET:
            hidden.append(RADIUS_SECRET[t])
        elif t in RADIUS_TEXT:
            attrs[RADIUS_TEXT[t]] = safe_text(val)
        elif t in RADIUS_INT and len(val) == 4:
            n = struct.unpack("!I", val)[0]
            attrs[RADIUS_INT[t]] = (
                SERVICE_TYPES.get(n, n) if t == 6 else ACCT_STATUS.get(n, n) if t == 40 else n
            )
        elif t in RADIUS_IP and len(val) == 4:
            attrs[RADIUS_IP[t]] = ip4(val)
        elif t in (64, 65, 81):  # Tunnel-Type / Medium-Type / Private-Group-ID (VLAN)
            label = {64: "Tunnel-Type", 65: "Tunnel-Medium-Type", 81: "Tunnel-Private-Group-ID"}[t]
            attrs[label] = safe_text(val[1:]) if t == 81 else int.from_bytes(val[1:], "big")
        elif t == 79:
            eap += val
        elif t == 26 and len(val) >= 6:
            vendor = struct.unpack("!I", val[0:4])[0]
            if vendor == 9:  # Cisco: every Cisco-AVPair (sub-type 1) in the attribute
                j = 4
                while j + 2 <= len(val) and val[j + 1] >= 2:
                    if val[j] == 1:
                        avpairs.append(avpair(val[j + 2 : j + val[j + 1]].decode("utf-8", "replace")))
                    j += val[j + 1]
            elif vendor not in attrs.setdefault("vendor_specific", []):
                attrs["vendor_specific"].append(vendor)
    pkt.protocol = "RADIUS"
    user = attrs.get("User-Name")
    pkt.info = f"{name} id={ident}" + (f" user={user}" if user else "")
    detail: dict[str, Any] = {"code": name, "id": ident, **attrs}
    if avpairs:
        detail["cisco_avpairs"] = avpairs
    if eap:
        detail["eap"] = eap_summary(bytes(eap))
        pkt.info += f" EAP {detail['eap'].get('code', 'truncated')}"
    if hidden:
        detail["hidden_attributes"] = sorted(set(hidden))
    pkt.detail = detail


EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_TYPES = {
    1: "Identity",
    3: "Nak",
    4: "MD5-Challenge",
    13: "EAP-TLS",
    21: "EAP-TTLS",
    25: "PEAP",
    26: "MSCHAPv2",
    43: "EAP-FAST",
}


def eap_summary(b: bytes) -> dict[str, Any]:
    if len(b) < 4:
        return {"error": "truncated EAP"}
    code, ident = b[0], b[1]
    out: dict[str, Any] = {"code": EAP_CODES.get(code, code), "id": ident}
    if code in (1, 2) and len(b) > 4:
        out["type"] = EAP_TYPES.get(b[4], b[4])
        if b[4] == 1 and code == 2:
            length = struct.unpack("!H", b[2:4])[0]
            out["identity"] = safe_text(b[5:length])
    return out


EAPOL_TYPES = {0: "EAP", 1: "Start", 2: "Logoff", 3: "Key", 4: "ASF-Alert"}


def decode_eapol(pkt: Packet, p: bytes) -> None:
    typ = p[1]
    pkt.protocol = "EAPOL"
    pkt.info = f"EAPOL-{EAPOL_TYPES.get(typ, typ)}"
    pkt.detail = {"type": EAPOL_TYPES.get(typ, typ)}
    if typ == 0 and len(p) > 4:
        eap = eap_summary(p[4:])
        pkt.detail["eap"] = eap
        pkt.info += f" {eap.get('code', eap.get('error'))}" + (f" {eap['type']}" if "type" in eap else "")
        if "identity" in eap:
            pkt.info += f" identity={eap['identity']}"
    elif typ == 3 and len(p) >= 7:
        # EAPOL-Key: descriptor type, then key information (big endian); key data never decoded
        info = struct.unpack("!H", p[5:7])[0]
        pairwise, install, ack, mic, secure = (bool(info & b) for b in (0x08, 0x40, 0x80, 0x100, 0x200))
        if info & 0x0800:
            msg = "key request" + (" (MIC failure)" if info & 0x0400 else "")
        elif not pairwise:
            msg = "group key 1/2" if ack else "group key 2/2"
        elif ack and not mic:
            msg = "4-way 1/4"
        elif ack and mic and install:
            msg = "4-way 3/4"
        elif mic and not ack and not secure:
            msg = "4-way 2/4"
        elif mic and not ack and secure:
            msg = "4-way 4/4"
        else:
            msg = f"key info 0x{info:04x}"
        pkt.info += f" {msg}"
        pkt.detail["key"] = msg


# --- overlay, SGT, routing, VPN and telemetry protocols (L70) -----------------------------------

Decoder = Callable[[Packet, bytes], None]
NETFLOW_PORTS = {2055, 2056, 4739, 9995, 9996}


def udp_app(pkt: Packet, payload: bytes) -> tuple[str, Decoder] | None:
    """The L70 decoder for a UDP payload, by well-known port (the destination port first: a client's
    ephemeral source port can collide with one of these)."""
    for port in (pkt.dport, pkt.sport):
        if port == 4789 and len(payload) >= 8 and payload[0] & 0x08:
            return "VXLAN", decode_vxlan
        if port == 4342:
            return "LISP", decode_lisp
        if port in (3784, 4784, 3785):
            return "BFD", decode_bfd
        if port in (500, 4500):
            return "IKE", decode_ike_udp
        if port in NETFLOW_PORTS and payload[:2] in (b"\x00\x05", b"\x00\x09", b"\x00\x0a"):
            return "NetFlow", decode_netflow
        if port == 514:
            return "Syslog", decode_syslog
        if port == 53:
            return "DNS", decode_dns
    return None


def _u16(b: bytes, off: int) -> int:
    return int(struct.unpack("!H", b[off : off + 2])[0])


def _u32(b: bytes, off: int) -> int:
    return int(struct.unpack("!I", b[off : off + 4])[0])


# VXLAN (RFC 7348) with the Group Policy Option (draft-smith-vxlan-group-policy): SD-Access carries the
# source SGT in the 16-bit group policy ID; G flag = GPO header present, A flag = policy already applied.
def decode_vxlan(pkt: Packet, b: bytes) -> None:
    flags, gflags = b[0], b[1]
    vni = int.from_bytes(b[4:7], "big")
    gpo = bool(flags & 0x80)
    group = _u16(b, 2)
    pkt.protocol = "VXLAN"
    detail: dict[str, Any] = {"vni": vni, "sgt": group if gpo else None}
    if gpo:
        detail["policy_applied"] = bool(gflags & 0x08)
        pkt.sgt, pkt.sgt_carrier = group, "VXLAN"
    inner = Packet(no=pkt.no, time=pkt.time, length=max(len(b) - 8, 0))
    try:
        decode_ethernet(inner, b[8:])
    except Exception:  # noqa: BLE001 - the outer header is still worth reporting
        inner.info = inner.info or "malformed"
    src = f"{inner.src}:{inner.sport}" if inner.sport is not None else inner.src
    dst = f"{inner.dst}:{inner.dport}" if inner.dport is not None else inner.dst
    detail["inner"] = {"src": src, "dst": dst, "protocol": inner.protocol, "info": inner.info}
    tag = (f"SGT {group}" + (" (unknown)" if group == 0 else "")) if gpo else "no SGT"
    pkt.info = f"VNI {vni} {tag} inner {src} -> {dst} {inner.protocol} {inner.info}".rstrip()
    pkt.detail = detail


# LISP control plane (RFC 9301), UDP 4342: what an SD-Access edge registers with the control-plane node
LISP_TYPES = {
    1: "Map-Request",
    2: "Map-Reply",
    3: "Map-Register",
    4: "Map-Notify",
    5: "Map-Notify-Ack",
    6: "Map-Referral",
    8: "Encapsulated Control Message",
}
LISP_ACTIONS = {0: "no-action", 1: "natively-forward", 2: "send-map-request", 3: "drop"}
MAX_RECORDS = 10


def lisp_address(b: bytes, off: int) -> tuple[str, int]:
    """An AFI-prefixed LISP address at `off` and the offset after it; instance-id LCAF as '[iid] addr'."""
    afi = _u16(b, off)
    off += 2
    if afi == 0:
        return "", off
    if afi == 1:
        return ip4(b[off : off + 4]), off + 4
    if afi == 2:
        return str(ipaddress.IPv6Address(b[off : off + 16])), off + 16
    if afi == 6:
        return mac(b[off : off + 6]), off + 6
    if afi == 16387:  # LISP Canonical Address Format
        typ, length = b[off + 2], _u16(b, off + 4)
        body, end = b[off + 6 : off + 6 + length], off + 6 + length
        if typ == 2 and len(body) >= 6:  # instance ID: the VN in SD-Access
            addr, _ = lisp_address(body, 4)
            return f"[{_u32(body, 0)}] {addr}", end
        return f"LCAF type {typ}", end
    raise ValueError(f"LISP AFI {afi}")


def lisp_records(b: bytes, off: int, count: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for _ in range(min(count, MAX_RECORDS)):
        ttl, locators, masklen, act = _u32(b, off), b[off + 4], b[off + 5], b[off + 6] >> 5
        eid, off = lisp_address(b, off + 10)
        rlocs = []
        for _ in range(locators):
            reachable = bool(b[off + 5] & 0x01)
            rloc, off = lisp_address(b, off + 6)
            rlocs.append(rloc if reachable else f"{rloc} (unreachable)")
        record: dict[str, Any] = {"eid": f"{eid}/{masklen}", "rlocs": rlocs, "ttl_minutes": ttl}
        if not locators:
            record["action"] = LISP_ACTIONS.get(act, act)
        records.append(record)
    return records


def _record_text(records: list[dict[str, Any]]) -> str:
    parts = [
        f"{r['eid']} RLOC {', '.join(r['rlocs'])}"
        if r["rlocs"]
        else f"{r['eid']} negative ({r.get('action')})"
        for r in records
    ]
    return _few(parts, 2)


def decode_lisp(pkt: Packet, b: bytes) -> None:
    typ = b[0] >> 4
    name = LISP_TYPES.get(typ, f"type {typ}")
    pkt.protocol = "LISP"
    detail: dict[str, Any] = {"type": name}
    if typ == 8:  # ECM: an IP + UDP header, then the Map-Request it carries towards the map resolver
        inner_ip = b[4:]
        if inner_ip[0] >> 4 != 4:
            pkt.info, pkt.detail = name, detail
            return
        ihl = (inner_ip[0] & 0x0F) * 4
        inner = Packet(no=pkt.no, time=pkt.time, length=len(inner_ip))
        decode_lisp(inner, inner_ip[ihl + 8 :])
        pkt.info = f"{inner.info} (encapsulated)"
        pkt.detail = {**inner.detail, "encapsulated": True, "eid_source": ip4(inner_ip[12:16])}
        return
    if typ == 1:
        irc, count = b[2] & 0x1F, b[3]
        detail["nonce"] = b[4:12].hex()
        source, off = lisp_address(b, 12)
        itr = []
        for _ in range(irc + 1):
            rloc, off = lisp_address(b, off)
            itr.append(rloc)
        eids = []
        for _ in range(min(count, MAX_RECORDS)):
            masklen = b[off + 1]
            eid, off = lisp_address(b, off + 2)
            eids.append(f"{eid}/{masklen}")
        detail.update(eids=eids, itr_rlocs=itr, smr=bool(b[0] & 0x01))
        if source:
            detail["source_eid"] = source
        pkt.info = f"{name} for {_few(eids, 2)} from ITR {_few(itr, 2)}"
    elif typ == 2:
        detail["nonce"] = b[4:12].hex()
        detail["records"] = lisp_records(b, 12, b[3])
        pkt.info = f"{name} {_record_text(detail['records'])}"
    elif typ in (3, 4, 5):
        # nonce, key ID, authentication data length, authentication data (never read), records
        detail["nonce"] = b[4:12].hex()
        detail["records"] = lisp_records(b, 16 + _u16(b, 14), b[3])
        if typ == 3:
            detail["proxy_reply"] = bool(b[0] & 0x08)
            detail["want_map_notify"] = bool(b[2] & 0x01)
        n = len(detail["records"])
        pkt.info = f"{name} {n} record{'s' if n != 1 else ''}: {_record_text(detail['records'])}"
    else:
        pkt.info = name
    pkt.detail = detail


# BGP (RFC 4271) on TCP 179: every complete message in the segment
BGP_TYPES = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}
BGP_ERRORS: dict[int, tuple[str, dict[int, str]]] = {
    1: (
        "Message Header Error",
        {1: "Connection Not Synchronized", 2: "Bad Message Length", 3: "Bad Message Type"},
    ),
    2: (
        "OPEN Message Error",
        {
            1: "Unsupported Version Number",
            2: "Bad Peer AS",
            3: "Bad BGP Identifier",
            4: "Unsupported Optional Parameter",
            6: "Unacceptable Hold Time",
            7: "Unsupported Capability",
            11: "Role Mismatch",
        },
    ),
    3: (
        "UPDATE Message Error",
        {
            1: "Malformed Attribute List",
            2: "Unrecognized Well-known Attribute",
            3: "Missing Well-known Attribute",
            4: "Attribute Flags Error",
            5: "Attribute Length Error",
            6: "Invalid ORIGIN Attribute",
            8: "Invalid NEXT_HOP Attribute",
            9: "Optional Attribute Error",
            10: "Invalid Network Field",
            11: "Malformed AS_PATH",
        },
    ),
    4: ("Hold Timer Expired", {}),
    5: (
        "Finite State Machine Error",
        {
            1: "Unexpected Message in OpenSent",
            2: "Unexpected Message in OpenConfirm",
            3: "Unexpected Message in Established",
        },
    ),
    6: (
        "Cease",
        {
            1: "Maximum Number of Prefixes Reached",
            2: "Administrative Shutdown",
            3: "Peer De-configured",
            4: "Administrative Reset",
            5: "Connection Rejected",
            6: "Other Configuration Change",
            7: "Connection Collision Resolution",
            8: "Out of Resources",
            9: "Hard Reset",
            10: "BFD Down",
        },
    ),
    7: ("ROUTE-REFRESH Message Error", {1: "Invalid Message Length"}),
}
BGP_FAMILIES = {
    (1, 1): "ipv4-unicast",
    (1, 2): "ipv4-multicast",
    (2, 1): "ipv6-unicast",
    (2, 2): "ipv6-multicast",
    (1, 4): "ipv4-labeled",
    (1, 128): "vpnv4",
    (2, 128): "vpnv6",
    (25, 70): "l2vpn-evpn",
    (1, 133): "ipv4-flowspec",
}
BGP_CAPABILITIES = {
    1: "multiprotocol",
    2: "route-refresh",
    64: "graceful-restart",
    65: "4-octet-as",
    69: "add-path",
    70: "enhanced-route-refresh",
    71: "long-lived-graceful-restart",
}


def bgp_error(code: int, subcode: int) -> str:
    name, subs = BGP_ERRORS.get(code, (f"error code {code}", {}))
    if subcode and subs:
        return f"{name} / {subs.get(subcode, f'subcode {subcode}')}"
    return name if not subcode else f"{name} / subcode {subcode}"


def _count_prefixes(b: bytes) -> int:
    n = i = 0
    while i < len(b):
        i += 1 + (b[i] + 7) // 8
        n += 1
    return n


def bgp_message(typ: int, body: bytes) -> tuple[dict[str, Any], str]:
    name = BGP_TYPES.get(typ, f"type {typ}")
    msg: dict[str, Any] = {"type": name}
    if typ == 1 and len(body) >= 10:
        my_as, hold, bgp_id, optlen = _u16(body, 1), _u16(body, 3), ip4(body[5:9]), body[9]
        caps: list[str] = []
        afis: list[str] = []
        off, end = 10, 10 + optlen
        while off + 2 <= end:
            ptype, plen = body[off], body[off + 1]
            if ptype == 2:  # capabilities
                c = off + 2
                while c + 2 <= off + 2 + plen:
                    code, clen = body[c], body[c + 1]
                    value = body[c + 2 : c + 2 + clen]
                    caps.append(BGP_CAPABILITIES.get(code, f"capability {code}"))
                    if code == 65 and clen == 4:
                        my_as = _u32(value, 0)
                    elif code == 1 and clen == 4:
                        afi, safi = _u16(value, 0), value[3]
                        afis.append(BGP_FAMILIES.get((afi, safi), f"afi {afi} safi {safi}"))
                    c += 2 + clen
            off += 2 + plen
        msg.update(version=body[0], asn=my_as, hold_time=hold, bgp_id=bgp_id)
        if afis:
            msg["families"] = afis
        if caps:
            msg["capabilities"] = sorted(set(caps))
        return msg, f"OPEN AS {my_as} hold {hold}s id {bgp_id}"
    if typ == 2 and len(body) >= 4:
        wlen = _u16(body, 0)
        alen = _u16(body, 2 + wlen)
        attrs, nlri = body[4 + wlen : 4 + wlen + alen], body[4 + wlen + alen :]
        families: dict[str, dict[str, int | None]] = {}
        if wlen or nlri:
            families["ipv4-unicast"] = {
                "announced": _count_prefixes(nlri),
                "withdrawn": _count_prefixes(body[2 : 2 + wlen]),
            }
        i = 0
        while i + 3 <= len(attrs):
            flags, atype = attrs[i], attrs[i + 1]
            ext = bool(flags & 0x10)
            alen_i = _u16(attrs, i + 2) if ext else attrs[i + 2]
            value = attrs[i + (4 if ext else 3) : i + (4 if ext else 3) + alen_i]
            i += (4 if ext else 3) + alen_i
            if atype in (14, 15) and len(value) >= 3:  # MP_REACH_NLRI / MP_UNREACH_NLRI
                afi, safi = _u16(value, 0), value[2]
                fam = families.setdefault(
                    BGP_FAMILIES.get((afi, safi), f"afi {afi} safi {safi}"),
                    {"announced": 0, "withdrawn": 0},
                )
                routes = value[5 + value[3] :] if atype == 14 else value[3:]
                # unicast/multicast prefixes are counted; other families (VPN, EVPN) only say "some"
                count = _count_prefixes(routes) if safi in (1, 2) else (None if routes else 0)
                fam["announced" if atype == 14 else "withdrawn"] = count
        msg["families"] = families
        empty = all(v == {"announced": 0, "withdrawn": 0} for v in families.values())
        if (not families and not alen) or (families and empty and not wlen and not nlri):
            msg["end_of_rib"] = True
            return msg, f"UPDATE End-of-RIB ({', '.join(families) or 'ipv4-unicast'})"
        if not families:
            return msg, "UPDATE (no prefixes)"
        parts = []
        for family, n in families.items():
            a, w = n.get("announced"), n.get("withdrawn")
            counts = " ".join(
                f"{sign}{v if v is not None else '?'}" for sign, v in (("+", a), ("-", w)) if v != 0
            )
            parts.append(f"{family} {counts}")
        return msg, f"UPDATE {', '.join(parts)} prefixes"
    if typ == 3 and len(body) >= 2:
        msg.update(code=body[0], subcode=body[1], error=bgp_error(body[0], body[1]))
        return msg, f"NOTIFICATION {msg['error']}"
    if typ == 5 and len(body) >= 4:
        afi, safi = _u16(body, 0), body[3]
        msg["family"] = BGP_FAMILIES.get((afi, safi), f"afi {afi} safi {safi}")
        return msg, f"ROUTE-REFRESH {msg['family']}"
    return msg, name


def decode_bgp(pkt: Packet, payload: bytes) -> None:
    messages: list[dict[str, Any]] = []
    texts: list[str] = []
    off = 0
    while off + 19 <= len(payload) and payload[off : off + 16] == b"\xff" * 16:
        length, typ = _u16(payload, off + 16), payload[off + 18]
        if length < 19 or off + length > len(payload):
            texts.append(f"{BGP_TYPES.get(typ, typ)} (continues in the next segment)")
            break
        try:
            msg, text = bgp_message(typ, payload[off + 19 : off + length])
        except (IndexError, ValueError, struct.error):
            msg, text = {"type": BGP_TYPES.get(typ, f"type {typ}"), "malformed": True}, "malformed"
        messages.append(msg)
        texts.append(text)
        off += length
    if messages:
        pkt.detail["bgp"] = messages
    pkt.info = "; ".join(texts) if texts else f"{pkt.info} (continuation)"


# BFD control packets (RFC 5880): UDP 3784 single hop, 4784 multihop, 3785 echo
BFD_STATES = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}
BFD_DIAG = {
    0: "none",
    1: "Control Detection Time Expired",
    2: "Echo Function Failed",
    3: "Neighbor Signaled Session Down",
    4: "Forwarding Plane Reset",
    5: "Path Down",
    6: "Concatenated Path Down",
    7: "Administratively Down",
    8: "Reverse Concatenated Path Down",
    9: "Mis-Connectivity Defect",
}


def decode_bfd(pkt: Packet, b: bytes) -> None:
    pkt.protocol = "BFD"
    if 3785 in (pkt.sport, pkt.dport):
        pkt.info, pkt.detail = "echo", {"echo": True}
        return
    if len(b) < 24:
        raise ValueError("short BFD packet")
    diag, state = b[0] & 0x1F, BFD_STATES[b[1] >> 6]
    tx, rx = _u32(b, 12) // 1000, _u32(b, 16) // 1000
    pkt.detail = {
        "state": state,
        "diag": BFD_DIAG.get(diag, f"diag {diag}"),
        "my_discriminator": _u32(b, 4),
        "your_discriminator": _u32(b, 8),
        "min_tx_ms": tx,
        "min_rx_ms": rx,
        "multiplier": b[2],
    }
    if 4784 in (pkt.sport, pkt.dport):
        pkt.detail["multihop"] = True
    flags = [n for bit, n in ((0x20, "poll"), (0x10, "final")) if b[1] & bit]
    if flags:
        pkt.detail["flags"] = flags
    pkt.info = f"{state} diag {pkt.detail['diag']} tx {tx}ms rx {rx}ms x{b[2]}"


# IKE (RFC 7296 IKEv2, RFC 2408 ISAKMP) on UDP 500 and 4500 (NAT-T, after a 4-byte zero marker)
IKEV2_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    43: "IKE_INTERMEDIATE",
}
IKEV1_EXCHANGES = {2: "Main Mode", 4: "Aggressive Mode", 5: "Informational", 32: "Quick Mode"}
IKE_NOTIFY = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND",
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
    16404: "MULTIPLE_AUTH_SUPPORTED",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS",
}
IKE_ERROR_LIMIT = 16384  # notify types below this are errors


def decode_ike_udp(pkt: Packet, b: bytes) -> None:
    if 4500 in (pkt.sport, pkt.dport):
        if len(b) == 1 and b[0] == 0xFF:
            pkt.protocol, pkt.info = "IKE", "NAT-T keepalive"
            return
        if b[:4] != b"\x00\x00\x00\x00":  # no non-ESP marker: ESP in UDP
            decode_esp(pkt, b)
            pkt.detail["udp_encapsulated"] = True
            return
        b = b[4:]
    decode_ike(pkt, b)


def decode_ike(pkt: Packet, b: bytes) -> None:
    if len(b) < 28:
        raise ValueError("short IKE header")
    nxt, version, xchg, flags = b[16], b[17] >> 4, b[18], b[19]
    end = min(_u32(b, 24), len(b))
    notify: list[int] = []
    encrypted = False
    off = 28
    if version == 2:
        pkt.protocol = "IKEv2"
        exchange = IKEV2_EXCHANGES.get(xchg, f"exchange {xchg}")
        response = bool(flags & 0x20)
        while nxt and off + 4 <= end:
            plen = _u16(b, off + 2)
            if nxt == 46:  # SK: everything after it is encrypted (IKE_AUTH errors travel in here)
                encrypted = True
                break
            if nxt == 41 and plen >= 8:
                notify.append(_u16(b, off + 6))
            if plen < 4:
                break
            nxt, off = b[off], off + plen
    else:
        pkt.protocol = "IKEv1"
        exchange = IKEV1_EXCHANGES.get(xchg, f"exchange {xchg}")
        response = b[8:16] != bytes(8)  # the responder cookie is set
        encrypted = bool(flags & 0x01)
        while nxt and not encrypted and off + 4 <= end:
            plen = _u16(b, off + 2)
            if nxt == 11 and plen >= 12:  # notification: DOI, protocol, SPI size, type
                notify.append(_u16(b, off + 10))
            if plen < 4:
                break
            nxt, off = b[off], off + plen
    pkt.detail = {
        "exchange": exchange,
        "message": "response" if response else "request",
        "initiator": bool(flags & 0x08) if version == 2 else None,
        "message_id": _u32(b, 20),
        "spi_i": b[0:8].hex(),
        "spi_r": b[8:16].hex(),
    }
    if notify:
        pkt.detail["notify"] = [IKE_NOTIFY.get(n, f"notify {n}") for n in notify]
        errors = [IKE_NOTIFY.get(n, f"notify {n}") for n in notify if n < IKE_ERROR_LIMIT]
        if errors:
            pkt.detail["errors"] = errors
    if encrypted:
        pkt.detail["encrypted"] = True
    errors = pkt.detail.get("errors") or []
    pkt.info = f"{exchange} {pkt.detail['message']}" + (f": {', '.join(errors)}" if errors else "")


def decode_esp(pkt: Packet, b: bytes) -> None:
    pkt.protocol = "ESP"
    if len(b) < 8:
        pkt.info = "IPsec ESP (truncated)"
        return
    spi, seq = _u32(b, 0), _u32(b, 4)
    pkt.info = f"SPI 0x{spi:08x} seq={seq}"
    pkt.detail = {"spi": f"0x{spi:08x}", "seq": seq}


# NetFlow v5/v9 (RFC 3954) and IPFIX (RFC 7011): templates and data sets per export packet
def decode_netflow(pkt: Packet, b: bytes) -> None:
    version = _u16(b, 0)
    pkt.protocol = "IPFIX" if version == 10 else "NetFlow"
    if version == 5:
        count = _u16(b, 2)
        pkt.detail = {"version": 5, "records": count, "sequence": _u32(b, 16)}
        pkt.info = f"v5 {count} records"
        return
    if version == 9:
        sequence, domain, off, end = _u32(b, 12), _u32(b, 16), 20, len(b)
        template_set, options_set = 0, 1
    else:
        sequence, domain, off, end = _u32(b, 8), _u32(b, 12), 16, min(_u16(b, 2), len(b))
        template_set, options_set = 2, 3
    templates: list[dict[str, Any]] = []
    options: list[dict[str, Any]] = []
    data: list[dict[str, Any]] = []
    while off + 4 <= end:
        set_id, set_len = _u16(b, off), _u16(b, off + 2)
        if set_len < 4:
            break
        body = b[off + 4 : off + set_len]
        off += set_len
        if set_id == template_set:
            templates += _templates(body, ipfix=version == 10)
        elif set_id == options_set:
            options += _options_templates(body, ipfix=version == 10)
        elif set_id >= 256:
            data.append({"template": set_id, "bytes": len(body)})
    pkt.detail = {"version": version, "source_id": domain, "sequence": sequence}
    if templates:
        pkt.detail["templates"] = templates
    if options:
        pkt.detail["options_templates"] = options
    if data:
        pkt.detail["data_sets"] = data
    parts = []
    if templates or options:
        parts.append("templates " + ", ".join(str(t["id"]) for t in templates + options))
    if data:
        parts.append("data " + ", ".join(f"{d['template']} ({d['bytes']} bytes)" for d in data))
    pkt.info = f"v{version} source {domain}: " + ("; ".join(parts) or "empty")


def _fields(body: bytes, off: int, count: int, *, ipfix: bool) -> tuple[int | None, int]:
    """Record length of `count` field specifiers at `off` (None when one is variable-length) and the end."""
    total: int | None = 0
    for _ in range(count):
        ftype, flen = _u16(body, off), _u16(body, off + 2)
        off += 4 + (4 if ipfix and ftype & 0x8000 else 0)  # IPFIX enterprise number
        total = None if total is None or flen == 0xFFFF else total + flen
    if off > len(body):
        raise ValueError("template runs past its set")
    return total, off


def _templates(body: bytes, *, ipfix: bool) -> list[dict[str, Any]]:
    out, off = [], 0
    while off + 4 <= len(body):
        tid, count = _u16(body, off), _u16(body, off + 2)
        if tid < 256:  # padding
            break
        length, off = _fields(body, off + 4, count, ipfix=ipfix)
        out.append({"id": tid, "fields": count, "record_bytes": length})
    return out


def _options_templates(body: bytes, *, ipfix: bool) -> list[dict[str, Any]]:
    out, off = [], 0
    while off + 6 <= len(body):
        tid = _u16(body, off)
        if tid < 256:
            break
        if ipfix:  # template ID, field count, scope field count, fields
            count = _u16(body, off + 2)
            length, off = _fields(body, off + 6, count, ipfix=True)
        else:  # template ID, scope length, option length (bytes), fields
            count = (_u16(body, off + 2) + _u16(body, off + 4)) // 4
            length, off = _fields(body, off + 6, count, ipfix=False)
        out.append({"id": tid, "fields": count, "record_bytes": length, "options": True})
    return out


# Syslog (RFC 3164/5424) on UDP 514: priority in words, Cisco mnemonic, text with secrets masked
SYSLOG_SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
SYSLOG_FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "audit",
    14: "alert",
    15: "clock",
    **{16 + i: f"local{i}" for i in range(8)},
}
CISCO_MNEMONIC = re.compile(r"%([A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*)-([0-7])-([A-Z0-9_]+)")
SYSLOG_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|community|token|psk|pre-shared-key|passphrase|key-string|key)"
    r"(\s*[:=]\s*|\s+(?:[0-9]\s+)?)(\S+)"
)


def mask_syslog(text: str) -> str:
    """Syslog text with the value after password/secret/key/community/... words replaced by ********."""
    return SYSLOG_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}********", text)


def decode_syslog(pkt: Packet, b: bytes) -> None:
    pkt.protocol = "Syslog"
    text = b.decode("utf-8", "replace")
    m = re.match(r"<(\d{1,3})>", text)
    if not m or int(m.group(1)) > 191:
        pkt.info, pkt.detail = "no priority", {"text": safe_text(mask_syslog(text))}
        return
    facility, severity = divmod(int(m.group(1)), 8)
    body = mask_syslog(text[m.end() :].strip())
    pkt.detail = {
        "facility": SYSLOG_FACILITIES.get(facility, str(facility)),
        "severity": SYSLOG_SEVERITIES[severity],
        "text": safe_text(body),
    }
    if mn := CISCO_MNEMONIC.search(body):
        pkt.detail["mnemonic"] = mn.group(0)
    pkt.info = f"{pkt.detail['facility']}.{pkt.detail['severity']} {safe_text(body, 100)}"


# DNS (RFC 1035) on UDP 53: questions and answers
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_name(b: bytes, off: int) -> tuple[str, int]:
    """A (possibly compressed) domain name at `off` and the offset after it in the message."""
    labels: list[str] = []
    end: int | None = None
    for _ in range(128):  # bounds compression loops
        ln = b[off]
        if ln & 0xC0 == 0xC0:
            end = off + 2 if end is None else end
            off = ((ln & 0x3F) << 8) | b[off + 1]
            continue
        if ln == 0:
            return safe_text(".".join(labels) or ".", 255), off + 1 if end is None else end
        labels.append(b[off + 1 : off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    raise ValueError("DNS name loop")


def _dns_rdata(b: bytes, typ: int, off: int, rdlen: int) -> str:
    rd = b[off : off + rdlen]
    if typ == 1 and rdlen == 4:
        return ip4(rd)
    if typ == 28 and rdlen == 16:
        return str(ipaddress.IPv6Address(rd))
    if typ in (2, 5, 12):
        return dns_name(b, off)[0]
    if typ == 15:
        return f"{_u16(b, off)} {dns_name(b, off + 2)[0]}"
    if typ == 33:
        return f"{dns_name(b, off + 6)[0]}:{_u16(b, off + 4)}"
    return f"{rdlen} bytes"


def decode_dns(pkt: Packet, b: bytes) -> None:
    pkt.protocol = "DNS"
    ident, flags, qdcount, ancount = struct.unpack("!HHHH", b[0:8])
    response, rcode = bool(flags & 0x8000), flags & 0x0F
    off = 12
    questions = []
    for _ in range(min(qdcount, MAX_RECORDS)):
        name, off = dns_name(b, off)
        questions.append(f"{DNS_TYPES.get(_u16(b, off), _u16(b, off))} {name}")
        off += 4
    answers = []
    for _ in range(min(ancount, 20) if response else 0):
        name, off = dns_name(b, off)
        typ, rdlen = _u16(b, off), _u16(b, off + 8)
        answers.append(f"{name} {DNS_TYPES.get(typ, typ)} {_dns_rdata(b, typ, off + 10, rdlen)}")
        off += 10 + rdlen
    pkt.detail = {"id": ident, "message": "response" if response else "query", "questions": questions}
    q = _few(questions, 2)
    if not response:
        pkt.info = f"query {q}"
        return
    pkt.detail["rcode"] = DNS_RCODES.get(rcode, f"rcode {rcode}")
    pkt.detail["answers"] = answers
    values = [a.split(" ", 2)[2] for a in answers]
    pkt.info = f"response {q}" + (f" -> {_few(values, 3)}" if values else "") + f" ({pkt.detail['rcode']})"


# --- filtering and summary ----------------------------------------------------------------------


def matches(
    pkt: Packet,
    *,
    host: str | None = None,
    src: str | None = None,
    dst: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
) -> bool:
    if host and host.lower() not in (pkt.src.lower(), pkt.dst.lower()):
        return False
    if src and src.lower() != pkt.src.lower():
        return False
    if dst and dst.lower() != pkt.dst.lower():
        return False
    names = (pkt.protocol.lower(), pkt.transport.lower(), pkt.sgt_carrier.lower())
    if protocol and protocol.lower() not in names:
        return False
    return not (port is not None and port not in (pkt.sport, pkt.dport))


HIGHLIGHT = (
    "RADIUS",
    "EAPOL",
    "OSPF",
    "DHCP",
    "ARP",
    "ICMP",
    "sftunnel",
    "TACACS+",
    "VXLAN",
    "LISP",
    "BGP",
    "BFD",
    "IKEv2",
    "IKEv1",
    "NetFlow",
    "IPFIX",
    "Syslog",
    "DNS",
)


def summarise(
    packets: list[Packet],
    *,
    highlights: int = 20,
    conversations: int = 10,
    whole: list[Packet] | None = None,
    truncated: bool = False,
) -> dict[str, Any]:
    """Protocol mix, top conversations and decoded highlights of the interesting protocols.
    `findings` are computed on `whole` (the unfiltered capture: a filter would hide the replies)."""
    mix = Counter(p.protocol for p in packets)
    conv: dict[tuple[str, str, str], list[int]] = {}
    for p in packets:
        a, b = sorted((p.src, p.dst))
        c = conv.setdefault((a, b, p.protocol), [0, 0])
        c[0] += 1
        c[1] += p.length
    top = sorted(conv.items(), key=lambda kv: (-kv[1][0], kv[0]))[:conversations]
    out: dict[str, Any] = {
        "packets": len(packets),
        "duration_seconds": round(packets[-1].time - packets[0].time, 3) if packets else 0,
        "protocols": dict(mix.most_common()),
        "top_conversations": [
            {"a": a, "b": b, "protocol": proto, "packets": n, "bytes": size}
            for (a, b, proto), (n, size) in top
        ],
    }
    hl: dict[str, list[dict[str, Any]]] = {}
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    omitted: Counter[str] = Counter()
    for p in packets if highlights else []:
        if p.protocol not in HIGHLIGHT:
            continue
        # repeats of the same packet (retransmitted Discovers, hellos) are one row with a count (L31)
        sig = _signature(p)
        if (row := groups.get(sig)) is not None:
            row["count"] = row.get("count", 1) + 1
            row["last_time"] = round(p.time, 3)
            continue
        if len(hl.setdefault(p.protocol, [])) < highlights:
            groups[sig] = p.row()
            hl[p.protocol].append(groups[sig])
        else:
            omitted[p.protocol] += 1
    if hl:
        out["highlights"] = {k: v for k, v in hl.items() if v}
    if omitted:
        out["highlights_omitted"] = dict(omitted)  # distinct packets beyond `highlights` per protocol
    if found := findings(packets if whole is None else whole, truncated=truncated):
        out["findings"] = found
    radius = Counter(p.detail.get("code") for p in packets if p.protocol == "RADIUS")
    if radius:
        out["radius"] = dict(radius)
    eapol = Counter(p.info for p in packets if p.protocol == "EAPOL")
    if eapol:
        out["eapol"] = dict(eapol.most_common(10))
    out.update(overlay_summary(packets))
    return out


def overlay_summary(packets: list[Packet]) -> dict[str, Any]:
    """L70 counters: SGTs seen (per carrier and VNI), BGP / LISP / IKE message counts, ESP SPIs,
    NetFlow/IPFIX exporters and syslog severities."""
    out: dict[str, Any] = {}
    sgt = Counter(
        (p.sgt_carrier, p.detail.get("vni") if p.sgt_carrier == "VXLAN" else None, p.sgt)
        for p in packets
        if p.sgt is not None
    )
    if sgt:
        out["sgt"] = [
            {"carrier": c, **({"vni": v} if v is not None else {}), "sgt": t, "packets": n}
            for (c, v, t), n in sgt.most_common(20)
        ]
    bgp = Counter(str(m.get("type")) for p in packets if p.protocol == "BGP" for m in p.detail.get("bgp", []))
    if bgp:
        out["bgp"] = dict(bgp.most_common())
    for proto, key in (("LISP", "lisp"), ("BFD", "bfd")):
        counts = Counter(
            str(p.detail.get("type") or p.detail.get("state")) for p in packets if p.protocol == proto
        )
        if counts:
            out[key] = dict(counts.most_common())
    ike = Counter(
        f"{p.protocol} {p.detail.get('exchange')} {p.detail.get('message')}"
        for p in packets
        if p.protocol in ("IKEv2", "IKEv1")
    )
    if ike:
        out["ike"] = dict(ike.most_common())
    esp = Counter((p.src, p.dst, p.detail.get("spi")) for p in packets if p.protocol == "ESP" and p.detail)
    if esp:
        out["esp"] = [
            {"spi": spi, "src": a, "dst": b, "packets": n} for (a, b, spi), n in esp.most_common(20)
        ]
    if exporters := netflow_exporters(packets)[0]:
        out["netflow"] = exporters
    syslog = Counter(str(p.detail.get("severity")) for p in packets if p.protocol == "Syslog")
    if syslog:
        senders = Counter(p.src for p in packets if p.protocol == "Syslog")
        out["syslog"] = {"severity": dict(syslog.most_common()), "senders": dict(senders.most_common(10))}
    return out


def netflow_exporters(packets: list[Packet]) -> tuple[list[dict[str, Any]], Counter[tuple[str, int, int]]]:
    """Per exporter (address, source ID / observation domain): templates seen, data records counted with
    the template's record length, and the data sets that came before any template for them."""
    known: dict[tuple[str, int], dict[int, int | None]] = {}
    rows: dict[tuple[str, int], dict[str, Any]] = {}
    early: Counter[tuple[str, int, int]] = Counter()
    for p in packets:
        d = p.detail
        if p.protocol not in ("NetFlow", "IPFIX") or "version" not in d:
            continue
        key = (p.src, int(d.get("source_id", 0)))
        row = rows.setdefault(
            key,
            {
                "exporter": p.src,
                "source_id": key[1],
                "version": d["version"],
                "packets": 0,
                "data_records": 0,
            },
        )
        row["packets"] += 1
        if d["version"] == 5:
            row["data_records"] += int(d.get("records", 0))
            continue
        templates = known.setdefault(key, {})
        for t in d.get("templates", []) + d.get("options_templates", []):
            templates[t["id"]] = t["record_bytes"]
            if t["id"] not in row.setdefault("templates", []):
                row["templates"].append(t["id"])
        for ds in d.get("data_sets", []):
            tid = ds["template"]
            if tid not in templates:
                early[(p.src, key[1], tid)] += 1
                row["data_sets_without_template"] = row.get("data_sets_without_template", 0) + 1
            elif length := templates[tid]:
                row["data_records"] += ds["bytes"] // length
            else:
                row["variable_length_sets"] = row.get("variable_length_sets", 0) + 1
    for row in rows.values():
        if "templates" in row:
            row["templates"].sort()
    return list(rows.values()), early


# --- findings: exchanges that never completed (L31) ----------------------------------------------
VOLATILE_DETAIL = {"xid", "id", "seq", "authenticator", "nonce", "sequence", "message_id"}


def _signature(p: Packet) -> tuple[Any, ...]:
    detail = {k: v for k, v in p.detail.items() if k not in VOLATILE_DETAIL}
    info = re.sub(r"\b(?:id|seq|xid)=\S+", "", p.info)
    return (p.protocol, p.src, p.dst, p.sport, p.dport, info, repr(sorted(detail.items(), key=str)))


def _few(items: list[str], n: int = 3) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


RADIUS_REQUESTS = {"Access-Request", "Accounting-Request", "CoA-Request", "Disconnect-Request"}
RADIUS_RESPONSES = {
    "Access-Accept",
    "Access-Reject",
    "Access-Challenge",
    "Accounting-Response",
    "CoA-ACK",
    "CoA-NAK",
    "Disconnect-ACK",
    "Disconnect-NAK",
}
IN_FLIGHT_SECONDS = 2.0  # a request this close to the end of the capture may still get its answer


def findings(packets: list[Packet], *, truncated: bool = False) -> list[str]:
    """Plain statements about exchanges in the capture that got no answer or failed: what a person
    reading the packet list would conclude first. Requests are matched to their own answers (DHCP
    per client, RADIUS by NAS port and identifier, TCP by connection, ping by id/seq); requests in
    the last IN_FLIGHT_SECONDS of the capture don't count as unanswered."""
    out: list[str] = []
    if not packets:
        return out
    cutoff = packets[-1].time - IN_FLIGHT_SECONDS
    settled = [p for p in packets if p.time <= cutoff]

    # DHCP, per client MAC
    offered = {p.detail.get("client_mac") for p in packets if p.detail.get("type") == "Offer"}
    acked = {p.detail.get("client_mac") for p in packets if p.detail.get("type") in ("ACK", "NAK")}
    discovers: Counter[str] = Counter()
    requests_dhcp: Counter[str] = Counter()
    for p in settled:
        if p.protocol != "DHCP":
            continue
        mac = str(p.detail.get("client_mac"))
        if p.detail.get("type") == "Discover" and p.detail.get("client_mac") not in offered:
            discovers[mac] += 1
        elif p.detail.get("type") == "Request" and p.detail.get("client_mac") not in acked:
            requests_dhcp[mac] += 1
    if discovers:
        out.append(
            "DHCP: Discover without any Offer from "
            + _few([f"{m} ({n}x)" for m, n in discovers.most_common()])
            + " - no DHCP server answered on this link (port not authorised yet, no server or relay on the "
            "VLAN, or the server is down)."
        )
    if requests_dhcp:
        out.append(
            f"DHCP: Request without ACK/NAK from {_few(list(requests_dhcp))} - the lease never completed."
        )
    naks = sum(1 for p in packets if p.protocol == "DHCP" and p.detail.get("type") == "NAK")
    if naks:
        out.append(f"DHCP: {naks} NAK - the server refused the requested address.")

    # ARP (probes from 0.0.0.0 are never answered: ignored)
    arp_req: Counter[str] = Counter()
    answered = {
        str(p.detail.get("sender_ip"))
        for p in packets
        if p.protocol == "ARP" and p.detail.get("op") == "reply"
    }
    for p in settled:
        d = p.detail
        if (
            p.protocol == "ARP"
            and d.get("op") == "request"
            and d.get("sender_ip") not in ("0.0.0.0", d.get("target_ip"))
        ):
            arp_req[str(d.get("target_ip"))] += 1
    silent = [f"{ip} ({n}x)" for ip, n in arp_req.most_common() if ip not in answered]
    if silent:
        out.append(f"ARP: no reply for {_few(silent)} - that address is down or not on this segment.")

    # ICMP echo by (requester, id, seq): broadcast pings may be answered by anyone
    replied = {
        (p.dst, p.detail.get("id"), p.detail.get("seq"))
        for p in packets
        if p.protocol == "ICMP" and p.detail.get("type") == 0
    }
    lost: Counter[tuple[str, str]] = Counter()
    unreachable: Counter[str] = Counter()
    for p in settled:
        if p.protocol != "ICMP":
            continue
        t = p.detail.get("type")
        if t == 8 and (p.src, p.detail.get("id"), p.detail.get("seq")) not in replied:
            lost[(p.src, p.dst)] += 1
        elif t in (3, 11):
            unreachable[f"{p.src} -> {p.dst}: {re.sub(r' id=.*', '', p.info)}"] += 1
    if lost:
        out.append(
            "ICMP: echo requests without a reply: "
            + _few([f"{a} -> {b} ({n}x)" for (a, b), n in lost.most_common()])
            + "."
        )
    if unreachable:
        out.append(f"ICMP: {_few([f'{k} ({n}x)' for k, n in unreachable.most_common()])}.")

    # TCP by connection (client address and port, server address and port)
    synack: set[tuple[Any, ...]] = set()
    rst: set[tuple[Any, ...]] = set()
    for p in packets:
        flags = p.detail.get("flags") if p.transport == "TCP" else None
        if flags and "SYN" in flags and "ACK" in flags:
            synack.add((p.dst, p.dport, p.src, p.sport))
        elif flags and "RST" in flags:
            rst.add((p.dst, p.dport, p.src, p.sport))
    refused: Counter[str] = Counter()
    no_answer: Counter[str] = Counter()
    for p in settled:
        flags = p.detail.get("flags") if p.transport == "TCP" else None
        if not flags or "SYN" not in flags or "ACK" in flags:
            continue
        conn = (p.src, p.sport, p.dst, p.dport)
        if conn in synack:
            continue
        (refused if conn in rst else no_answer)[f"{p.src} -> {p.dst}:{p.dport}"] += 1
    if refused:
        out.append(
            f"TCP: connection refused (RST) for {_few([f'{k} ({n}x)' for k, n in refused.most_common()])}."
        )
    if no_answer:
        out.append(
            f"TCP: SYN without SYN-ACK for {_few([f'{k} ({n}x)' for k, n in no_answer.most_common()])}"
            " - filtered, or nothing listens there."
        )

    # RADIUS: a response answers the request with the same NAS address/port and identifier
    responded = {
        (p.dst, p.dport, p.src, p.sport, p.detail.get("id"))
        for p in packets
        if p.protocol == "RADIUS" and p.detail.get("code") in RADIUS_RESPONSES
    }
    quiet: Counter[str] = Counter()
    for p in settled:
        request = p.protocol == "RADIUS" and p.detail.get("code") in RADIUS_REQUESTS
        if request and (p.src, p.sport, p.dst, p.dport, p.detail.get("id")) not in responded:
            quiet[f"{p.detail.get('code')} {p.src} -> {p.dst}"] += 1
    if quiet:
        out.append(
            f"RADIUS: requests without any response: {_few([f'{k} ({n}x)' for k, n in quiet.most_common()])}"
            " - the server is unreachable, doesn't know this NAS as a network device, or the shared "
            "secret is wrong (ISE drops those silently)."
        )
    rejects = sum(1 for p in packets if p.protocol == "RADIUS" and p.detail.get("code") == "Access-Reject")
    if rejects:
        out.append(f"RADIUS: {rejects} Access-Reject - the server refused the login (see its auth log).")

    # EAPOL
    eap_codes = Counter(
        str((p.detail.get("eap") or {}).get("code")) for p in packets if p.protocol == "EAPOL"
    )
    eapol_types = Counter(str(p.detail.get("type")) for p in packets if p.protocol == "EAPOL")
    if eap_codes.get("Failure"):
        out.append(f"EAPOL: {eap_codes['Failure']} EAP Failure - 802.1X authentication failed.")
    if eapol_types.get("Start") and not eap_codes.get("Request"):
        out.append(
            "EAPOL: the client sent EAPOL-Start but the switch never sent an EAP Request "
            "(802.1X off on the port?)."
        )
    if eap_codes.get("Request") and not eap_codes.get("Response"):
        out.append(
            "EAPOL: the switch sent EAP Requests but the client never answered - no 802.1X "
            "supplicant (the switch falls back to MAB if configured)."
        )
    out += overlay_findings(packets, settled)
    if out and truncated:
        out.append("Note: the capture was cut off (packet limit); answers after the cut-off are not seen.")
    return out


IKE_HINTS = {
    "NO_PROPOSAL_CHOSEN": "the proposals (encryption, integrity, PRF, DH group) don't match",
    "INVALID_KE_PAYLOAD": "DH group mismatch (the initiator retries with the other group)",
    "AUTHENTICATION_FAILED": "pre-shared key, certificate or identity mismatch",
    "TS_UNACCEPTABLE": "the protected networks (crypto ACL / traffic selectors) don't match",
}


def overlay_findings(packets: list[Packet], settled: list[Packet]) -> list[str]:
    """L70 findings: IKE that got no answer or an error, BGP sessions torn down by a NOTIFICATION,
    NetFlow data the collector can't decode yet, VXLAN without an SGT, BFD sessions down, DNS
    queries without an answer or with an error."""
    out: list[str] = []

    # IKEv2: an IKE_SA_INIT response carries the request's initiator SPI
    init_answered = {
        (p.dst, p.src, p.detail.get("spi_i"))
        for p in packets
        if p.protocol == "IKEv2"
        and p.detail.get("exchange") == "IKE_SA_INIT"
        and p.detail.get("message") == "response"
    }
    no_init: Counter[str] = Counter()
    for p in settled:
        d = p.detail
        if (
            p.protocol == "IKEv2"
            and d.get("exchange") == "IKE_SA_INIT"
            and d.get("message") == "request"
            and (p.src, p.dst, d.get("spi_i")) not in init_answered
        ):
            no_init[f"{p.src} -> {p.dst}"] += 1
    if no_init:
        out.append(
            "IKEv2: IKE_SA_INIT without response from "
            + _few([f"{k} ({n}x)" for k, n in no_init.most_common()])
            + " - the peer doesn't answer on UDP 500: unreachable, a firewall or ACL drops IKE, or the "
            "peer has no tunnel configured for this address."
        )
    ike_errors: Counter[str] = Counter()
    for p in packets:
        for err in p.detail.get("errors", []) if p.protocol in ("IKEv2", "IKEv1") else []:
            ike_errors[f"{err} {p.src} -> {p.dst}"] += 1
    if ike_errors:
        seen = {k.split(" ", 1)[0] for k in ike_errors}
        hints = [f"{name}: {h}" for name, h in IKE_HINTS.items() if name in seen]
        out.append(
            f"IKE: error notifications: {_few([f'{k} ({n}x)' for k, n in ike_errors.most_common()])}"
            + (f" - {'; '.join(hints)}." if hints else ".")
        )

    # BGP NOTIFICATIONs: the sender tears the session down and says why
    hold: Counter[str] = Counter()
    other: Counter[str] = Counter()
    for p in packets:
        for m in p.detail.get("bgp", []) if p.protocol == "BGP" else []:
            if m.get("type") != "NOTIFICATION":
                continue
            if m.get("code") == 4:
                hold[f"{p.src} -> {p.dst}"] += 1
            else:
                other[f"{m.get('error')} {p.src} -> {p.dst}"] += 1
    if hold:
        out.append(
            "BGP: NOTIFICATION hold timer expired from "
            + _few([f"{k} ({n}x)" for k, n in hold.most_common()])
            + " - the sender heard no KEEPALIVE or UPDATE within the hold time: loss on the path, an "
            "overloaded peer, or traffic getting through in one direction only."
        )
    if other:
        out.append(
            f"BGP: NOTIFICATION {_few([f'{k} ({n}x)' for k, n in other.most_common()])}"
            " - the session was closed; the error names why (e.g. Bad Peer AS: remote-as mismatch)."
        )

    # NetFlow / IPFIX data sets that arrived before any template for them
    early = netflow_exporters(packets)[1]
    if early:
        out.append(
            "NetFlow: data before template from "
            + _few([f"{a} source {sid} template {tid} ({n}x)" for (a, sid, tid), n in early.most_common()])
            + " - a collector can't decode those records until the exporter re-sends the template "
            "(template timeout / refresh rate on the exporter)."
        )

    # VXLAN without an SGT: no group-policy header, or group 0 (unknown)
    untagged: Counter[str] = Counter()
    for p in packets:
        if p.protocol != "VXLAN":
            continue
        vni, sgt = p.detail.get("vni"), p.detail.get("sgt")
        if sgt is None:
            untagged[f"VNI {vni} no group-policy header"] += 1
        elif sgt == 0:
            untagged[f"VNI {vni} SGT 0"] += 1
    if untagged:
        out.append(
            "VXLAN: packets without an SGT: "
            + _few([f"{k} ({n}x)" for k, n in untagged.most_common()])
            + " - the fabric edge didn't classify the source (no SGT from ISE or a static mapping), or "
            "this isn't a VXLAN-GPO fabric; group-based policy treats them as unknown."
        )

    # BFD: a session reported down with a diagnostic
    bfd_down = Counter(
        f"{p.src} -> {p.dst} {p.detail.get('state')} ({p.detail.get('diag')})"
        for p in packets
        if p.protocol == "BFD"
        and p.detail.get("state") in ("Down", "AdminDown")
        and p.detail.get("diag") not in (None, "none")
    )
    if bfd_down:
        out.append(
            f"BFD: sessions reported down: {_few([f'{k} ({n}x)' for k, n in bfd_down.most_common()])}"
            " - the diagnostic says why (Control Detection Time Expired: the peer's packets stopped coming)."
        )

    # DNS: a response carries the query's ID back to the client's address and port
    dns_answered = {
        (p.dst, p.dport, p.src, p.detail.get("id"))
        for p in packets
        if p.protocol == "DNS" and p.detail.get("message") == "response"
    }
    dns_quiet: Counter[str] = Counter()
    for p in settled:
        d = p.detail
        query = p.protocol == "DNS" and d.get("message") == "query"
        if query and (p.src, p.sport, p.dst, d.get("id")) not in dns_answered:
            dns_quiet[f"{_few(d.get('questions') or [], 1)} {p.src} -> {p.dst}"] += 1
    if dns_quiet:
        out.append(
            f"DNS: queries without a response: {_few([f'{k} ({n}x)' for k, n in dns_quiet.most_common()])}"
            " - the server is unreachable or doesn't answer this client."
        )
    dns_errors = Counter(
        f"{p.detail.get('rcode')} for {_few(p.detail.get('questions') or [], 1)}"
        for p in packets
        if p.protocol == "DNS" and p.detail.get("rcode") not in (None, "NOERROR")
    )
    if dns_errors:
        out.append(f"DNS: error answers: {_few([f'{k} ({n}x)' for k, n in dns_errors.most_common()])}.")
    return out
