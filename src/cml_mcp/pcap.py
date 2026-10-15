"""A small pcap reader and protocol decoder for CML link captures (no third-party dependencies).

CML serves a capture as a classic libpcap file (`GET /pcap/{link_id}`), Ethernet link type. This
module decodes what lab tests need to prove: ARP, IPv4 with ICMP/TCP/UDP, OSPF, DHCP, RADIUS
(including CoA and the EAP inside it) and EAPOL. Secrets never leave it: RADIUS passwords, State,
Class, Message-Authenticator and similar attributes are dropped, and AV-pairs that look like
secrets are masked.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from collections import Counter
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


def decode_ethernet(pkt: Packet, frame: bytes) -> None:
    pkt.dst, pkt.src = mac(frame[0:6]), mac(frame[6:12])
    etype = struct.unpack("!H", frame[12:14])[0]
    payload = frame[14:]
    while etype in (0x8100, 0x88A8):  # 802.1Q / QinQ
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
    23: "Telnet",
    49: "TACACS+",
    80: "HTTP",
    443: "HTTPS",
    830: "NETCONF",
    8305: "sftunnel",
}
UDP_PORTS = {53: "DNS", 123: "NTP", 161: "SNMP", 162: "SNMP-trap", 514: "Syslog", 69: "TFTP"}
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
        if t in (0, 8) and len(body) >= 8:
            ident, seq = struct.unpack("!HH", body[4:8])
            pkt.info += f" id={ident} seq={seq}"
        pkt.detail = {"type": t, "code": c}
    elif proto == 6:
        decode_tcp(pkt, body)
    elif proto == 17:
        decode_udp(pkt, body)
    elif proto == 89:
        decode_ospf(pkt, body)
    elif proto == 112:
        pkt.protocol, pkt.info = "VRRP", "VRRP advertisement"
    elif proto == 50:
        pkt.protocol, pkt.info = "ESP", "IPsec ESP"
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


def decode_udp(pkt: Packet, b: bytes) -> None:
    pkt.transport = "UDP"
    pkt.sport, pkt.dport = struct.unpack("!HH", b[0:4])
    payload = b[8:]
    ports = {pkt.sport, pkt.dport}
    if ports & {67, 68}:
        decode_dhcp(pkt, payload)
    elif ports & RADIUS_PORTS:
        decode_radius(pkt, payload)
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
    if protocol and protocol.lower() not in (pkt.protocol.lower(), pkt.transport.lower()):
        return False
    return not (port is not None and port not in (pkt.sport, pkt.dport))


HIGHLIGHT = ("RADIUS", "EAPOL", "OSPF", "DHCP", "ARP", "ICMP", "sftunnel", "TACACS+")


def summarise(packets: list[Packet], *, highlights: int = 20, conversations: int = 10) -> dict[str, Any]:
    """Protocol mix, top conversations and decoded highlights of the interesting protocols."""
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
    for p in packets if highlights else []:
        if p.protocol in HIGHLIGHT and len(hl.setdefault(p.protocol, [])) < highlights:
            hl[p.protocol].append(p.row())
    if hl:
        out["highlights"] = hl
    radius = Counter(p.detail.get("code") for p in packets if p.protocol == "RADIUS")
    if radius:
        out["radius"] = dict(radius)
    eapol = Counter(p.info for p in packets if p.protocol == "EAPOL")
    if eapol:
        out["eapol"] = dict(eapol.most_common(10))
    return out
