"""L31 capture findings and grouped highlights; L32 route legend and short recipe rows."""

from typing import Any

from cml_mcp.console import strip_route_legend
from cml_mcp.pcap import Packet, findings, summarise


def pkt(no: int, protocol: str, src: str, dst: str, info: str = "", **kw: Any) -> Packet:
    detail = kw.pop("detail", {})
    return Packet(
        no=no, time=float(no), length=100, src=src, dst=dst, protocol=protocol, info=info, detail=detail, **kw
    )


def discover(no: int, xid: str) -> Packet:
    return pkt(
        no,
        "DHCP",
        "0.0.0.0",
        "255.255.255.255",
        f"DHCP Discover xid={xid} client aa",
        detail={"type": "Discover", "xid": xid, "client_mac": "aa"},
        sport=68,
        dport=67,
    )


def end(no: int = 100) -> Packet:
    """A late packet: requests before it are no longer in flight."""
    return pkt(no, "ETH", "x", "y")


def test_repeated_packets_are_grouped_and_dhcp_without_offer_is_a_finding() -> None:
    packets = [discover(i, f"0x{i // 3:08x}") for i in range(1, 14)] + [end()]
    out = summarise(packets)
    rows = out["highlights"]["DHCP"]
    assert len(rows) == 1 and rows[0]["count"] == 13 and rows[0]["last_time"] == 13.0
    assert out["findings"][0].startswith("DHCP: Discover without any Offer from aa (13x)")
    offer = pkt(20, "DHCP", "10.0.0.1", "10.0.0.9", "Offer", detail={"type": "Offer", "client_mac": "aa"})
    assert not [f for f in findings([*packets, offer]) if "Offer" in f]
    other = pkt(21, "DHCP", "10.0.0.1", "10.0.0.9", "Offer", detail={"type": "Offer", "client_mac": "bb"})
    assert [f for f in findings([*packets, other]) if "without any Offer from aa" in f]  # per client


def tcp(no: int, src: str, sport: int, dst: str, dport: int, *flags: str) -> Packet:
    return pkt(no, "TCP", src, dst, transport="TCP", sport=sport, dport=dport, detail={"flags": list(flags)})


def radius(no: int, src: str, sport: int, dst: str, dport: int, code: str, ident: int) -> Packet:
    return pkt(no, "RADIUS", src, dst, sport=sport, dport=dport, detail={"code": code, "id": ident})


def echo(no: int, src: str, dst: str, typ: int, seq: int) -> Packet:
    return pkt(no, "ICMP", src, dst, detail={"type": typ, "code": 0, "id": 7, "seq": seq})


def test_unanswered_exchanges_are_matched_per_exchange() -> None:
    packets = [
        pkt(1, "ARP", "a", "b", detail={"op": "request", "sender_ip": "10.0.0.1", "target_ip": "10.0.0.2"}),
        pkt(2, "ARP", "a", "b", detail={"op": "request", "sender_ip": "10.0.0.1", "target_ip": "10.0.0.3"}),
        pkt(3, "ARP", "c", "a", detail={"op": "reply", "sender_ip": "10.0.0.3", "target_ip": "10.0.0.1"}),
        pkt(4, "ARP", "d", "b", detail={"op": "request", "sender_ip": "0.0.0.0", "target_ip": "10.0.0.8"}),
        echo(5, "10.0.0.1", "10.0.0.9", 8, 1),
        echo(6, "10.0.0.1", "10.0.0.3", 8, 2),
        echo(7, "10.0.0.3", "10.0.0.1", 0, 2),
        tcp(8, "10.0.0.1", 40000, "10.0.0.5", 22, "SYN"),
        tcp(9, "10.0.0.1", 40001, "10.0.0.6", 443, "SYN"),
        tcp(10, "10.0.0.6", 443, "10.0.0.1", 40001, "ACK", "RST"),
        tcp(11, "10.0.0.1", 40002, "10.0.0.6", 22, "SYN"),
        tcp(12, "10.0.0.6", 22, "10.0.0.1", 40002, "SYN", "ACK"),
        radius(13, "10.0.0.1", 1645, "10.0.0.7", 1812, "Access-Request", 1),
        radius(14, "10.0.0.7", 1812, "10.0.0.1", 1645, "Access-Accept", 1),
        radius(15, "10.0.0.1", 1646, "10.0.0.7", 1813, "Accounting-Request", 2),
        pkt(16, "EAPOL", "aa", "bb", detail={"type": "EAP", "eap": {"code": "Request", "type": "Identity"}}),
        tcp(17, "10.0.0.1", 40009, "10.0.0.5", 80, "SYN"),  # at the very end: still in flight
        end(18),
    ]
    text = "\n".join(findings(packets))
    assert "ARP: no reply for 10.0.0.2 (1x)" in text and "10.0.0.8" not in text
    assert "10.0.0.1 -> 10.0.0.9 (1x)" in text and "10.0.0.1 -> 10.0.0.3" not in text
    assert "SYN without SYN-ACK for 10.0.0.1 -> 10.0.0.5:22 (1x)" in text and ":80" not in text
    assert (
        "connection refused (RST) for 10.0.0.1 -> 10.0.0.6:443" in text
        and ":22 -" not in text.split("RST")[1][:30]
    )
    assert "Accounting-Request 10.0.0.1 -> 10.0.0.7 (1x)" in text and "Access-Request 10.0.0.1" not in text
    assert "never answered - no 802.1X" in text


def test_a_clean_capture_has_no_findings() -> None:
    packets = [
        radius(1, "nas", 1645, "ise", 1812, "Access-Request", 1),
        radius(2, "ise", 1812, "nas", 1645, "Access-Accept", 1),
        end(),
    ]
    assert findings(packets) == [] and "findings" not in summarise(packets)


def test_findings_use_the_whole_capture_and_flag_truncation() -> None:
    req, ans = echo(1, "10.0.0.1", "10.0.0.2", 8, 1), echo(2, "10.0.0.2", "10.0.0.1", 0, 1)
    filtered = summarise([req], whole=[req, ans, end()])
    assert "findings" not in filtered  # the reply is outside the display filter, not missing
    cut = findings([req, end()], truncated=True)
    assert cut[-1].startswith("Note: the capture was cut off")


def test_route_legend_is_stripped() -> None:
    text = (
        "Codes: L - local, C - connected, S - static\n       D - EIGRP, EX - EIGRP external\n\n"
        "Gateway of last resort is not set\n\nO   10.0.23.0/24 [110/20] via 10.0.12.2"
    )
    assert (
        strip_route_legend(text)
        == "Gateway of last resort is not set\n\nO   10.0.23.0/24 [110/20] via 10.0.12.2"
    )
    assert strip_route_legend("Codes are fine here") == "Codes are fine here"
