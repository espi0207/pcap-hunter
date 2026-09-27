import struct

import pytest

from pcaphunter import craft
from pcaphunter.decode import (
    ACK,
    ETH_ARP,
    ETH_IPV4,
    LINK_ETHERNET,
    LINK_NULL,
    LINK_RAW,
    LINK_SLL,
    SYN,
    MalformedPacket,
    decode,
    parse_dns,
)

A, B = "3c:52:82:00:00:01", "3c:52:82:00:00:02"


def eth_tcp(flags=SYN, payload=b"", vlan=None):
    segment = craft.tcp("192.168.1.2", "10.0.0.1", 50000, 443, flags, payload)
    return craft.ethernet(A, B, ETH_IPV4, craft.ipv4("192.168.1.2", "10.0.0.1", 6, segment), vlan=vlan)


def test_ethernet_ipv4_tcp():
    p = decode(1.0, LINK_ETHERNET, eth_tcp(SYN, b""))
    assert (p.src_mac, p.dst_mac) == (A, B)
    assert (p.src, p.dst, p.proto, p.sport, p.dport) == ("192.168.1.2", "10.0.0.1", "TCP", 50000, 443)
    assert p.is_syn and not p.is_synack and p.ttl == 64


def test_vlan_tag_and_payload():
    p = decode(1.0, LINK_ETHERNET, eth_tcp(ACK | 0x08, b"hola", vlan=100))
    assert p.dport == 443 and p.payload == b"hola"


def test_ethernet_padding_is_not_payload():
    frame = eth_tcp(ACK, b"") + b"\0" * 6  # tramas cortas llevan relleno hasta 60 bytes
    assert decode(1.0, LINK_ETHERNET, frame).payload == b""


def test_udp_dns_query():
    query = craft.dns_query(0xBEEF, "www.Ejemplo.example", qtype=16)
    frame = craft.ethernet(
        A,
        B,
        ETH_IPV4,
        craft.ipv4("192.168.1.2", "192.168.1.1", 17, craft.udp("192.168.1.2", "192.168.1.1", 5555, 53, query)),
    )
    p = decode(1.0, LINK_ETHERNET, frame)
    assert p.proto == "UDP" and p.dns.qname == "www.ejemplo.example" and p.dns.qtype == "TXT"
    assert not p.dns.response


def test_dns_compression_pointer():
    dns = parse_dns(craft.dns_answer(1, "github.com", "198.51.100.1"))
    assert dns.response and dns.qname == "github.com"


def test_dns_pointer_loop_does_not_hang():
    # La pregunta es un puntero que apunta a sí mismo.
    msg = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\0\x01\0\x01"
    with pytest.raises(MalformedPacket):
        parse_dns(msg)


def test_arp():
    frame = craft.ethernet(A, "ff:ff:ff:ff:ff:ff", ETH_ARP, craft.arp(2, A, "192.168.1.1", B, "192.168.1.9"))
    p = decode(1.0, LINK_ETHERNET, frame)
    assert (p.arp.op, p.arp.sender_mac, p.arp.sender_ip, p.arp.target_ip) == (2, A, "192.168.1.1", "192.168.1.9")


def test_ipv6_with_extension_header():
    segment = struct.pack("!HHHH", 5353, 53, 8, 0)
    hop_by_hop = bytes([17, 0]) + b"\0" * 6  # siguiente cabecera: UDP
    packet = craft.ipv6("2001:db8::1", "2001:db8::2", 0, hop_by_hop + segment)
    p = decode(1.0, LINK_RAW, packet)
    assert (p.src, p.proto, p.sport, p.dport) == ("2001:db8::1", "UDP", 5353, 53)


def test_linux_cooked_capture():
    ip = craft.ipv4("10.0.0.1", "10.0.0.2", 1, craft.icmp_echo(1, 1))
    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\0" * 8, ETH_IPV4)
    p = decode(1.0, LINK_SLL, sll + ip)
    assert p.proto == "ICMP" and p.icmp_type == 8


@pytest.mark.parametrize("family", [struct.pack("<I", 2), struct.pack(">I", 2)])
def test_bsd_loopback_either_byte_order(family):
    ip = craft.ipv4("127.0.0.1", "127.0.0.1", 17, craft.udp("127.0.0.1", "127.0.0.1", 1, 2, b"x"))
    assert decode(1.0, LINK_NULL, family + ip).proto == "UDP"


@pytest.mark.parametrize(
    "data",
    [b"", b"\x00" * 13, eth_tcp()[:30], craft.ethernet(A, B, ETH_IPV4, b"\x45" + b"\0" * 5)],
)
def test_truncated_packets_raise_malformed(data):
    with pytest.raises(MalformedPacket):
        decode(1.0, LINK_ETHERNET, data)


def test_checksums_are_valid():
    # El checksum de una cabecera IPv4 correcta, sumado otra vez, da 0.
    packet = craft.ipv4("192.168.1.2", "10.0.0.1", 6, b"")
    assert craft.checksum(packet[:20]) == 0
