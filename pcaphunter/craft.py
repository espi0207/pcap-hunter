"""Construir paquetes byte a byte, para la captura de ejemplo y para las pruebas.

Es lo contrario de decode.py. Los checksums de IP, TCP y UDP se calculan de verdad
(RFC 1071), así que la captura de ejemplo se abre en Wireshark sin errores.
"""

from __future__ import annotations

import ipaddress
import struct

from .decode import ACK, ETH_ARP, ETH_IPV4, ETH_VLAN, PROTO_ICMP, PROTO_TCP, PROTO_UDP, SYN

BROADCAST = "ff:ff:ff:ff:ff:ff"


def mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def checksum(data: bytes) -> int:
    """Suma en complemento a uno de palabras de 16 bits (RFC 1071)."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(src_mac: str, dst_mac: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", ETH_VLAN, vlan) if vlan is not None else b""
    return mac(dst_mac) + mac(src_mac) + tag + struct.pack("!H", ethertype) + payload


def arp(op: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return (
        struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, op)
        + mac(sender_mac)
        + ipaddress.IPv4Address(sender_ip).packed
        + mac(target_mac)
        + ipaddress.IPv4Address(target_ip).packed
    )


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0x4000,  # "no fragmentar"
        ttl,
        proto,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    return (
        struct.pack("!IHBB", 6 << 28, len(payload), next_header, hop_limit)
        + ipaddress.IPv6Address(src).packed
        + ipaddress.IPv6Address(dst).packed
        + payload
    )


def _pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    return ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!BBH", 0, proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, flags: int, payload: bytes = b"", seq=0, ack=0) -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    csum = checksum(_pseudo_header(src, dst, PROTO_TCP, len(header) + len(payload)) + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = checksum(_pseudo_header(src, dst, PROTO_UDP, len(header) + len(payload)) + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


def icmp_echo(ident: int, seq: int, reply: bool = False, payload: bytes = b"abcdefghijklmnop") -> bytes:
    header = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq)
    csum = checksum(header + payload)
    return header[:2] + struct.pack("!H", csum) + header[4:] + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def dns_query(ident: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_answer(ident: int, name: str, address: str, qtype: int = 1) -> bytes:
    """Respuesta con un registro A. El nombre de la respuesta es un puntero a la pregunta (0xC00C)."""
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + ipaddress.IPv4Address(address).packed
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + answer


class Lan:
    """Una red de mentira: sabe la MAC de cada IP y monta tramas Ethernet completas."""

    def __init__(self, macs: dict[str, str], gateway_mac: str) -> None:
        self.macs = macs
        self.gateway_mac = gateway_mac  # lo que está fuera de la red sale por el router

    def mac_of(self, ip: str) -> str:
        return self.macs.get(ip, self.gateway_mac)

    def ip_frame(self, src: str, dst: str, proto: int, segment: bytes, src_mac: str | None = None) -> bytes:
        return ethernet(src_mac or self.mac_of(src), self.mac_of(dst), ETH_IPV4, ipv4(src, dst, proto, segment))

    def tcp(self, src, dst, sport, dport, flags, payload=b"", seq=0, ack=0) -> bytes:
        return self.ip_frame(src, dst, PROTO_TCP, tcp(src, dst, sport, dport, flags, payload, seq, ack))

    def udp(self, src, dst, sport, dport, payload) -> bytes:
        return self.ip_frame(src, dst, PROTO_UDP, udp(src, dst, sport, dport, payload))

    def ping(self, src, dst, seq, reply=False) -> bytes:
        return self.ip_frame(src, dst, PROTO_ICMP, icmp_echo(0x1234, seq, reply))

    def arp_reply(self, sender_mac: str, sender_ip: str, target_ip: str, target_mac: str | None = None) -> bytes:
        target_mac = target_mac or self.mac_of(target_ip)
        return ethernet(sender_mac, target_mac, ETH_ARP, arp(2, sender_mac, sender_ip, target_mac, target_ip))

    def handshake(self, t: float, client, server, cport, sport, data: bytes = b"", reply: bytes = b""):
        """Una conexión TCP completa: SYN, SYN-ACK, ACK, datos, respuesta y cierre."""
        frames = [
            (t, self.tcp(client, server, cport, sport, SYN, seq=1000)),
            (t + 0.020, self.tcp(server, client, sport, cport, SYN | ACK, seq=5000, ack=1001)),
            (t + 0.021, self.tcp(client, server, cport, sport, ACK, seq=1001, ack=5001)),
        ]
        if data:
            frames.append((t + 0.022, self.tcp(client, server, cport, sport, ACK | 0x08, data, 1001, 5001)))
        if reply:
            frames.append(
                (t + 0.060, self.tcp(server, client, sport, cport, ACK | 0x08, reply, 5001, 1001 + len(data)))
            )
        frames.append((t + 0.100, self.tcp(client, server, cport, sport, ACK | 0x01, seq=1001 + len(data))))
        return frames
