"""Decodificación de paquetes, capa a capa, sin scapy ni dpkt.

Enlace (Ethernet, VLAN, Linux cooked, IP en bruto) -> red (ARP, IPv4, IPv6) ->
transporte (TCP, UDP, ICMP) -> y DNS por encima de UDP. Todo con struct y leyendo los
campos a mano según su RFC. Un paquete mal formado lanza MalformedPacket: en una
captura de un ataque puede haber de todo y el programa no debe caerse por ello.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

# Tipos de enlace (LINKTYPE_* de tcpdump.org)
LINK_NULL, LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_IPV4, LINK_IPV6, LINK_SLL2 = 0, 1, 101, 113, 228, 229, 276

ETH_IPV4, ETH_IPV6, ETH_ARP, ETH_VLAN, ETH_QINQ = 0x0800, 0x86DD, 0x0806, 0x8100, 0x88A8
PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMPV6 = 1, 6, 17, 58
IPV6_EXTENSIONS = {0, 43, 44, 60}  # hop-by-hop, routing, fragmento, opciones de destino

# Flags TCP
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}


class MalformedPacket(Exception):
    pass


@dataclass(slots=True)
class Arp:
    op: int  # 1 = petición ("¿quién tiene X?"), 2 = respuesta ("X está en esta MAC")
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


@dataclass(slots=True)
class Dns:
    id: int
    response: bool
    rcode: int
    qname: str
    qtype: str


@dataclass(slots=True)
class Packet:
    ts: float
    length: int
    src_mac: str | None = None
    dst_mac: str | None = None
    arp: Arp | None = None
    src: str | None = None  # IP
    dst: str | None = None
    proto: str | None = None  # "TCP", "UDP", "ICMP", "ICMPv6" u otro número
    ttl: int | None = None
    sport: int | None = None
    dport: int | None = None
    flags: int = 0  # flags TCP
    icmp_type: int | None = None
    payload: bytes = b""
    dns: Dns | None = None

    @property
    def is_syn(self) -> bool:
        """Primer paquete de una conexión TCP: SYN sin ACK."""
        return self.proto == "TCP" and self.flags & SYN != 0 and self.flags & ACK == 0

    @property
    def is_synack(self) -> bool:
        return self.proto == "TCP" and self.flags & SYN != 0 and self.flags & ACK != 0


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _need(data: bytes, n: int, what: str) -> None:
    if len(data) < n:
        raise MalformedPacket(f"{what}: faltan bytes ({len(data)} de {n})")


def decode(ts: float, linktype: int, data: bytes, orig_len: int | None = None) -> Packet:
    pkt = Packet(ts=ts, length=orig_len or len(data))
    if linktype == LINK_ETHERNET:
        _need(data, 14, "Ethernet")
        pkt.dst_mac, pkt.src_mac = _mac(data[0:6]), _mac(data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in (ETH_VLAN, ETH_QINQ):  # etiquetas 802.1Q (puede haber dos)
            _need(data, offset + 4, "VLAN")
            ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
        _network(pkt, ethertype, data[offset:])
    elif linktype == LINK_SLL:  # "any" en Linux: cabecera de 16 bytes en vez de Ethernet
        _need(data, 16, "Linux SLL")
        _network(pkt, struct.unpack("!H", data[14:16])[0], data[16:])
    elif linktype == LINK_SLL2:
        _need(data, 20, "Linux SLL2")
        _network(pkt, struct.unpack("!H", data[0:2])[0], data[20:])
    elif linktype in (LINK_RAW, LINK_IPV4, LINK_IPV6):
        _need(data, 1, "IP")
        _network(pkt, ETH_IPV6 if data[0] >> 4 == 6 else ETH_IPV4, data)
    elif linktype == LINK_NULL:  # loopback de BSD/macOS: 4 bytes con la familia del protocolo
        _need(data, 4, "loopback")
        # Va en el orden de bytes de la máquina que capturó: el que dé un número pequeño.
        little, big = struct.unpack("<I", data[:4])[0], struct.unpack(">I", data[:4])[0]
        family = little if little < 256 else big
        _network(pkt, ETH_IPV4 if family == 2 else ETH_IPV6, data[4:])
    else:
        raise MalformedPacket(f"tipo de enlace no soportado: {linktype}")
    return pkt


def _network(pkt: Packet, ethertype: int, data: bytes) -> None:
    if ethertype == ETH_ARP:
        _need(data, 28, "ARP")
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
        if htype == 1 and ptype == ETH_IPV4 and hlen == 6 and plen == 4:
            pkt.arp = Arp(
                op,
                _mac(data[8:14]),
                str(ipaddress.IPv4Address(data[14:18])),
                _mac(data[18:24]),
                str(ipaddress.IPv4Address(data[24:28])),
            )
    elif ethertype == ETH_IPV4:
        _need(data, 20, "IPv4")
        ihl = (data[0] & 0x0F) * 4
        total = struct.unpack("!H", data[2:4])[0]
        if ihl < 20 or total < ihl:
            raise MalformedPacket("cabecera IPv4 incoherente")
        frag = struct.unpack("!H", data[6:8])[0] & 0x1FFF
        pkt.ttl, proto = data[8], data[9]
        pkt.src, pkt.dst = str(ipaddress.IPv4Address(data[12:16])), str(ipaddress.IPv4Address(data[16:20]))
        # Si el paquete viene con relleno de Ethernet, total dice dónde acaba de verdad.
        body = data[ihl:total] if total <= len(data) else data[ihl:]
        if frag == 0:  # los fragmentos que no son el primero no llevan cabecera de transporte
            _transport(pkt, proto, body)
        else:
            pkt.proto = "fragmento"
    elif ethertype == ETH_IPV6:
        _need(data, 40, "IPv6")
        payload_len, next_header, pkt.ttl = struct.unpack("!HBB", data[4:8])
        pkt.src, pkt.dst = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
        body = data[40 : 40 + payload_len]
        hops = 0
        while next_header in IPV6_EXTENSIONS and hops < 8:
            _need(body, 8, "extensión IPv6")
            if next_header == 44 and struct.unpack("!H", body[2:4])[0] & 0xFFF8:
                pkt.proto = "fragmento"  # fragmento que no es el primero
                return
            length = 8 if next_header == 44 else (body[1] + 1) * 8
            next_header, body = body[0], body[length:]
            hops += 1
        _transport(pkt, next_header, body)


def _transport(pkt: Packet, proto: int, data: bytes) -> None:
    if proto == PROTO_TCP:
        _need(data, 20, "TCP")
        pkt.proto = "TCP"
        pkt.sport, pkt.dport = struct.unpack("!HH", data[:4])
        offset = (data[12] >> 4) * 4
        if offset < 20:
            raise MalformedPacket("cabecera TCP incoherente")
        pkt.flags = data[13]
        pkt.payload = data[offset:]
    elif proto == PROTO_UDP:
        _need(data, 8, "UDP")
        pkt.proto = "UDP"
        pkt.sport, pkt.dport = struct.unpack("!HH", data[:4])
        pkt.payload = data[8:]
        if 53 in (pkt.sport, pkt.dport):
            try:
                pkt.dns = parse_dns(pkt.payload)
            except MalformedPacket:
                pass  # por el 53 también pasa tráfico que no es DNS (o que es un DNS roto a propósito)
    elif proto in (PROTO_ICMP, PROTO_ICMPV6):
        _need(data, 4, "ICMP")
        pkt.proto = "ICMP" if proto == PROTO_ICMP else "ICMPv6"
        pkt.icmp_type = data[0]
        pkt.payload = data[8:]
    else:
        pkt.proto = str(proto)


def _read_name(msg: bytes, pos: int) -> tuple[str, int]:
    """Lee un nombre DNS, con la compresión de punteros del RFC 1035 (sección 4.1.4).

    Devuelve el nombre y dónde sigue el mensaje. Un paquete malicioso puede tener
    punteros que apuntan en bucle, así que se limita el número de saltos.
    """
    labels: list[str] = []
    end = None
    for _ in range(128):
        _need(msg, pos + 1, "nombre DNS")
        length = msg[pos]
        if length == 0:
            return ".".join(labels), end if end is not None else pos + 1
        if length & 0xC0 == 0xC0:  # puntero: los 14 bits siguientes son la posición
            _need(msg, pos + 2, "puntero DNS")
            if end is None:
                end = pos + 2
            pos = struct.unpack("!H", msg[pos : pos + 2])[0] & 0x3FFF
            continue
        if length > 63:
            raise MalformedPacket("etiqueta DNS de más de 63 bytes")
        _need(msg, pos + 1 + length, "etiqueta DNS")
        labels.append(msg[pos + 1 : pos + 1 + length].decode("ascii", errors="replace"))
        pos += 1 + length
    raise MalformedPacket("nombre DNS con demasiados saltos (¿punteros en bucle?)")


def parse_dns(msg: bytes) -> Dns:
    _need(msg, 12, "DNS")
    ident, flags, qdcount = struct.unpack("!HHH", msg[:6])
    if qdcount == 0:
        raise MalformedPacket("DNS sin pregunta")
    name, pos = _read_name(msg, 12)
    _need(msg, pos + 4, "pregunta DNS")
    qtype = struct.unpack("!H", msg[pos : pos + 2])[0]
    return Dns(ident, bool(flags & 0x8000), flags & 0x000F, name.lower(), DNS_TYPES.get(qtype, str(qtype)))
