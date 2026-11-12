"""Repaso del 10 de noviembre: falsos positivos con tráfico normal y ataques que se escapaban."""

import json
import struct

from pcaphunter.craft import Lan, ipv4, ipv6
from pcaphunter.craft import tcp as tcp_segment
from pcaphunter.creds import CredentialSniffer
from pcaphunter.decode import ACK, PROTO_TCP, RST, SYN, Dns, Packet, decode
from pcaphunter.detectors import Severity, run_detectors
from pcaphunter.pcapfile import read_capture

PC, SERVER = "192.168.1.23", "192.168.1.10"
FIN, PSH, URG = 0x01, 0x08, 0x20


def tcp(ts, src, dst, sport, dport, flags, payload=b""):
    return Packet(
        ts=ts, length=60, src=src, dst=dst, proto="TCP", sport=sport, dport=dport, flags=flags, payload=payload
    )


def rules(packets):
    return sorted(f.rule for f in run_detectors(sorted(packets, key=lambda p: p.ts)))


def conversation(ts, client, server, sport, dport, data=b"\x16\x03\x01hola"):
    return [
        tcp(ts, client, server, sport, dport, SYN),
        tcp(ts + 0.02, server, client, dport, sport, SYN | ACK),
        tcp(ts + 0.021, client, server, sport, dport, ACK),
        tcp(ts + 0.022, client, server, sport, dport, ACK | PSH, data),
    ]


# Barrido de la red


def test_browsing_many_https_sites_is_not_a_network_sweep():
    # Abrir una web moderna: 25 servidores distintos por el 443 en pocos segundos, y todos contestan.
    packets = []
    for i in range(25):
        packets += conversation(i * 0.3, PC, f"203.0.113.{i + 1}", 50000 + i, 443)
    assert rules(packets) == []


def test_sweep_where_a_few_hosts_answer_is_still_reported():
    packets = [tcp(i * 0.1, PC, f"192.168.1.{i}", 45000 + i, 445, SYN) for i in range(2, 40)]
    for i in (5, 9):  # dos equipos tienen el 445 abierto; el escáner corta con RST
        packets.append(tcp(i * 0.1 + 0.001, f"192.168.1.{i}", PC, 445, 45000 + i, SYN | ACK))
        packets.append(tcp(i * 0.1 + 0.002, PC, f"192.168.1.{i}", 45000 + i, 445, RST))
    [finding] = run_detectors(sorted(packets, key=lambda p: p.ts))
    assert finding.rule == "network_sweep" and "2 lo tienen abierto" in finding.details


# Escaneos sigilosos: sin SYN


def stealth_scan(flags):
    return [tcp(i * 0.05, PC, SERVER, 40000, port, flags) for i, port in enumerate(range(1, 41))]


def test_null_fin_and_xmas_scans_are_port_scans():
    for flags, name in ((0, "NULL"), (FIN, "FIN"), (FIN | PSH | URG, "Xmas")):
        [finding] = run_detectors(stealth_scan(flags))
        assert finding.rule == "stealth_scan" and finding.src == PC and finding.dst == SERVER
        assert name in finding.details


def test_closing_normal_connections_is_not_a_stealth_scan():
    # Un FIN con ACK es el cierre normal de una conexión, aunque haya muchas.
    packets = [tcp(i * 0.05, PC, SERVER, 40000 + i, 8000 + i, FIN | ACK) for i in range(40)]
    assert rules(packets) == []


# Túnel ICMP


def ping(ts, src, dst, payload, reply=False):
    return Packet(ts=ts, length=len(payload) + 42, src=src, dst=dst, proto="ICMP", icmp_type=0 if reply else 8,
                  payload=payload)  # fmt: skip


def test_big_linux_pings_are_not_an_icmp_tunnel():
    # "ping -s 1000" en Linux y macOS: los 16 primeros bytes son la hora (cambian) y el resto, relleno fijo.
    filler = bytes(i % 256 for i in range(16, 1000))
    packets = []
    for i in range(30):
        stamp = struct.pack("<QQ", 1_700_000_000 + i, 123456 + i * 7)
        packets.append(ping(i, PC, SERVER, stamp + filler))
        packets.append(ping(i + 0.001, SERVER, PC, stamp + filler, reply=True))
    assert rules(packets) == []


# Túnel DNS


def query(ts, name, src=PC):
    return Packet(ts=ts, length=80, src=src, dst="192.168.1.1", proto="UDP", sport=53000, dport=53,
                  dns=Dns(id=1, response=False, rcode=0, qname=name, qtype="A"))  # fmt: skip


def test_many_ordinary_subdomains_are_not_a_dns_tunnel():
    hosts = (
        "www mail drive docs calendar accounts play maps news photos translate meet chat fonts apis "
        "clients1 clients2 ssl lh3 encrypted-tbn0 ogs contacts keep myaccount support store classroom"
    ).split()
    assert rules([query(i, f"{h}.google.com") for i, h in enumerate(hosts)]) == []


def test_cdn_hostnames_are_not_a_dns_tunnel():
    # Ver vídeos: muchos nombres de servidor con pinta rara, pero cortos y con guiones.
    names = [f"rr{i % 6 + 1}---sn-h5q7dn{chr(97 + i)}{i % 10}.googlevideo.com" for i in range(24)]
    assert rules([query(i, n) for i, n in enumerate(names)]) == []


def test_short_hex_chunks_are_still_a_dns_tunnel():
    # Sacar datos en trozos de 16 caracteres hexadecimales: cortos, pero sin una sola palabra.
    names = [f"{(i * 0x9E3779B97F4A7C15) % 2**64:016x}.t.evil-cdn.net" for i in range(40)]
    [finding] = run_detectors([query(i, n) for i, n in enumerate(names)])
    assert finding.rule == "dns_tunnel"


# DGA


def nxdomain(ts, name, client=PC):
    return Packet(ts=ts, length=80, src="192.168.1.1", dst=client, proto="UDP", sport=53, dport=53000,
                  dns=Dns(id=1, response=True, rcode=3, qname=name, qtype="A"))  # fmt: skip


def test_local_names_that_do_not_exist_are_not_a_dga():
    # Nombres de la red de casa o del trabajo que el DNS no conoce: impresoras, equipos, wpad...
    names = [
        f"{h}.{zone}" for zone in ("lan", "local", "home.arpa") for h in ("wpad", "nas", "impresora", "tele", "pc")
    ]
    assert rules([nxdomain(i, n) for i, n in enumerate(names)]) == []


def test_readable_blocked_domains_are_a_lower_priority_than_random_ones():
    readable = "doubleclick googlesyndication adservice scorecardresearch taboola outbrain criteo adnxs moatads hotjar"
    [finding] = run_detectors(
        [nxdomain(i, f"{name}.com") for i, name in enumerate(readable.split() + ["rubicon", "pubmatic"])]
    )
    assert finding.rule == "dga" and finding.severity == Severity.LOW

    random_names = ["xkqzvbnwpl", "qwrtzpsdfg", "mnbvcxzlkj", "ploikmjnhb", "zxcvbnmqwr", "trwqplmkjh",
                    "bvcxzasdfg", "hjklpoiuyt", "wqsdcvfrtg", "nhytgbvfrd", "kjhgfdsapz", "yhnbgtrfvc"]  # fmt: skip
    [finding] = run_detectors([nxdomain(i, f"{name}.biz") for i, name in enumerate(random_names)])
    assert finding.severity == Severity.HIGH


# Beaconing


def test_beacon_with_one_long_gap_is_still_detected():
    # Llama cada 60 s, pero el portátil estuvo dormido 20 minutos a mitad.
    times = [i * 60.0 for i in range(15)] + [15 * 60 + 1200 + i * 60.0 for i in range(15)]
    packets = [tcp(t, PC, "198.51.100.7", 40000 + i, 443, SYN) for i, t in enumerate(times)]
    assert rules(packets) == ["beaconing"]


# Lector y decodificador


def test_pcapng_with_a_huge_non_packet_block_is_read(tmp_path):
    # Wireshark guarda las claves TLS (bloque de secretos) dentro del pcapng, y pueden ocupar mucho.
    lan = Lan({PC: "aa:aa:aa:aa:aa:23", SERVER: "aa:aa:aa:aa:aa:10"}, "aa:aa:aa:aa:aa:01")
    frame = lan.tcp(PC, SERVER, 40000, 80, SYN)

    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", kind, len(body) + 12) + body + struct.pack("<I", len(body) + 12)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    secrets = block(0x0000000A, struct.pack("<II", 0x544C534B, 400_000) + b"k" * 400_000)
    epb = block(6, struct.pack("<IIIII", 0, 0, 1_000_000, len(frame), len(frame)) + frame)
    path = tmp_path / "con-claves.pcapng"
    path.write_bytes(shb + idb + secrets + epb)
    assert len(list(read_capture(path))) == 1


def test_ipv4_packet_with_total_length_zero_is_decoded():
    # Captura hecha en el propio equipo con TSO: la tarjeta parte el paquete después y el campo va a 0.
    segment = tcp_segment(PC, SERVER, 40000, 80, ACK | PSH, b"GET / HTTP/1.1\r\n\r\n")
    packet = bytearray(ipv4(PC, SERVER, PROTO_TCP, segment))
    packet[2:4] = b"\0\0"
    decoded = decode(0.0, 101, bytes(packet))
    assert decoded.proto == "TCP" and decoded.payload.startswith(b"GET /")


# Credenciales


def http(dport, text):
    return Packet(ts=0, length=len(text), src=PC, dst=SERVER, proto="TCP", sport=40000, dport=dport,
                  flags=ACK | PSH, payload=text.encode())  # fmt: skip


def test_proxy_authorization_is_a_cleartext_credential():
    [cred] = CredentialSniffer().feed(
        http(3128, "GET http://ejemplo.test/ HTTP/1.1\r\nProxy-Authorization: Basic YW5hOnNlY3JldG8=\r\n\r\n")
    )
    assert (cred.user, cred.secret) == ("ana", "secreto") and "proxy" in cred.protocol.lower()


def test_json_login_is_a_cleartext_credential():
    body = json.dumps({"email": "ana@ejemplo.test", "password": "Tr0ub4dor&3"})
    [cred] = CredentialSniffer().feed(
        http(80, f"POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{body}")
    )
    assert (cred.user, cred.secret) == ("ana@ejemplo.test", "Tr0ub4dor&3")


def test_form_fields_with_prefixes_are_found():
    # WordPress manda "log" y "pwd"; otros, "user_password" o "j_password".
    for body, user in (("log=ana&pwd=secreto1", "ana"), ("j_username=ana&j_password=secreto1", "ana"),
                       ("user_email=ana&user_password=secreto1", "ana")):  # fmt: skip
        [cred] = CredentialSniffer().feed(
            http(80, f"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{body}")
        )
        assert (cred.user, cred.secret) == (user, "secreto1")


def test_password_in_the_query_string_is_found():
    [cred] = CredentialSniffer().feed(http(80, "GET /cgi-bin/login.cgi?user=admin&password=camara123 HTTP/1.1\r\n\r\n"))
    assert (cred.user, cred.secret) == ("admin", "camara123")


def test_words_that_only_end_like_a_password_field_are_not_credentials():
    assert CredentialSniffer().feed(http(80, "GET /mapa?compass=norte&bypass=1&q=hola HTTP/1.1\r\n\r\n")) == []


def test_ipv6_packet_with_payload_length_zero_is_decoded():
    segment = tcp_segment(PC, SERVER, 40000, 80, ACK | PSH, b"GET / HTTP/1.1\r\n\r\n")
    packet = bytearray(ipv6("2001:db8::23", "2001:db8::10", PROTO_TCP, segment))
    packet[4:6] = b"\0\0"
    decoded = decode(0.0, 101, bytes(packet))
    assert decoded.proto == "TCP" and decoded.payload.startswith(b"GET /")
