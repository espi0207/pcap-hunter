"""Reglas añadidas en noviembre de 2026: fuerza bruta a servicios, puertos de malware,
DGA, DHCP falso, túnel ICMP y comunidades SNMP en claro."""

import struct

from pcaphunter.creds import CredentialSniffer
from pcaphunter.decode import ACK, PSH, SYN, Dns, Packet
from pcaphunter.detectors import Severity, run_detectors

ATTACKER, SERVER, PC = "192.168.1.66", "192.168.1.10", "192.168.1.20"


def tcp(ts, src, dst, sport, dport, flags, payload=b""):
    return Packet(ts=ts, length=60, src=src, dst=dst, proto="TCP", sport=sport, dport=dport, flags=flags,
                  payload=payload)  # fmt: skip


def udp(ts, src, dst, sport, dport, payload=b"", src_mac=None):
    return Packet(ts=ts, length=60 + len(payload), src=src, dst=dst, proto="UDP", sport=sport, dport=dport,
                  payload=payload, src_mac=src_mac)  # fmt: skip


def findings(packets, rule):
    return [f for f in run_detectors(sorted(packets, key=lambda p: p.ts)) if f.rule == rule]


# --- fuerza bruta contra un servicio ---------------------------------------


def logins(port, n, spacing=1.0):
    packets = []
    for i in range(n):
        t, sport = i * spacing, 50000 + i
        packets += [
            tcp(t, ATTACKER, SERVER, sport, port, SYN),
            tcp(t + 0.001, SERVER, ATTACKER, port, sport, SYN | ACK),
            tcp(t + 0.002, ATTACKER, SERVER, sport, port, ACK),
        ]
    return packets


def test_many_ssh_connections_in_a_minute_are_bruteforce():
    [f] = findings(logins(22, 30), "service_bruteforce")
    assert f.src == ATTACKER and f.dst == SERVER and "SSH" in f.title
    assert f.mitre.startswith("T1110") and f.wireshark == f"ip.addr=={ATTACKER} && ip.addr=={SERVER} && tcp.port==22"


def test_rdp_and_smb_too():
    assert findings(logins(3389, 20), "service_bruteforce")
    assert findings(logins(445, 20), "service_bruteforce")


def test_a_few_logins_or_web_traffic_are_not_bruteforce():
    assert findings(logins(22, 5), "service_bruteforce") == []
    assert findings(logins(443, 40), "service_bruteforce") == []  # la web abre muchas conexiones


# --- puertos de malware ----------------------------------------------------


def test_data_on_a_metasploit_port():
    packets = logins(4444, 1) + [tcp(0.01, ATTACKER, SERVER, 50000, 4444, ACK | PSH, b"\x00" * 40)]
    [f] = findings(packets, "suspicious_port")
    assert "4444" in f.title and "Metasploit" in f.details and f.mitre.startswith("T1571")


def test_a_scan_that_finds_the_port_open_is_not_a_session():
    assert findings(logins(4444, 1), "suspicious_port") == []  # sin datos: solo se tocó la puerta


# --- DGA -------------------------------------------------------------------


def nxdomain(ts, name):
    return Packet(ts=ts, length=90, src="192.168.1.1", dst=PC, proto="UDP", sport=53, dport=40000,
                  dns=Dns(1, True, 3, name, "A"))  # fmt: skip


def test_many_nxdomain_for_different_domains_is_a_dga():
    names = [f"xk{i}qzv{i * 7}ptl.com" for i in range(12)] + [f"aa{i}rrt.net" for i in range(8)]
    [f] = findings([nxdomain(i, n) for i, n in enumerate(names)], "dga")
    assert f.src == PC and f.severity is Severity.HIGH and f.mitre.startswith("T1568.002")
    assert f.wireshark == f"ip.dst=={PC} && dns.flags.rcode==3"


def test_nxdomain_under_one_domain_is_a_typo_or_a_search_suffix():
    names = [f"host{i}.empresa.local" for i in range(30)]
    assert findings([nxdomain(i, n) for i, n in enumerate(names)], "dga") == []


# --- DHCP falso --------------------------------------------------------------


def dhcp_offer(server_ip, router, dns, msg_type=2):
    body = bytearray(240)
    body[0] = 2  # BOOTREPLY
    body[236:240] = b"\x63\x82\x53\x63"
    options = bytes([53, 1, msg_type, 54, 4]) + bytes(map(int, server_ip.split(".")))
    options += bytes([3, 4]) + bytes(map(int, router.split(".")))
    options += bytes([6, 4]) + bytes(map(int, dns.split(".")))
    return bytes(body) + options + b"\xff"


def test_two_dhcp_servers_is_a_rogue_dhcp():
    packets = [
        udp(1, "192.168.1.1", "255.255.255.255", 67, 68, dhcp_offer("192.168.1.1", "192.168.1.1", "192.168.1.1"),
            "aa:aa:aa:aa:aa:01"),  # fmt: skip
        udp(1.01, ATTACKER, "255.255.255.255", 67, 68, dhcp_offer(ATTACKER, ATTACKER, ATTACKER), "bb:bb:bb:bb:bb:66"),
    ]
    [f] = findings(packets, "rogue_dhcp")
    assert f.severity is Severity.HIGH and f.mitre.startswith("T1557.003")
    assert "192.168.1.1" in f.details and ATTACKER in f.details and "puerta de enlace" in f.details


def test_one_dhcp_server_is_normal():
    packets = [udp(i, "192.168.1.1", PC, 67, 68, dhcp_offer("192.168.1.1", "192.168.1.1", "1.1.1.1", t))
               for i, t in enumerate((2, 5, 2, 5))]  # fmt: skip
    assert findings(packets, "rogue_dhcp") == []


def test_broken_dhcp_does_not_crash():
    packets = [udp(1, ATTACKER, PC, 67, 68, b"\x02" + b"\x00" * 10), udp(2, ATTACKER, PC, 67, 68, b"")]
    assert findings(packets, "rogue_dhcp") == []


# --- túnel ICMP --------------------------------------------------------------


def ping(ts, payload, src=PC, dst="203.0.113.50"):
    return Packet(ts=ts, length=42 + len(payload), src=src, dst=dst, proto="ICMP", icmp_type=8, payload=payload)


def test_big_and_changing_pings_are_a_tunnel():
    packets = [ping(i, struct.pack("!I", i) + bytes([i % 251]) * 400) for i in range(15)]
    [f] = findings(packets, "icmp_tunnel")
    assert f.src == PC and f.mitre.startswith("T1095") and "KB" in f.details


def test_normal_and_mtu_test_pings_are_not_a_tunnel():
    normal = [ping(i, b"abcdefghijklmnopqrstuvwabcdefghi") for i in range(30)]
    mtu = [ping(100 + i, b"\x00" * 1472) for i in range(15)]  # ping -s 1472: siempre lo mismo
    assert findings(normal + mtu, "icmp_tunnel") == []


# --- SNMP --------------------------------------------------------------------


def snmp_get(community: bytes, version: int = 1) -> bytes:
    inner = bytes([0x02, 0x01, version, 0x04, len(community)]) + community + bytes([0xA0, 0x00])
    return bytes([0x30, len(inner)]) + inner


def test_snmp_community_is_a_cleartext_password():
    sniffer = CredentialSniffer()
    [cred] = sniffer.feed(udp(1, PC, SERVER, 40000, 161, snmp_get(b"s3cr3t-rw")))
    assert cred.protocol == "SNMPv2c" and cred.secret == "s3cr3t-rw" and cred.kind == "comunidad"


def test_snmp_finding_and_garbage():
    packets = [udp(1, PC, SERVER, 40000, 161, snmp_get(b"public", 0)), udp(2, PC, SERVER, 40001, 161, b"\x30\x99")]
    [f] = findings(packets, "cleartext_credentials")
    assert "SNMPv1" in f.title
