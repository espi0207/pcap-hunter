import base64
import random

import pytest

from pcaphunter.decode import ACK, RST, SYN, Arp, Dns, Packet
from pcaphunter.detectors import Severity, base_domain, run_detectors

ATTACKER, SERVER = "192.168.1.66", "192.168.1.10"


def tcp(ts, src, dst, sport, dport, flags, payload=b""):
    return Packet(
        ts=ts, length=60, src=src, dst=dst, proto="TCP", sport=sport, dport=dport, flags=flags, payload=payload
    )


def rules(packets):
    return sorted(f.rule for f in run_detectors(sorted(packets, key=lambda p: p.ts)))


# Escaneos


def syn_scan(ports, open_ports=(), complete=False, spacing=0.05):
    packets = []
    for i, port in enumerate(ports):
        t, sport = i * spacing, 40000 + i
        packets.append(tcp(t, ATTACKER, SERVER, sport, port, SYN))
        if port in open_ports:
            packets.append(tcp(t + 0.001, SERVER, ATTACKER, port, sport, SYN | ACK))
            packets.append(tcp(t + 0.002, ATTACKER, SERVER, sport, port, ACK if complete else RST))
        else:
            packets.append(tcp(t + 0.001, SERVER, ATTACKER, port, sport, RST | ACK))
    return packets


def test_port_scan_reports_open_ports_and_scan_type():
    [finding] = run_detectors(syn_scan(range(1, 31), open_ports={22, 25}))
    assert finding.rule == "port_scan" and finding.src == ATTACKER and finding.dst == SERVER
    assert "abiertos: 22, 25" in finding.details and "nmap -sS" in finding.details

    [finding] = run_detectors(syn_scan(range(1, 31), open_ports={22}, complete=True))
    assert "nmap -sT" in finding.details


def test_slow_scan_below_the_window_is_not_reported():
    # 30 puertos, uno cada 5 minutos: nunca hay 15 dentro del mismo minuto.
    assert rules(syn_scan(range(1, 31), spacing=300)) == []


def test_network_sweep_and_ping_sweep():
    sweep = [tcp(i * 0.1, ATTACKER, f"192.168.1.{i}", 45000 + i, 445, SYN) for i in range(2, 40)]
    pings = [
        Packet(ts=100 + i * 0.1, length=60, src=ATTACKER, dst=f"192.168.1.{i}", proto="ICMP", icmp_type=8)
        for i in range(2, 40)
    ]
    assert rules(sweep + pings) == ["network_sweep", "ping_sweep"]


def test_normal_browsing_is_not_a_scan():
    rng = random.Random(1)
    packets = []
    for i in range(200):  # 200 conexiones a unos pocos servicios
        t = i * rng.uniform(1, 20)
        packets.append(
            tcp(t, "192.168.1.30", f"198.51.100.{rng.randint(1, 50)}", 50000 + i, rng.choice([80, 443]), SYN)
        )
    assert rules(packets) == []


# ARP


def arp(ts, mac, ip, op=2):
    return Packet(ts=ts, length=42, arp=Arp(op, mac, ip, "ff:ff:ff:ff:ff:ff", "192.168.1.255"))


def test_arp_spoofing_by_a_known_machine():
    packets = [
        arp(0, "00:00:00:00:00:01", "192.168.1.1"),
        arp(1, "de:ad:be:ef:00:66", "192.168.1.66"),
        arp(10, "de:ad:be:ef:00:66", "192.168.1.1"),
        arp(12, "de:ad:be:ef:00:66", "192.168.1.1"),
    ]
    [finding] = run_detectors(packets)
    assert finding.severity is Severity.HIGH
    assert "192.168.1.66" in finding.details and "2 paquete(s)" in finding.details


def test_arp_mac_change_from_unknown_machine_is_medium():
    [finding] = run_detectors([arp(0, "00:00:00:00:00:01", "192.168.1.1"), arp(5, "00:00:00:00:00:99", "192.168.1.1")])
    assert finding.severity is Severity.MEDIUM


def test_stable_arp_and_probes_are_fine():
    packets = [arp(t, "00:00:00:00:00:01", "192.168.1.1") for t in range(10)]
    packets += [arp(t, f"00:00:00:00:01:{t:02x}", "0.0.0.0", op=1) for t in range(10)]  # sondeos al arrancar
    assert rules(packets) == []


# DNS


def dns(ts, name, qtype="A", src="192.168.1.23"):
    return Packet(ts=ts, length=80, src=src, dst="192.168.1.1", proto="UDP", sport=5000, dport=53,
                  dns=Dns(1, False, 0, name, qtype))  # fmt: skip


def test_dns_tunnel():
    rng = random.Random(3)
    names = [base64.b32encode(rng.randbytes(30)).decode().rstrip("=").lower() + f".{i}.malo.example" for i in range(40)]
    [finding] = run_detectors([dns(i, n, "TXT") for i, n in enumerate(names)])
    assert finding.rule == "dns_tunnel" and finding.dst == "malo.example"
    assert "TXT (40)" in finding.details


@pytest.mark.parametrize(
    "names",
    [
        [f"img{i}.cdn.example" for i in range(40)],  # muchos subdominios, pero cortos y normales
        [f"{i % 250}.{i // 250}.113.203.zen.spamhaus.org" for i in range(40)],  # listas negras por DNS
        ["www.wikipedia.org"] * 100,  # muchas consultas al mismo nombre
    ],
)
def test_normal_dns_is_not_a_tunnel(names):
    assert rules([dns(i, n) for i, n in enumerate(names)]) == []


def test_base_domain():
    assert base_domain("a.b.github.com") == "github.com"
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk"


# Beaconing


def connections(times, dst="203.0.113.50", port=443):
    return [tcp(t, "192.168.1.23", dst, 50000 + i, port, SYN) for i, t in enumerate(times)]


def test_beaconing_with_jitter():
    rng = random.Random(5)
    times = [i * 60 + rng.uniform(-2, 2) for i in range(15)]
    [finding] = run_detectors(connections(times))
    assert finding.rule == "beaconing" and finding.severity is Severity.HIGH
    assert "una cada 60 s" in finding.details and "T1071.001" in finding.mitre


def test_irregular_connections_are_not_beaconing():
    rng = random.Random(6)
    t, times = 0.0, []
    for _ in range(30):
        t += rng.expovariate(1 / 60)  # una persona: intervalos al azar
        times.append(t)
    assert rules(connections(times)) == []


def test_bursts_and_few_connections_are_not_beaconing():
    assert rules(connections([i * 0.5 for i in range(20)])) == []  # ráfaga: cada medio segundo
    assert rules(connections([0, 60, 120, 180])) == []  # solo 4


# Credenciales


def test_same_credentials_twice_is_one_finding():
    packets = [
        tcp(1, "10.0.0.2", "10.0.0.1", 50000, 21, ACK, b"USER juan\r\n"),
        tcp(2, "10.0.0.2", "10.0.0.1", 50000, 21, ACK, b"PASS clave123\r\n"),
        tcp(9, "10.0.0.2", "10.0.0.1", 50001, 21, ACK, b"USER juan\r\n"),
        tcp(10, "10.0.0.2", "10.0.0.1", 50001, 21, ACK, b"PASS clave123\r\n"),
    ]
    [finding] = run_detectors(packets)
    assert finding.rule == "cleartext_credentials" and finding.last_seen == 10
    assert "clave123" not in finding.details
