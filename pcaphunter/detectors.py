"""Detectores sobre los paquetes ya decodificados.

Cada uno busca un patrón concreto, el mismo que buscaría alguien mirando la captura en
Wireshark: muchos puertos distintos en poco tiempo (escaneo), una IP que cambia de MAC
(ARP spoofing), subdominios larguísimos y aleatorios (túnel DNS), conexiones a
intervalos demasiado regulares (beaconing) y contraseñas que viajan en claro.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import IntEnum
from itertools import pairwise

from .creds import CredentialSniffer, mask
from .decode import RST, SYN, Packet


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {1: "BAJA", 2: "MEDIA", 3: "ALTA", 4: "CRÍTICA"}[self.value]


@dataclass
class Finding:
    severity: Severity
    rule: str
    title: str
    first_seen: float
    last_seen: float
    details: str
    src: str | None = None
    dst: str | None = None
    mitre: str | None = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.label,
            "rule": self.rule,
            "title": self.title,
            "src": self.src,
            "dst": self.dst,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "mitre": self.mitre,
            "details": self.details,
        }


@dataclass(frozen=True)
class Config:
    scan_ports: int = 15  # puertos distintos de un equipo a otro...
    scan_window: float = 60.0  # ...en esta ventana (segundos)
    sweep_hosts: int = 15  # equipos distintos probados en el mismo puerto
    dns_min_names: int = 20  # subdominios distintos bajo un mismo dominio
    dns_min_length: float = 25.0  # longitud media de la parte del subdominio...
    dns_min_entropy: float = 3.8  # ...o entropía (bits por carácter)
    beacon_min_connections: int = 6
    beacon_min_interval: float = 5.0  # por debajo de esto es una ráfaga normal, no una baliza
    beacon_max_jitter: float = 0.15  # desviación típica / media de los intervalos


def _max_distinct_in_window(events: list[tuple[float, object]], window: float) -> tuple[int, float, float]:
    """Máximo de valores distintos dentro de cualquier ventana de `window` segundos (dos punteros)."""
    counts: Counter = Counter()
    best, best_span = 0, (events[0][0], events[0][0])
    start = 0
    for ts, value in events:
        counts[value] += 1
        while ts - events[start][0] > window:
            old = events[start][1]
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
            start += 1
        if len(counts) > best:
            best, best_span = len(counts), (events[start][0], ts)
    return best, *best_span


def _duration(start: float, end: float) -> str:
    seconds = end - start
    if seconds < 1:
        return "menos de un segundo"
    return f"{seconds:.0f} s" if seconds < 120 else f"{seconds / 60:.0f} min"


def _ports_text(ports) -> str:
    ports = sorted(ports)
    return ", ".join(map(str, ports[:12])) + (f" y {len(ports) - 12} más" if len(ports) > 12 else "")


def detect_scans(packets: list[Packet], cfg: Config) -> list[Finding]:
    syns = [p for p in packets if p.is_syn]
    # Una conexión es (cliente, puerto del cliente, servidor, puerto del servidor): así una
    # respuesta solo cuenta para el intento concreto al que responde.
    synacks = {(p.dst, p.dport, p.src, p.sport) for p in packets if p.is_synack}
    # Si el que escanea contesta al SYN-ACK con un ACK, completa la conexión (nmap -sT);
    # si contesta con RST, es un escaneo "medio abierto" (nmap -sS), más sigiloso.
    acks = {(p.src, p.sport, p.dst, p.dport) for p in packets if p.proto == "TCP" and p.flags & (SYN | RST) == 0}
    findings = []

    by_pair: dict[tuple, list] = defaultdict(list)
    by_port: dict[tuple, list] = defaultdict(list)
    for p in syns:
        by_pair[(p.src, p.dst)].append((p.ts, p))
        by_port[(p.src, p.dport)].append((p.ts, p))

    for (src, dst), events in by_pair.items():
        count, start, end = _max_distinct_in_window([(ts, p.dport) for ts, p in events], cfg.scan_window)
        if count < cfg.scan_ports:
            continue
        probed = {p.dport for _, p in events}
        answered = [p for _, p in events if (p.src, p.sport, p.dst, p.dport) in synacks]
        open_ports = {p.dport for p in answered}
        if open_ports:
            completed = any((p.src, p.sport, p.dst, p.dport) in acks for p in answered)
            kind = "de conexión completa (como nmap -sT)" if completed else "SYN, medio abierto (como nmap -sS)"
            result = f"abiertos: {_ports_text(open_ports)}. Escaneo {kind}"
        else:
            result = "ninguno respondió como abierto"
        findings.append(
            Finding(
                Severity.MEDIUM,
                "port_scan",
                f"Escaneo de puertos de {src} a {dst}",
                start,
                end,
                f"{count} puertos distintos en {_duration(start, end)}"
                + (f" ({len(probed)} en total)" if len(probed) != count else "")
                + f"; {result}",
                src,
                dst,
                "T1046 Network Service Discovery",
            )
        )

    for (src, port), events in by_port.items():
        count, start, end = _max_distinct_in_window([(ts, p.dst) for ts, p in events], cfg.scan_window)
        if count < cfg.sweep_hosts:
            continue
        hosts = {p.dst for _, p in events}
        answered = {p.dst for _, p in events if (p.src, p.sport, p.dst, p.dport) in synacks}
        findings.append(
            Finding(
                Severity.MEDIUM,
                "network_sweep",
                f"Barrido de la red desde {src} buscando el puerto {port}",
                start,
                end,
                f"{len(hosts)} equipos probados, {len(answered)} lo tienen abierto",
                src,
                None,
                "T1046 Network Service Discovery",
            )
        )

    pings = [(p.ts, p.dst, p.src) for p in packets if p.proto == "ICMP" and p.icmp_type == 8]
    by_src: dict[str, list] = defaultdict(list)
    for ts, dst, src in pings:
        by_src[src].append((ts, dst))
    for src, events in by_src.items():
        count, start, end = _max_distinct_in_window(events, cfg.scan_window)
        if count >= cfg.sweep_hosts:
            findings.append(
                Finding(
                    Severity.LOW,
                    "ping_sweep",
                    f"Barrido con ping desde {src}",
                    start,
                    end,
                    f"{len({d for _, d in events})} equipos distintos, buscando cuáles están encendidos",
                    src,
                    None,
                    "T1018 Remote System Discovery",
                )
            )
    return findings


def detect_arp_spoofing(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Una IP que de repente contesta desde otra MAC. Si esa MAC ya era de otro equipo de
    la red, es que ese equipo se está haciendo pasar por la IP (típicamente la del router,
    para ponerse en medio de todo el tráfico)."""
    owner: dict[str, str] = {}  # IP -> MAC que la anunció primero
    changes: dict[tuple, list[float]] = defaultdict(list)  # (ip, mac antigua, mac nueva) -> momentos
    for p in packets:
        if not p.arp or p.arp.sender_ip == "0.0.0.0":  # 0.0.0.0: sondeo ARP de un equipo que arranca
            continue
        ip, mac = p.arp.sender_ip, p.arp.sender_mac
        if ip not in owner:
            owner[ip] = mac
        elif owner[ip] != mac:
            changes[(ip, owner[ip], mac)].append(p.ts)

    findings = []
    for (ip, old, new), times in changes.items():
        others = sorted(other for other, mac in owner.items() if mac == new and other != ip)
        if others:
            severity = Severity.HIGH
            detail = f"la MAC {new} es la de {', '.join(others)}: ese equipo se está haciendo pasar por {ip}"
        else:
            severity = Severity.MEDIUM
            detail = f"puede ser un cambio legítimo (otro router, otra tarjeta), o alguien suplantándola desde {new}"
        findings.append(
            Finding(
                severity,
                "arp_spoofing",
                f"La IP {ip} cambia de MAC: {old} -> {new}",
                times[0],
                times[-1],
                f"{len(times)} paquete(s) ARP; {detail}",
                ip,
                None,
                "T1557.002 ARP Cache Poisoning",
            )
        )
    return findings


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def base_domain(name: str) -> str:
    """El dominio "registrado": ejemplo.com, o ejemplo.co.uk. Es una aproximación: lo exacto
    necesitaría la Public Suffix List entera."""
    labels = name.rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def detect_dns_tunnel(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Muchísimos subdominios distintos, largos y con pinta aleatoria bajo un mismo dominio.

    Así se sacan datos por DNS (dnscat2, iodine...): se codifican en el subdominio y el
    servidor DNS del atacante, que es el autoritativo de ese dominio, los recibe. Funciona
    aunque el firewall no deje salir nada más, porque casi nadie bloquea el DNS.
    """
    queries: dict[tuple, list[Packet]] = defaultdict(list)
    for p in packets:
        if p.dns and not p.dns.response and p.dns.qname.count(".") >= 2:
            queries[(p.src, base_domain(p.dns.qname))].append(p)

    findings = []
    for (src, domain), pkts in queries.items():
        subs = {p.dns.qname[: -len(domain) - 1] for p in pkts}
        if len(subs) < cfg.dns_min_names:
            continue
        avg_len = statistics.mean(len(s) for s in subs)
        ent = _entropy("".join(s.replace(".", "") for s in subs))
        if avg_len < cfg.dns_min_length and ent < cfg.dns_min_entropy:
            continue
        types = Counter(p.dns.qtype for p in pkts)
        encoded = sum(len(s) for s in subs)
        findings.append(
            Finding(
                Severity.HIGH,
                "dns_tunnel",
                f"Posible túnel DNS de {src} hacia {domain}",
                pkts[0].ts,
                pkts[-1].ts,
                f"{len(subs)} subdominios distintos de {avg_len:.0f} caracteres de media y entropía {ent:.1f}; "
                f"unos {encoded / 1024:.1f} KB codificados en los nombres; "
                f"tipos: {', '.join(f'{t} ({n})' for t, n in types.most_common(3))}",
                src,
                domain,
                "T1071.004 Application Layer Protocol: DNS",
            )
        )
    return findings


def detect_beaconing(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Conexiones al mismo destino a intervalos casi exactos.

    Una persona navegando no abre una conexión cada 60 segundos clavados durante una hora.
    Un malware que "llama a casa" para pedir órdenes a su servidor de control, sí. Muchos
    añaden algo de variación (jitter) para disimular; por eso se mide la dispersión de los
    intervalos y no si son exactamente iguales.
    """
    starts: dict[tuple, list[float]] = defaultdict(list)
    for p in packets:
        if p.is_syn:
            starts[(p.src, p.dst, p.dport)].append(p.ts)

    findings = []
    for (src, dst, port), times in starts.items():
        if len(times) < cfg.beacon_min_connections:
            continue
        intervals = [b - a for a, b in pairwise(times)]
        mean = statistics.mean(intervals)
        if mean < cfg.beacon_min_interval:
            continue
        jitter = statistics.pstdev(intervals) / mean
        if jitter > cfg.beacon_max_jitter:
            continue
        web = port in (80, 443, 8080, 8443)
        findings.append(
            Finding(
                Severity.HIGH,
                "beaconing",
                f"Conexiones periódicas de {src} a {dst}:{port}",
                times[0],
                times[-1],
                f"{len(times)} conexiones, una cada {mean:.0f} s (variación del {jitter:.0%}): "
                "parece un programa que se comunica solo con un servidor de control",
                src,
                dst,
                "T1071.001 Web Protocols" if web else "T1071 Application Layer Protocol",
            )
        )
    return findings


def detect_cleartext_credentials(packets: list[Packet], cfg: Config) -> list[Finding]:
    sniffer = CredentialSniffer()
    seen: dict[tuple, Finding] = {}
    for p in packets:
        for cred in sniffer.feed(p):
            key = (cred.protocol, p.src, p.dst, cred.user, cred.secret)
            if key in seen:
                seen[key].last_seen = p.ts
                continue
            who = f"usuario '{cred.user}', " if cred.user else ""
            seen[key] = Finding(
                Severity.HIGH,
                "cleartext_credentials",
                f"{cred.kind.capitalize()} en claro por {cred.protocol}: {p.src} -> {p.dst}:{p.dport}",
                p.ts,
                p.ts,
                f"{who}{cred.kind} {mask(cred.secret)}. Cualquiera en la misma red puede leerla",
                p.src,
                p.dst,
                "T1040 Network Sniffing",
            )
    return list(seen.values())


DETECTORS = [detect_scans, detect_arp_spoofing, detect_dns_tunnel, detect_beaconing, detect_cleartext_credentials]


def run_detectors(packets: list[Packet], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings = [f for detector in DETECTORS for f in detector(packets, cfg)]
    return sorted(findings, key=lambda f: (-f.severity, f.first_seen))
