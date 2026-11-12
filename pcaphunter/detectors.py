"""Detectores sobre los paquetes ya decodificados.

Cada uno busca un patrón concreto, el mismo que buscaría alguien mirando la captura en
Wireshark: muchos puertos distintos en poco tiempo (escaneo), una IP que cambia de MAC
(ARP spoofing), subdominios larguísimos y aleatorios (túnel DNS), conexiones a
intervalos demasiado regulares (beaconing), contraseñas que viajan en claro, ráfagas de
conexiones a SSH o RDP (fuerza bruta), sesiones en puertos típicos de malware, muchos
dominios que no existen (DGA), dos servidores DHCP (uno falso) y pings que llevan datos.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import IntEnum
from itertools import pairwise

from .creds import CredentialSniffer, mask
from .decode import ACK, RST, SYN, Packet


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
    port: int | None = None  # el puerto del servicio, cuando el hallazgo va de uno concreto

    @property
    def wireshark(self) -> str | None:
        """Filtro de Wireshark que deja a la vista los paquetes de este hallazgo."""
        return wireshark_filter(self.rule, self.src, self.dst, self.port)

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
            "wireshark": self.wireshark,
        }


def _ip(field: str, address: str) -> str:
    return f"{'ipv6' if ':' in address else 'ip'}.{field}=={address}"


def wireshark_filter(rule: str, src: str | None, dst: str | None, port: int | None = None) -> str | None:
    if rule == "rogue_dhcp":
        return "udp.srcport==67"
    if not src:
        return None
    if rule == "dga":
        return f"{_ip('dst', src)} && dns.flags.rcode==3"
    if rule == "icmp_tunnel" and dst:
        return f"{_ip('addr', src)} && {_ip('addr', dst)} && (icmp || icmpv6)"
    if dst and port is not None:
        return f"{_ip('addr', src)} && {_ip('addr', dst)} && tcp.port=={port}"
    if rule == "arp_spoofing":
        return f"arp.src.proto_ipv4=={src}"
    if rule == "ping_sweep":
        return f"{_ip('src', src)} && (icmp.type==8 || icmpv6.type==128)"
    if rule == "network_sweep":
        return f"{_ip('src', src)} && tcp.flags.syn==1 && tcp.flags.ack==0"
    if rule == "dns_tunnel" and dst:
        domain = dst.replace("\\", "\\\\").replace('"', '\\"')
        return f'{_ip("src", src)} && dns.qry.name contains "{domain}"'
    if dst and rule == "stealth_scan":
        return f"{_ip('src', src)} && {_ip('dst', dst)} && tcp.flags.syn==0 && tcp.flags.ack==0 && tcp.flags.reset==0"
    if dst and rule in ("port_scan", "beaconing"):
        return f"{_ip('addr', src)} && {_ip('addr', dst)} && tcp.flags.syn==1"
    if dst:
        return f"{_ip('addr', src)} && {_ip('addr', dst)}"
    return _ip("addr", src)


@dataclass(frozen=True)
class Config:
    scan_ports: int = 15  # puertos distintos de un equipo a otro...
    scan_window: float = 60.0  # ...en esta ventana (segundos)
    sweep_hosts: int = 15  # equipos distintos probados en el mismo puerto
    dns_min_names: int = 20  # subdominios distintos bajo un mismo dominio
    dns_min_length: float = 25.0  # longitud media de la parte del subdominio...
    dns_min_entropy: float = 3.8  # ...o entropía (bits por carácter)...
    dns_min_encoded_length: float = 10.0  # ...en nombres de al menos esta longitud media...
    dns_max_vowels: float = 0.25  # ...y casi sin vocales: datos codificados, no palabras
    beacon_min_connections: int = 6
    beacon_min_interval: float = 5.0  # por debajo de esto es una ráfaga normal, no una baliza
    beacon_max_jitter: float = 0.15  # desviación típica / media de los intervalos
    beacon_max_gaps: float = 0.2  # parte de los intervalos que pueden ser parones (equipo suspendido)
    brute_min_connections: int = 15  # conexiones nuevas a SSH, RDP, SMB... desde un equipo...
    brute_window: float = 60.0  # ...en esta ventana (segundos)
    dga_min_domains: int = 10  # dominios distintos que no existen, pedidos por un equipo
    icmp_min_payload: int = 128  # bytes de datos en un ping (Windows manda 32 y Linux 56)
    icmp_min_packets: int = 10


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
    acks = {
        (p.src, p.sport, p.dst, p.dport)
        for p in packets
        if p.proto == "TCP" and p.flags & ACK and not p.flags & (SYN | RST)  # un FIN suelto no completa nada
    }
    # Conexiones en las que el cliente llegó a mandar datos: una conversación de verdad.
    talked = {(p.src, p.sport, p.dst, p.dport) for p in packets if p.proto == "TCP" and p.payload}
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
        # Quien barre una red encuentra casi todo cerrado y, si algo contesta, corta. Quien navega
        # habla con todos: abrir una web moderna son decenas de servidores distintos por el 443.
        conversed = {p.dst for _, p in events if (p.src, p.sport, p.dst, p.dport) in synacks & talked}
        if len(conversed) * 2 >= len(hosts):
            continue
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

    findings += _stealth_scans(packets, cfg)

    # echo request: tipo 8 en ICMP y 128 en ICMPv6
    pings = [(p.ts, p.dst, p.src) for p in packets if (p.proto, p.icmp_type) in (("ICMP", 8), ("ICMPv6", 128))]
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


STEALTH_KINDS = {0: "NULL (sin ningún flag, nmap -sN)", 0x01: "FIN (nmap -sF)", 0x29: "Xmas (FIN, PSH y URG, nmap -sX)"}


def _stealth_scans(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Escaneos que no usan SYN: paquetes sueltos sin SYN, ACK ni RST a muchos puertos.

    Ninguna conexión normal empieza así. Un puerto cerrado contesta con RST y uno abierto se
    calla, y con eso el que escanea se entera sin llegar a abrir ninguna conexión.
    """
    probes: dict[tuple, list] = defaultdict(list)
    for p in packets:
        if p.proto == "TCP" and not p.flags & (SYN | ACK | RST) and not p.payload:
            probes[(p.src, p.dst)].append((p.ts, p))
    resets = {(p.dst, p.dport, p.src, p.sport) for p in packets if p.proto == "TCP" and p.flags & RST}
    findings = []
    for (src, dst), events in probes.items():
        count, start, end = _max_distinct_in_window([(ts, p.dport) for ts, p in events], cfg.scan_window)
        if count < cfg.scan_ports:
            continue
        flags = Counter(p.flags & 0x3F for _, p in events).most_common(1)[0][0]
        kind = STEALTH_KINDS.get(flags, "con flags que no usa ninguna conexión normal")
        silent = {p.dport for _, p in events} - {
            p.dport for _, p in events if (p.src, p.sport, p.dst, p.dport) in resets
        }
        result = (
            f"sin respuesta (abiertos o filtrados): {_ports_text(silent)}" if silent else "todos contestaron cerrado"
        )
        findings.append(
            Finding(
                Severity.MEDIUM,
                "stealth_scan",
                f"Escaneo sigiloso de puertos de {src} a {dst}",
                start,
                end,
                f"{count} puertos distintos en {_duration(start, end)} con paquetes {kind}; {result}",
                src,
                dst,
                "T1046 Network Service Discovery",
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

    ips_of: dict[str, list[str]] = defaultdict(list)  # MAC -> IPs (antes se recorrían todas por cada cambio)
    for other, mac in owner.items():
        ips_of[mac].append(other)
    findings = []
    for (ip, old, new), times in changes.items():
        others = sorted(other for other in ips_of[new] if other != ip)
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


# Redes de reparto de contenido y nubes que dan a cada servidor un nombre con pinta aleatoria.
# Por ellas no se puede montar un túnel: haría falta mandar en el servidor DNS de esa zona.
CDN_ZONES = {
    "googlevideo.com", "gvt1.com", "1e100.net", "cloudfront.net", "amazonaws.com", "akamaihd.net",
    "akamaiedge.net", "akamai.net", "edgekey.net", "edgesuite.net", "fbcdn.net", "cdninstagram.com",
    "windows.net", "azureedge.net", "msedge.net", "nflxvideo.net", "llnwd.net", "fastly.net",
    "apple-dns.net", "aaplimg.com", "office.com", "microsoft.com", "googleusercontent.com",
}  # fmt: skip
VOWELS = set("aeiou")


def _vowel_share(text: str) -> float:
    """Parte de las letras y cifras que son vocales. En palabras ronda el 35-40 %; en datos
    codificados (hexadecimal, base32, base64) no pasa del 16 %."""
    chars = [c for c in text if c.isalnum()]
    return sum(c in VOWELS for c in chars) / len(chars) if chars else 1.0


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
        if len(subs) < cfg.dns_min_names or domain in CDN_ZONES:
            continue
        avg_len = statistics.mean(len(s) for s in subs)
        joined = "".join(s.replace(".", "") for s in subs)
        ent = _entropy(joined)
        # Nombres largos, o más cortos pero codificados. La entropía sola no vale: veinte nombres
        # normales (www, mail, drive...) juntos ya tienen tanta como un texto en hexadecimal.
        encoded_looking = (
            avg_len >= cfg.dns_min_encoded_length
            and ent >= cfg.dns_min_entropy
            and _vowel_share(joined) < cfg.dns_max_vowels
        )
        if avg_len < cfg.dns_min_length and not encoded_looking:
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


SYN_RETRANSMIT_GAP = 40.0  # segundos


def detect_beaconing(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Conexiones al mismo destino a intervalos casi exactos.

    Una persona navegando no abre una conexión cada 60 segundos clavados durante una hora.
    Un malware que "llama a casa" para pedir órdenes a su servidor de control, sí. Muchos
    añaden algo de variación (jitter) para disimular; por eso se mide la dispersión de los
    intervalos y no si son exactamente iguales.
    """
    starts: dict[tuple, list[float]] = defaultdict(list)
    last_syn: dict[tuple, float] = {}
    for p in packets:
        if not p.is_syn:
            continue
        # Un SYN reenviado (mismo puerto de origen, segundos después) es la misma conexión,
        # no una llamada más. Los reenvíos van a 1, 2, 4... hasta 32 s del anterior; un puerto
        # que se vuelve a usar minutos más tarde sí es una conexión nueva.
        conn = (p.src, p.sport, p.dst, p.dport)
        retransmission = conn in last_syn and p.ts - last_syn[conn] <= SYN_RETRANSMIT_GAP
        last_syn[conn] = p.ts
        if not retransmission:
            starts[(p.src, p.dst, p.dport)].append(p.ts)

    findings = []
    for (src, dst, port), times in starts.items():
        if len(times) < cfg.beacon_min_connections:
            continue
        intervals = [b - a for a, b in pairwise(times)]
        # Un equipo que se suspende o pierde la red deja huecos largos entre llamadas; se apartan
        # (si son pocos) para que no tapen el ritmo de todas las demás.
        median = statistics.median(intervals)
        regular = [x for x in intervals if x <= 3 * median]
        gaps = len(intervals) - len(regular)
        if len(regular) + 1 < cfg.beacon_min_connections or gaps > len(intervals) * cfg.beacon_max_gaps:
            continue
        mean = statistics.mean(regular)
        if mean < cfg.beacon_min_interval:
            continue
        jitter = statistics.pstdev(regular) / mean
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
                f"{len(times)} conexiones, una cada {mean:.0f} s (variación del {jitter:.0%}"
                + (f", con {gaps} parón(es) largo(s)" if gaps else "")
                + "): "
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


def _max_in_window(times: list[float], window: float) -> tuple[int, float, float]:
    best, span, start = 0, (times[0], times[0]), 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        if end - start + 1 > best:
            best, span = end - start + 1, (times[start], t)
    return best, *span


# Servicios donde se entra con usuario y contraseña: muchas conexiones seguidas = probando claves.
LOGIN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB",
    1433: "SQL Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM",
}  # fmt: skip


def detect_service_bruteforce(packets: list[Packet], cfg: Config) -> list[Finding]:
    starts: dict[tuple, list[float]] = defaultdict(list)
    seen: set[tuple] = set()
    for p in packets:
        if p.is_syn and p.dport in LOGIN_SERVICES:
            conn = (p.src, p.sport, p.dst, p.dport)
            if conn not in seen:  # los SYN reenviados son la misma conexión
                seen.add(conn)
                starts[(p.src, p.dst, p.dport)].append(p.ts)
    findings = []
    for (src, dst, port), times in starts.items():
        count, start, end = _max_in_window(times, cfg.brute_window)
        if count < cfg.brute_min_connections:
            continue
        service = LOGIN_SERVICES[port]
        findings.append(
            Finding(
                Severity.MEDIUM,
                "service_bruteforce",
                f"Posible fuerza bruta contra {service} de {dst} desde {src}",
                start,
                end,
                f"{count} conexiones nuevas al puerto {port} en {_duration(start, end)} ({len(times)} en total). "
                "Una persona abre una o dos; tantas seguidas son un programa probando contraseñas "
                "(hydra, ncrack, crackmapexec...)",
                src,
                dst,
                "T1110 Brute Force",
                port,
            )
        )
    return findings


# Puertos que usan por defecto herramientas de ataque y puertas traseras. Que haya datos en
# ellos no prueba nada (cualquiera puede usar el 4444), pero merece un vistazo.
MALWARE_PORTS = {
    4444: "el que usa Metasploit por defecto para sus shells inversas y Meterpreter",
    4445: "uno de los de Metasploit",
    1337: "un puerto 'elite' típico de herramientas de ataque",
    31337: "el de Back Orifice y otras puertas traseras",
    12345: "el de NetBus",
    6666: "IRC, que usan muchas botnets para recibir órdenes",
    6667: "IRC, que usan muchas botnets para recibir órdenes",
    6697: "IRC con TLS, que usan algunas botnets",
}


def detect_suspicious_ports(packets: list[Packet], cfg: Config) -> list[Finding]:
    opened: dict[tuple, tuple[str, str, int]] = {}  # conexión -> (cliente, servidor, puerto)
    sessions: dict[tuple, list] = {}  # (cliente, servidor, puerto) -> [primero, último, bytes]
    for p in packets:
        if p.proto != "TCP":
            continue
        if p.is_syn and p.dport in MALWARE_PORTS:
            key = (p.src, p.dst, p.dport)
            opened[(p.src, p.sport, p.dst, p.dport)] = key
            opened[(p.dst, p.dport, p.src, p.sport)] = key
        elif p.payload and (key := opened.get((p.src, p.sport, p.dst, p.dport))):
            if key in sessions:
                sessions[key][1] = p.ts
                sessions[key][2] += len(p.payload)
            else:
                sessions[key] = [p.ts, p.ts, len(p.payload)]
    return [
        Finding(
            Severity.MEDIUM,
            "suspicious_port",
            f"Sesión con datos en el puerto {port}: {client} -> {server}",
            first,
            last,
            f"{size} bytes. El {port} es {MALWARE_PORTS[port]}. Puede ser legítimo, pero si {client} "
            "es un equipo normal de la red, mira qué programa abrió esa conexión",
            client,
            server,
            "T1571 Non-Standard Port",
            port,
        )
        for (client, server, port), (first, last, size) in sessions.items()
    ]


# Zonas que solo existen dentro de una red: que el DNS no las conozca no dice nada.
LOCAL_ZONES = ("local", "lan", "home", "internal", "intranet", "corp", "localdomain", "arpa", "test", "invalid",
               "workgroup", "localhost")  # fmt: skip


def _local_name(name: str) -> bool:
    labels = name.rstrip(".").split(".")
    return len(labels) < 2 or labels[-1] in LOCAL_ZONES


def _looks_generated(domain: str) -> bool:
    """Un nombre que nadie escribiría: casi sin vocales o con cuatro consonantes seguidas."""
    label = domain.split(".")[0]
    letters = [c for c in label if c.isalpha()]
    if len(label) < 6 or not letters:
        return False
    run = longest = 0
    for c in label:
        run = run + 1 if c.isalpha() and c not in "aeiouy" else 0
        longest = max(longest, run)
    digits = sum(c.isdigit() for c in label)
    return longest >= 4 or _vowel_share(label) < 0.2 or digits * 3 >= len(label)


def detect_dga(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Muchos dominios distintos que no existen (NXDOMAIN), pedidos por el mismo equipo.

    Algunos malware no llevan escrita la dirección de su servidor: generan cada día cientos
    de nombres al azar (un DGA) y prueban hasta dar con el que el atacante ha registrado.
    Desde la red se ve como un montón de respuestas "ese dominio no existe".
    """
    failed: dict[str, dict[str, Packet]] = defaultdict(dict)  # equipo -> dominio -> primera respuesta
    for p in packets:
        if p.dns and p.dns.response and p.dns.rcode == 3 and p.dst and not _local_name(p.dns.qname):
            failed[p.dst].setdefault(base_domain(p.dns.qname), p)
    findings = []
    for client, domains in failed.items():
        if len(domains) < cfg.dga_min_domains:
            continue
        responses = sorted(domains.values(), key=lambda p: p.ts)
        generated = sorted(d for d in domains if _looks_generated(d))
        if len(generated) * 2 >= len(domains):
            severity, title = Severity.HIGH, f"{client} pide muchos dominios que no existen (posible DGA)"
            sample = ", ".join(generated[:5])
            why = "Son nombres sin sentido: así buscan algunos malware su servidor de control"
        else:
            # Nombres que se pueden leer: lo normal es un bloqueador de anuncios (Pi-hole, AdGuard)
            # que contesta "no existe", o direcciones mal escritas.
            severity, title = Severity.LOW, f"{client} pide muchos dominios que no existen"
            sample = ", ".join(sorted(domains)[:5])
            why = "Se pueden leer, así que parece un bloqueador de anuncios o nombres mal escritos, no un malware"
        findings.append(
            Finding(
                severity,
                "dga",
                title,
                responses[0].ts,
                responses[-1].ts,
                f"{len(domains)} dominios distintos sin respuesta, por ejemplo {sample}. {why}",
                client,
                None,
                "T1568.002 Domain Generation Algorithms",
            )
        )
    return findings


def detect_rogue_dhcp(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Dos servidores DHCP repartiendo direcciones en la misma red.

    Un DHCP falso da a los equipos que se conectan su propia IP como puerta de enlace o como
    DNS, y así todo su tráfico pasa por él (o sus búsquedas de nombres).
    """
    servers: dict[str, dict] = {}
    for p in packets:
        if p.proto != "UDP" or p.sport != 67:
            continue
        reply = parse_dhcp_reply(p.payload)
        if reply is None:
            continue
        server = reply.get("server") or p.src or "?"
        info = servers.setdefault(server, {"first": p.ts, "last": p.ts, "mac": p.src_mac, **reply})
        info["last"] = p.ts
    if len(servers) < 2:
        return []
    ordered = sorted(servers.items(), key=lambda item: item[1]["first"])

    def describe(ip: str, info: dict) -> str:
        parts = [f"MAC {info['mac']}" if info.get("mac") else None]
        parts.append(f"puerta de enlace {info['router']}" if info.get("router") else None)
        parts.append(f"DNS {info['dns']}" if info.get("dns") else None)
        return f"{ip} ({', '.join(x for x in parts if x)})"

    return [
        Finding(
            Severity.HIGH,
            "rogue_dhcp",
            f"{len(servers)} servidores DHCP en la misma red: {', '.join(ip for ip, _ in ordered)}",
            ordered[0][1]["first"],
            max(info["last"] for _, info in ordered),
            "; ".join(describe(ip, info) for ip, info in ordered)
            + ". En una red normal solo hay uno: el que sobra puede estar desviando el tráfico",
            None,
            None,
            "T1557.003 DHCP Spoofing",
        )
    ]


DHCP_COOKIE = b"\x63\x82\x53\x63"


def parse_dhcp_reply(payload: bytes) -> dict | None:
    """Una oferta (2) o confirmación (5) de DHCP (RFC 2131 y 2132), o None si no lo es."""
    if len(payload) < 240 or payload[0] != 2 or payload[236:240] != DHCP_COOKIE:
        return None
    options: dict[int, bytes] = {}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 0:  # relleno
            i += 1
            continue
        if code == 255 or i + 1 >= len(payload):
            break
        length = payload[i + 1]
        options.setdefault(code, payload[i + 2 : i + 2 + length])
        i += 2 + length

    def ip(code: int) -> str | None:
        value = options.get(code, b"")
        return ".".join(map(str, value[:4])) if len(value) >= 4 else None

    if options.get(53, b"\0")[:1] not in (b"\x02", b"\x05"):
        return None
    return {"server": ip(54), "router": ip(3), "dns": ip(6)}


PING_TIMESTAMP = 16


def detect_icmp_tunnel(packets: list[Packet], cfg: Config) -> list[Finding]:
    """Pings grandes y cada uno distinto: datos escondidos en ICMP (ptunnel, icmpsh...).

    Un ping normal lleva 32 o 56 bytes de relleno, siempre el mismo. Alguien que prueba la
    MTU manda pings grandes, pero también iguales. Si son grandes y cambian, llevan datos.
    """
    flows: dict[tuple, list[Packet]] = defaultdict(list)
    for p in packets:
        echo = (p.proto, p.icmp_type) in (("ICMP", 8), ("ICMP", 0), ("ICMPv6", 128), ("ICMPv6", 129))
        if echo and len(p.payload) >= cfg.icmp_min_payload:
            # pregunta y respuesta van al mismo flujo, ordenado por IP
            flows[tuple(sorted((p.src or "", p.dst or "")))].append(p)
    findings = []
    for (a, b), pkts in flows.items():
        # ping en Linux y macOS mete la hora en los 16 primeros bytes: cada ping es distinto ahí
        # aunque el resto sea el relleno de siempre. Lo que cuenta es lo que va detrás.
        distinct = len({p.payload[PING_TIMESTAMP:] for p in pkts})
        if len(pkts) < cfg.icmp_min_packets or distinct < len(pkts) // 2:
            continue
        src = Counter(p.src for p in pkts if p.icmp_type in (8, 128)).most_common(1)
        client = src[0][0] if src else a
        server = b if client == a else a
        size = sum(len(p.payload) for p in pkts)
        findings.append(
            Finding(
                Severity.HIGH,
                "icmp_tunnel",
                f"Posible túnel ICMP entre {client} y {server}",
                pkts[0].ts,
                pkts[-1].ts,
                f"{len(pkts)} pings de más de {cfg.icmp_min_payload} bytes, {distinct} con contenido distinto; "
                f"unos {size / 1024:.1f} KB dentro. Un ping normal lleva siempre el mismo relleno",
                client,
                server,
                "T1095 Non-Application Layer Protocol",
            )
        )
    return findings


DETECTORS = [
    detect_scans,
    detect_arp_spoofing,
    detect_dns_tunnel,
    detect_beaconing,
    detect_cleartext_credentials,
    detect_service_bruteforce,
    detect_suspicious_ports,
    detect_dga,
    detect_rogue_dhcp,
    detect_icmp_tunnel,
]


def run_detectors(packets: list[Packet], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings = [f for detector in DETECTORS for f in detector(packets, cfg)]
    return sorted(findings, key=lambda f: (-f.severity, f.first_seen))
