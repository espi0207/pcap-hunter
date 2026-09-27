"""La captura de ejemplo: 40 minutos de tráfico inventado en la red de una oficina
pequeña, con varios ataques mezclados entre el tráfico normal.

La red interna es 192.168.1.0/24 y todo lo de fuera usa los rangos reservados para
documentación (RFC 5737) y dominios .example, así que no apunta a nadie real. Está dentro
del paquete para que la ventana pueda abrirla sin llevar el .pcap a cuestas.
"""

from __future__ import annotations

import base64
import random
from datetime import datetime, timezone
from pathlib import Path

from .craft import BROADCAST, Lan, dns_answer, dns_query
from .decode import ACK, RST, SYN
from .pcapfile import write_pcap

ROUTER, SERVER, INTRANET = "192.168.1.1", "192.168.1.10", "192.168.1.5"
INFECTED, EMPLOYEE, OTHER, ATTACKER = "192.168.1.23", "192.168.1.30", "192.168.1.41", "192.168.1.66"
C2 = "203.0.113.50"
MACS = {
    ROUTER: "00:1a:2b:00:00:01",
    INTRANET: "00:1a:2b:00:00:05",
    SERVER: "00:1a:2b:00:00:10",
    INFECTED: "3c:52:82:00:00:23",
    EMPLOYEE: "3c:52:82:00:00:30",
    OTHER: "3c:52:82:00:00:41",
    ATTACKER: "de:ad:be:ef:00:66",
}
NORMAL_SITES = ["www.wikipedia.org", "github.com", "outlook.office365.com", "fonts.googleapis.com", "www.bbc.co.uk"]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]


def write_sample(out: Path | str) -> int:
    """Escribe la captura de ejemplo en `out` y devuelve cuántos paquetes tiene. Siempre sale
    igual (semilla fija y hora fija), así que es la misma que samples/oficina.pcap."""
    rng = random.Random(2026)
    lan = Lan(MACS, gateway_mac=MACS[ROUTER])
    t0 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc).timestamp()  # las 10:00 en España
    frames: list[tuple[float, bytes]] = []
    port = iter(range(49152, 65535))

    def browse(t: float, client: str) -> None:
        """Una visita normal: pregunta DNS al router y abre una conexión HTTPS."""
        site = rng.choice(NORMAL_SITES)
        ident = rng.randint(0, 0xFFFF)
        server = f"198.51.100.{rng.randint(10, 200)}"
        dport = next(port)
        frames.append((t, lan.udp(client, ROUTER, dport, 53, dns_query(ident, site))))
        frames.append((t + 0.015, lan.udp(ROUTER, client, 53, dport, dns_answer(ident, site, server))))
        frames.extend(lan.handshake(t + 0.02, client, server, next(port), 443, rng.randbytes(300), rng.randbytes(1200)))

    # Tráfico normal: tres equipos navegando a ratos durante 40 minutos.
    for client in (INFECTED, EMPLOYEE, OTHER):
        t = t0 + rng.uniform(0, 20)
        while t < t0 + 2400:
            browse(t, client)
            t += rng.expovariate(1 / 45)

    # Al principio cada equipo anuncia su MAC (ARP normal).
    for i, (ip, mac) in enumerate(MACS.items()):
        frames.append((t0 + 1 + i * 0.1, lan.arp_reply(mac, ip, ip, BROADCAST)))

    # 1) Escaneo de puertos: el atacante prueba los puertos típicos del servidor. Nmap -sS:
    #    a los que responden abiertos les contesta con RST, sin terminar la conexión.
    t = t0 + 300
    for dport in COMMON_PORTS * 3 + list(range(8000, 8020)):
        t += rng.uniform(0.001, 0.01)
        sport = 40000 + dport % 1000
        frames.append((t, lan.tcp(ATTACKER, SERVER, sport, dport, SYN, seq=7)))
        if dport in (22, 80, 443, 445):
            frames.append((t + 0.0005, lan.tcp(SERVER, ATTACKER, dport, sport, SYN | ACK, seq=9, ack=8)))
            frames.append((t + 0.0007, lan.tcp(ATTACKER, SERVER, sport, dport, RST, seq=8)))
        else:
            frames.append((t + 0.0005, lan.tcp(SERVER, ATTACKER, dport, sport, RST | ACK, ack=8)))

    # 2) Barrido de la red buscando SMB (445), el puerto de WannaCry.
    t = t0 + 420
    for host in range(2, 60):
        t += rng.uniform(0.01, 0.05)
        target = f"192.168.1.{host}"
        frames.append((t, lan.tcp(ATTACKER, target, 45000 + host, 445, SYN)))
        if target in (SERVER, INTRANET):
            frames.append((t + 0.001, lan.tcp(target, ATTACKER, 445, 45000 + host, SYN | ACK, ack=1)))

    # 3) ARP spoofing: el atacante dice a los demás que la IP del router es su MAC, para
    #    que todo el tráfico hacia internet pase por él (man-in-the-middle).
    t = t0 + 600
    for _ in range(15):
        for victim in (INFECTED, EMPLOYEE, OTHER):
            frames.append((t, lan.arp_reply(MACS[ATTACKER], ROUTER, victim)))
        t += 2

    # 4) Credenciales en claro: FTP, una intranet con autenticación Basic y un formulario.
    t = t0 + 700
    ftp = "198.51.100.21"
    cport = next(port)
    frames.extend(lan.handshake(t, EMPLOYEE, ftp, cport, 21))
    frames.append((t + 1, lan.tcp(EMPLOYEE, ftp, cport, 21, ACK | 0x08, b"USER jgarcia\r\n", 1001, 5001)))
    frames.append((t + 2, lan.tcp(EMPLOYEE, ftp, cport, 21, ACK | 0x08, b"PASS Verano2026!\r\n", 1015, 5001)))

    basic = base64.b64encode(b"admin:Adm1nistrador").decode()
    request = f"GET /admin/ HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic {basic}\r\n\r\n".encode()
    frames.extend(lan.handshake(t + 30, EMPLOYEE, INTRANET, next(port), 80, request, b"HTTP/1.1 200 OK\r\n\r\n"))
    form = b"usuario=maria.lopez&password=Gatito%2A2024&enviar=Entrar"
    post = (
        b"POST /login HTTP/1.1\r\nHost: intranet\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(form)}\r\n\r\n".encode()
        + form
    )
    frames.extend(lan.handshake(t + 90, OTHER, INTRANET, next(port), 80, post, b"HTTP/1.1 302 Found\r\n\r\n"))

    # 5) Beaconing: el equipo infectado se conecta a su servidor de control cada 2 minutos,
    #    con un poco de variación para disimular.
    t = t0 + 45
    while t < t0 + 2400:
        frames.extend(lan.handshake(t, INFECTED, C2, next(port), 443, rng.randbytes(90), rng.randbytes(40)))
        t += 120 + rng.uniform(-4, 4)

    # 6) Túnel DNS: el mismo equipo saca un archivo codificado en subdominios de un dominio
    #    del atacante. Cada consulta lleva un trozo en base32.
    stolen = rng.randbytes(2400)
    t = t0 + 1500
    for i in range(0, len(stolen), 30):
        chunk = base64.b32encode(stolen[i : i + 30]).decode().rstrip("=").lower()
        name = f"{chunk}.{i // 30}.cdn-telemetria.example"
        ident = rng.randint(0, 0xFFFF)
        dport = next(port)
        frames.append((t, lan.udp(INFECTED, ROUTER, dport, 53, dns_query(ident, name, qtype=16))))
        t += rng.uniform(0.2, 0.8)

    frames.sort(key=lambda f: f[0])
    write_pcap(out, frames)
    return len(frames)
