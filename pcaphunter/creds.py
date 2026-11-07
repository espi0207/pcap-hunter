"""Credenciales que viajan en claro por protocolos sin cifrar.

Cualquiera que esté en la misma red (una wifi pública, un switch con el puerto espejo,
un equipo comprometido haciendo ARP spoofing) puede leerlas igual que las lee esto.

No se reconstruyen los flujos TCP: se mira cada paquete por separado. Para lo que se
busca aquí vale, porque estos comandos son cortos y caben en un solo segmento.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import parse_qs

from .decode import Packet

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")
PASSWORD_FIELDS = ("password", "passwd", "pass", "pwd", "contrasena", "clave")
USER_FIELDS = ("username", "user", "login", "email", "usuario")
IMAP_LOGIN = re.compile(r'^\S+ LOGIN ("[^"]*"|\S+) ("[^"]*"|\S+)', re.IGNORECASE)


@dataclass(frozen=True)
class Credential:
    protocol: str
    user: str | None
    secret: str
    kind: str = "contraseña"  # o "token"


def _b64(text: str) -> str | None:
    try:
        return base64.b64decode(text.strip(), validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _http(payload: bytes) -> list[Credential]:
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    found = []
    auth = headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() == "basic" and (decoded := _b64(value)) and ":" in decoded:
        user, _, password = decoded.partition(":")
        found.append(Credential("HTTP Basic", user, password))
    elif scheme.lower() == "bearer" and value:
        found.append(Credential("HTTP Bearer", None, value, kind="token"))
    if lines[0].startswith("POST ") and "x-www-form-urlencoded" in headers.get("content-type", ""):
        form = {k.lower(): v[0] for k, v in parse_qs(body.decode("utf-8", errors="replace")).items()}
        password = next((form[f] for f in PASSWORD_FIELDS if f in form), None)
        if password:
            user = next((form[f] for f in USER_FIELDS if f in form), None)
            found.append(Credential("formulario HTTP", user, password))
    return found


class CredentialSniffer:
    """Busca credenciales paquete a paquete. Guarda estado por conexión: en FTP y POP3 el
    usuario y la contraseña van en dos comandos (USER y PASS), y en SMTP AUTH LOGIN van
    en dos líneas en base64 después del comando."""

    def __init__(self) -> None:
        self._pending_user: dict[tuple, str] = {}
        self._smtp_login: dict[tuple, list[str]] = {}
        self._smtp_plain: set[tuple] = set()  # "AUTH PLAIN" sin datos: llegan en la línea siguiente

    def feed(self, pkt: Packet) -> list[Credential]:
        if pkt.proto == "UDP" and pkt.dport in (161, 162) and pkt.payload:
            return _snmp(pkt.payload)
        if pkt.proto != "TCP" or not pkt.payload:
            return []
        payload = pkt.payload
        if payload.startswith(HTTP_METHODS):
            return _http(payload)
        conn = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
        # Un segmento puede llevar varios comandos ("USER ana\r\nPASS secreto\r\n"): uno a uno.
        found = []
        for line in payload.decode("latin-1").splitlines():
            if line := line.strip():
                found += self._line(conn, pkt.dport, line)
        return found

    def _line(self, conn: tuple, dport: int | None, text: str) -> list[Credential]:
        command, _, arg = text.partition(" ")
        command = command.upper()

        if dport in (21, 110):  # FTP y POP3
            protocol = "FTP" if dport == 21 else "POP3"
            if command == "USER":
                self._pending_user[conn] = arg
            elif command == "PASS":
                user = self._pending_user.pop(conn, None)
                # el FTP anónimo no tiene secreto (en POP3 "ftp" es una cuenta como otra)
                if protocol != "FTP" or (user or "").lower() not in ("anonymous", "ftp"):
                    return [Credential(protocol, user, arg)]
        elif dport == 143:  # IMAP: "a1 LOGIN usuario contraseña"
            if m := IMAP_LOGIN.match(text):
                return [Credential("IMAP", m.group(1).strip('"'), m.group(2).strip('"'))]
        elif dport in (25, 587):  # SMTP
            if conn in self._smtp_plain:
                self._smtp_plain.discard(conn)
                return _smtp_plain(text)
            if conn in self._smtp_login:
                self._smtp_login[conn].append(_b64(text) or text)
                if len(self._smtp_login[conn]) == 2:
                    user, password = self._smtp_login.pop(conn)
                    return [Credential("SMTP AUTH LOGIN", user, password)]
            elif command == "AUTH":
                mechanism, _, initial = arg.partition(" ")
                if mechanism.upper() == "PLAIN":
                    if initial and initial != "=":
                        return _smtp_plain(initial)
                    self._smtp_plain.add(conn)  # el cliente espera el "334" y lo manda después
                elif mechanism.upper() == "LOGIN":
                    # El usuario puede venir ya en el mismo comando ("AUTH LOGIN dXN1YXJpbw==").
                    self._smtp_login[conn] = [_b64(initial) or initial] if initial else []
        return []


def _smtp_plain(blob: str) -> list[Credential]:
    # PLAIN: base64 de "\0usuario\0contraseña" (RFC 4616)
    decoded = _b64(blob)
    parts = decoded.split("\0") if decoded else []
    return [Credential("SMTP AUTH PLAIN", parts[1], parts[2])] if len(parts) == 3 else []


def _ber_length(data: bytes, pos: int) -> tuple[int, int]:
    """Longitud BER (forma corta o larga) en `pos`: devuelve (longitud, dónde empieza el valor)."""
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    n = first & 0x7F
    if not 1 <= n <= 2 or pos + 1 + n > len(data):
        raise ValueError("longitud BER rara")
    return int.from_bytes(data[pos + 1 : pos + 1 + n], "big"), pos + 1 + n


def _snmp(payload: bytes) -> list[Credential]:
    """SNMP v1 y v2c mandan la "comunidad" (que hace de contraseña) en claro en cada paquete.

    El mensaje es BER: SEQUENCE { INTEGER versión, OCTET STRING comunidad, ... } (RFC 1157).
    """
    try:
        if payload[0] != 0x30:
            return []
        _, pos = _ber_length(payload, 1)
        if payload[pos : pos + 2] != b"\x02\x01" or payload[pos + 2] not in (0, 1):
            return []  # v3 no lleva comunidad
        version = "SNMPv1" if payload[pos + 2] == 0 else "SNMPv2c"
        if payload[pos + 3] != 0x04:
            return []
        length, start = _ber_length(payload, pos + 4)
        community = payload[start : start + length]
        if len(community) != length or not community:
            return []
    except (IndexError, ValueError):
        return []
    return [Credential(version, None, community.decode("utf-8", errors="replace"), "comunidad")]


def mask(secret: str) -> str:
    return f"{secret[:1]}… ({len(secret)} caracteres)" if secret else "(vacía)"
