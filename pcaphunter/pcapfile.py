"""Lectura de capturas en formato pcap (el clásico de tcpdump) y pcapng (el de Wireshark).

Los dos formatos son sencillos una vez que se tiene la especificación delante:

- pcap: una cabecera global de 24 bytes y después, por cada paquete, 16 bytes de
  cabecera (segundos, microsegundos, longitud capturada y longitud real) y los datos.
  El número mágico del principio dice el orden de los bytes y si la hora va en
  micro o nanosegundos.
- pcapng: una sucesión de bloques (tipo, longitud, contenido, longitud otra vez). El
  bloque de sección dice el orden de los bytes, los de interfaz dicen el tipo de enlace
  y la resolución de la hora, y los paquetes van en bloques EPB (o SPB, los simples).

Referencias: https://www.tcpdump.org/manpages/pcap-savefile.5.html y
https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER = 0x1A2B3C4D
MAX_PACKET = 256 * 1024  # más que cualquier snaplen razonable: si no, el archivo está roto


class CaptureError(Exception):
    pass


@dataclass(frozen=True)
class RawPacket:
    ts: float  # segundos desde 1970, con decimales
    linktype: int  # 1 = Ethernet, 113 = Linux "cooked"... ver decode.py
    data: bytes
    orig_len: int


def read_capture(path: Path | str) -> Iterator[RawPacket]:
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if head in PCAP_MAGICS:
            yield from _read_pcap(fh)
        elif len(head) == 4 and struct.unpack("<I", head)[0] == PCAPNG_SHB:
            yield from _read_pcapng(fh)
        else:
            raise CaptureError("no es un archivo pcap ni pcapng")


def _read_pcap(fh) -> Iterator[RawPacket]:
    header = fh.read(24)
    if len(header) < 24:
        raise CaptureError("la cabecera del pcap está incompleta")
    endian, resolution = PCAP_MAGICS[header[:4]]
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF  # los bits altos son flags
    record = struct.Struct(endian + "IIII")
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return  # fin del archivo (o un último paquete cortado: tcpdump matado a mitad)
        sec, frac, incl_len, orig_len = record.unpack(rec)
        if incl_len > MAX_PACKET:
            raise CaptureError(f"un paquete dice medir {incl_len} bytes: el archivo está dañado")
        data = fh.read(incl_len)
        if len(data) < incl_len:
            return
        yield RawPacket(sec + frac * resolution, linktype, data, orig_len)


def _tsresol(options: bytes, endian: str) -> float:
    """Resolución de la hora de una interfaz (opción if_tsresol). Por defecto, microsegundos."""
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos : pos + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[pos + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0**-value
        pos += 4 + length + (-length % 4)
    return 1e-6


def _read_pcapng(fh) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: list[tuple[int, float, int]] = []  # (linktype, resolución, snaplen)
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        block_type = struct.unpack("<I", head[:4])[0]
        if block_type == PCAPNG_SHB:
            # El orden de los bytes se decide aquí, con el "byte-order magic" del bloque.
            magic = fh.read(4)
            if len(magic) < 4:
                return
            endian = "<" if struct.unpack("<I", magic)[0] == PCAPNG_BYTE_ORDER else ">"
            total = struct.unpack(endian + "I", head[4:8])[0]
            if total < 28 or total % 4 or total > 1024 * 1024:
                raise CaptureError(f"bloque de sección pcapng con longitud imposible ({total})")
            fh.read(total - 12)  # versión, longitud de la sección y opciones: no hacen falta
            interfaces = []  # cada sección tiene sus propias interfaces
            continue
        block_type, total = struct.unpack(endian + "II", head)
        if total < 12 or total % 4 or total > MAX_PACKET + 64:
            raise CaptureError(f"bloque pcapng con longitud imposible ({total})")
        body = fh.read(total - 8)
        if len(body) < total - 8:
            return
        body = body[:-4]  # la longitud repetida del final

        if block_type == 1:  # Interface Description Block
            linktype, _, snaplen = struct.unpack(endian + "HHI", body[:8])
            interfaces.append((linktype, _tsresol(body[8:], endian), snaplen))
        elif block_type == 6:  # Enhanced Packet Block
            iface, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            if iface >= len(interfaces):
                continue
            linktype, resolution, _ = interfaces[iface]
            ts = ((ts_high << 32) | ts_low) * resolution
            yield RawPacket(ts, linktype, body[20 : 20 + cap_len], orig_len)
        elif block_type == 3 and interfaces:  # Simple Packet Block: sin hora ni interfaz
            (orig_len,) = struct.unpack(endian + "I", body[:4])
            linktype, _, snaplen = interfaces[0]
            cap_len = min(orig_len, snaplen) if snaplen else orig_len
            yield RawPacket(0.0, linktype, body[4 : 4 + cap_len], orig_len)
        # el resto de bloques (estadísticas, nombres resueltos, comentarios) no hacen falta


def write_pcap(path: Path | str, packets: list[tuple[float, bytes]], linktype: int = 1) -> None:
    """Escribe un pcap clásico. Lo usan el generador de ejemplos y las pruebas."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, data in packets:
            sec, usec = divmod(round(ts * 1e6), 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)
