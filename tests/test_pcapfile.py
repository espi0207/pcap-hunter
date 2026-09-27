import struct

import pytest

from pcaphunter.pcapfile import CaptureError, read_capture, write_pcap

FRAME = bytes(range(60))


def pcapng(endian: str = "<", tsresol: int | None = None, packets=((1.5, FRAME),), linktype: int = 1) -> bytes:
    """Un pcapng mínimo: sección, una interfaz y paquetes EPB."""

    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        total = 12 + len(body)
        return struct.pack(endian + "II", kind, total) + body + struct.pack(endian + "I", total)

    shb = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = b""
    if tsresol is not None:
        options = struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\0\0\0" + struct.pack(endian + "HH", 0, 0)
    idb = block(1, struct.pack(endian + "HHI", linktype, 0, 65535) + options)
    scale = 10**9 if tsresol == 9 else 10**6
    epbs = b""
    for ts, data in packets:
        units = round(ts * scale)
        epbs += block(6, struct.pack(endian + "IIIII", 0, units >> 32, units & 0xFFFFFFFF, len(data), len(data)) + data)
    return shb + idb + epbs


def test_pcap_roundtrip(tmp_path):
    path = tmp_path / "a.pcap"
    write_pcap(path, [(1_700_000_000.25, FRAME), (1_700_000_001.5, FRAME[:20])])
    packets = list(read_capture(path))
    assert [p.ts for p in packets] == [1_700_000_000.25, 1_700_000_001.5]
    assert packets[0].data == FRAME and packets[0].linktype == 1


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcap_big_and_little_endian_and_nanoseconds(tmp_path, endian):
    header = struct.pack(endian + "IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)  # magia de nanosegundos
    record = struct.pack(endian + "IIII", 100, 500_000_000, len(FRAME), len(FRAME)) + FRAME
    path = tmp_path / "a.pcap"
    path.write_bytes(header + record)
    [packet] = read_capture(path)
    assert packet.ts == 100.5 and packet.data == FRAME


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng(tmp_path, endian):
    path = tmp_path / "a.pcapng"
    path.write_bytes(pcapng(endian))
    [packet] = read_capture(path)
    assert packet.ts == 1.5 and packet.data == FRAME and packet.linktype == 1


def test_pcapng_nanosecond_resolution(tmp_path):
    path = tmp_path / "a.pcapng"
    path.write_bytes(pcapng(tsresol=9, packets=[(1_700_000_000.123456789, FRAME)]))
    [packet] = read_capture(path)
    assert abs(packet.ts - 1_700_000_000.123456789) < 1e-6


def test_truncated_capture_stops_quietly(tmp_path):
    path = tmp_path / "a.pcap"
    write_pcap(path, [(1.0, FRAME), (2.0, FRAME)])
    path.write_bytes(path.read_bytes()[:-10])  # tcpdump cortado a mitad del último paquete
    assert len(list(read_capture(path))) == 1


def test_not_a_capture(tmp_path):
    path = tmp_path / "foto.jpg"
    path.write_bytes(b"\xff\xd8\xff\xe0 no soy una captura")
    with pytest.raises(CaptureError):
        list(read_capture(path))


def test_absurd_packet_length_is_rejected(tmp_path):
    path = tmp_path / "a.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(header + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF))
    with pytest.raises(CaptureError):
        list(read_capture(path))
