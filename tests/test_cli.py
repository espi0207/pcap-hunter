import json
import random
from pathlib import Path

from pcaphunter import craft
from pcaphunter.__main__ import main
from pcaphunter.analysis import analyze_capture
from pcaphunter.pcapfile import CaptureError, read_capture, write_pcap
from tests.test_pcapfile import pcapng

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "oficina.pcap"
EXPECTED = {
    "arp_spoofing",
    "beaconing",
    "cleartext_credentials",
    "dns_tunnel",
    "network_sweep",
    "port_scan",
}


def test_sample_capture_finds_every_attack(capsys):
    assert main([str(SAMPLE)]) == 1
    out = capsys.readouterr().out
    assert "cdn-telemetria.example" in out and "192.168.1.66" in out
    assert "Verano2026" not in out  # la contraseña del FTP no se imprime


def test_json_output(capsys):
    main([str(SAMPLE), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert {f["rule"] for f in data["findings"]} == EXPECTED
    assert data["packets"] > 1000 and data["malformed"] == 0


def test_same_result_from_pcapng(tmp_path):
    packets = [(p.ts, p.data) for p in read_capture(SAMPLE)]
    converted = tmp_path / "oficina.pcapng"
    converted.write_bytes(pcapng(packets=packets))
    assert {f.rule for f in analyze_capture(converted).findings} == EXPECTED


def test_errors(tmp_path, capsys):
    bad = tmp_path / "no.pcap"
    bad.write_text("hola")
    assert main([str(bad)]) == 2
    assert main([str(tmp_path / "no-existe.pcap")]) == 2
    assert "error" in capsys.readouterr().err


def test_clean_capture_exits_zero(tmp_path, capsys):
    lan = craft.Lan({"192.168.1.2": "00:00:00:00:00:02"}, gateway_mac="00:00:00:00:00:01")
    path = tmp_path / "limpia.pcap"
    write_pcap(path, lan.handshake(1.0, "192.168.1.2", "198.51.100.1", 50000, 443, b"x", b"y"))
    assert main([str(path)]) == 0
    assert "Sin hallazgos" in capsys.readouterr().out


def test_names_from_the_capture_are_escaped(tmp_path, capsys):
    lan = craft.Lan({"192.168.1.2": "00:00:00:00:00:02"}, gateway_mac="00:00:00:00:00:01")
    query = craft.dns_query(1, "x\x1b[2J.example")
    path = tmp_path / "rara.pcap"
    write_pcap(path, [(1.0, lan.udp("192.168.1.2", "192.168.1.1", 5000, 53, query))])
    main([str(path)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\\x1b[2j.example" in out  # el nombre DNS se pasa a minúsculas


def test_corrupted_captures_never_crash(tmp_path):
    """Captura de ejemplo con bytes cambiados al azar: o se lee lo que se pueda, o CaptureError."""
    original = SAMPLE.read_bytes()
    rng = random.Random(1234)
    path = tmp_path / "rota.pcap"
    for _ in range(150):
        data = bytearray(original)
        for _ in range(40):
            data[rng.randrange(24, len(data))] = rng.randrange(256)
        path.write_bytes(bytes(data[: rng.randrange(24, len(data))]))
        try:
            analyze_capture(path)
        except CaptureError:
            pass


def test_el_ejemplo_se_puede_regenerar_igual(tmp_path):
    # La ventana no lleva samples/oficina.pcap: lo genera al momento. Tiene que salir idéntico.
    from pcaphunter.sample import write_sample

    out = tmp_path / "oficina.pcap"
    assert write_sample(out) == 1678
    assert out.read_bytes() == SAMPLE.read_bytes()
