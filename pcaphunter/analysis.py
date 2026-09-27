"""Junta las piezas: lee la captura, decodifica los paquetes, saca estadísticas y pasa los detectores."""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .decode import MalformedPacket, Packet, decode
from .detectors import Config, Finding, run_detectors
from .pcapfile import read_capture


@dataclass
class Analysis:
    packets: list[Packet]
    malformed: int = 0
    unsupported: Counter = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.packets[-1].ts - self.packets[0].ts if self.packets else 0.0

    def protocols(self) -> Counter:
        return Counter("ARP" if p.arp else p.proto or "otro" for p in self.packets)

    def top_talkers(self, n: int = 5) -> list[tuple[str, int]]:
        """Las IPs que más bytes envían."""
        sent: Counter = Counter()
        for p in self.packets:
            if p.src:
                sent[p.src] += p.length
        return sent.most_common(n)

    def top_domains(self, n: int = 5) -> list[tuple[str, int]]:
        return Counter(p.dns.qname for p in self.packets if p.dns and not p.dns.response).most_common(n)


def analyze_capture(path: Path | str, cfg: Config | None = None) -> Analysis:
    packets, malformed, unsupported = [], 0, Counter()
    for raw in read_capture(path):
        try:
            packets.append(decode(raw.ts, raw.linktype, raw.data, raw.orig_len))
        except MalformedPacket as exc:
            if "no soportado" in str(exc):
                unsupported[raw.linktype] += 1
            else:
                malformed += 1
        except (struct.error, IndexError, ValueError):
            malformed += 1
    packets.sort(key=lambda p: p.ts)
    analysis = Analysis(packets, malformed, unsupported)
    analysis.findings = run_detectors(packets, cfg)
    return analysis
