"""Informe en texto (terminal) y JSON."""

from __future__ import annotations

import json
from datetime import datetime

from .analysis import Analysis
from .ansi import clean, paint
from .detectors import Severity

COLOR = {Severity.CRITICAL: "bright_red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "blue"}
INDENT = " " * 10


def _time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def to_text(analysis: Analysis, source: str) -> str:
    out = [paint(f"pcap-hunter: {source}", "bold", "cyan")]
    if analysis.packets:
        start = datetime.fromtimestamp(analysis.packets[0].ts)
        minutes = analysis.duration / 60
        out.append(paint(f"{start:%Y-%m-%d %H:%M:%S} (hora local), {minutes:.1f} minutos de tráfico", "gray"))
    total_bytes = sum(p.length for p in analysis.packets)
    protocols = ", ".join(f"{name} {n}" for name, n in analysis.protocols().most_common(6))
    out.append(f"{paint(str(len(analysis.packets)), 'bold')} paquetes ({_size(total_bytes)}): {protocols}")
    if analysis.malformed:
        out.append(paint(f"{analysis.malformed} paquete(s) mal formados se han saltado", "yellow"))
    for linktype, n in analysis.unsupported.items():
        out.append(paint(f"{n} paquete(s) con un tipo de enlace que no sé leer ({linktype})", "yellow"))
    out.append("")

    if not analysis.findings:
        out.append(paint("Sin hallazgos.", "green"))
    for f in analysis.findings:
        tag = paint(f"[{f.severity.label}]".ljust(len(INDENT)), "bold", COLOR[f.severity])
        span = _time(f.first_seen) + (f" -> {_time(f.last_seen)}" if f.last_seen - f.first_seen >= 1 else "")
        out.append(f"{tag}{paint(clean(f.title), 'bold')}")
        out.append(INDENT + paint(span + (f"  ({f.mitre})" if f.mitre else ""), "gray"))
        out.append(INDENT + clean(f.details))
        out.append("")

    talkers = ", ".join(f"{ip} ({_size(n)})" for ip, n in analysis.top_talkers())
    if talkers:
        out.append(f"{paint('Quién más envía:', 'bold')}      {talkers}")
    domains = ", ".join(f"{clean(d)} ({n})" for d, n in analysis.top_domains())
    if domains:
        out.append(f"{paint('Dominios más pedidos:', 'bold')}  {domains}")
    return "\n".join(out).rstrip()


def to_json(analysis: Analysis, source: str) -> str:
    return json.dumps(
        {
            "source": source,
            "packets": len(analysis.packets),
            "malformed": analysis.malformed,
            "duration": analysis.duration,
            "protocols": dict(analysis.protocols()),
            "top_talkers": analysis.top_talkers(),
            "top_domains": analysis.top_domains(),
            "findings": [f.to_dict() for f in analysis.findings],
        },
        indent=2,
        ensure_ascii=False,
    )
