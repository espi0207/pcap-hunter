"""Línea de comandos: pcaphunter captura.pcap [--format json]."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze_capture
from .detectors import Severity
from .pcapfile import CaptureError
from .report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcaphunter",
        description="Busca ataques y malas prácticas en capturas de red (pcap y pcapng)",
    )
    p.add_argument("captures", nargs="+", type=Path, help="archivos .pcap o .pcapng")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--version", action="version", version=f"pcaphunter {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    worst = 0
    for i, path in enumerate(args.captures):
        try:
            analysis = analyze_capture(path)
        except CaptureError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"error: no se pudo leer {path}: {exc.strerror}", file=sys.stderr)
            return 2
        if i:
            print()
        print(to_json(analysis, str(path)) if args.format == "json" else to_text(analysis, str(path)))
        worst = max([worst, *(f.severity for f in analysis.findings)])
    # Como en las otras herramientas: código 1 si hay algo de prioridad alta o crítica.
    return 1 if worst >= Severity.HIGH else 0


if __name__ == "__main__":
    sys.exit(main())
