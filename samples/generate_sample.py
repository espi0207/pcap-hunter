"""Regenera samples/oficina.pcap (el código está en pcaphunter/sample.py).
Uso: python samples/generate_sample.py
"""

from pathlib import Path

from pcaphunter.sample import write_sample

OUT = Path(__file__).with_name("oficina.pcap")

if __name__ == "__main__":
    print(f"{OUT} generado: {write_sample(OUT)} paquetes")
