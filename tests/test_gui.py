import os
import sys

import pytest

tk = pytest.importorskip("tkinter")

from pcaphunter import gui  # noqa: E402


@pytest.mark.skipif(
    sys.platform.startswith("linux") and not os.environ.get("DISPLAY"),
    reason="en Linux hace falta una pantalla (en la CI, xvfb-run)",
)
def test_la_ventana_funciona():
    # Lo mismo que hace la CI con el programa ya instalado: abrir la ventana con la captura de ejemplo
    # y comprobar que salen todos los hallazgos.
    assert gui.self_check() == 0
