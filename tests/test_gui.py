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


@pytest.mark.skipif(
    sys.platform.startswith("linux") and not os.environ.get("DISPLAY"),
    reason="en Linux hace falta una pantalla (en la CI, xvfb-run)",
)
def test_failed_open_keeps_the_previous_capture_and_its_name(tmp_path, monkeypatch):
    # Abrir A (bien) y luego B (mal): el informe que se guarde tiene que seguir siendo de A y llamarse A.
    import time

    from pcaphunter.sample import write_sample

    monkeypatch.setattr(gui.messagebox, "showerror", lambda *a, **k: None)
    good, bad = tmp_path / "buena.pcap", tmp_path / "mala.pcap"
    write_sample(good)
    bad.write_bytes(b"esto no es una captura")
    root = tk.Tk()
    try:
        app = gui.App(root, None)
        for path in (good, bad):
            app.open(path)
            deadline = time.time() + 20
            while app.busy and time.time() < deadline:
                root.update()
                time.sleep(0.02)
        assert app.analysis is not None
        assert app.source == good
        assert app.source_label.cget("text") == str(good)
    finally:
        root.destroy()
