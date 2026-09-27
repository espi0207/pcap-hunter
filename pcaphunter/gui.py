"""La ventana de pcap-hunter: abrir una captura y ver lo que ha encontrado.

Tkinter viene con Python, así que no hace falta instalar nada más. El análisis va en un
hilo aparte para que la ventana no se congele con una captura grande; Tkinter no se puede
tocar desde otro hilo, así que el resultado llega por una cola que la ventana mira cada
100 ms.
"""

from __future__ import annotations

import os
import queue
import sys
import tempfile
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from . import __version__
from .analysis import Analysis, analyze_capture
from .detectors import Finding, Severity
from .pcapfile import CaptureError
from .report import to_json, to_text
from .sample import write_sample

ICON = Path(__file__).with_name("icon.png")
CAPTURES = [("Capturas de red", "*.pcap *.pcapng *.cap"), ("Todos los archivos", "*")]
# Colores de fondo suaves por gravedad, legibles con texto negro.
ROW_COLORS = {
    Severity.CRITICAL: "#fecaca",
    Severity.HIGH: "#fed7aa",
    Severity.MEDIUM: "#fef08a",
    Severity.LOW: "#dbeafe",
}


def _time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}".replace(".", ",")
        n /= 1024
    return ""


class App:
    def __init__(self, root: tk.Tk, capture: Path | None):
        self.root = root
        self.analysis: Analysis | None = None
        self.source: Path | None = None
        self.findings: dict[str, Finding] = {}
        self.jobs: queue.Queue = queue.Queue()
        self.busy = False
        # Los informes de texto llevan colores si la salida es una terminal (y la ventana se
        # puede abrir desde una): al guardarlos en un archivo no tienen que ir.
        os.environ["NO_COLOR"] = "1"

        root.title("pcap-hunter")
        root.geometry("980x640")
        root.minsize(700, 460)
        if ICON.exists():
            root.iconphoto(True, tk.PhotoImage(file=str(ICON)))
        self.build()
        root.after(100, self.poll)
        if capture:
            self.open(capture)
        else:
            self.info.config(text="Abre una captura (.pcap o .pcapng) o prueba con la de ejemplo.")

    # La ventana

    def build(self) -> None:
        root = self.root
        style = ttk.Style(root)
        if style.theme_use() == "default" and "clam" in style.theme_names():
            style.theme_use("clam")  # en Linux el de por defecto es de los noventa
        bold = tkfont.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold")
        line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
        style.configure("Treeview", rowheight=line + 8)
        style.configure("Accent.TButton", font=bold)

        menu = tk.Menu(root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Abrir captura…", command=self.choose, accelerator="Ctrl+O")
        file_menu.add_command(label="Abrir la captura de ejemplo", command=self.open_sample)
        file_menu.add_command(label="Guardar informe…", command=self.save, accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=root.destroy)
        menu.add_cascade(label="Archivo", menu=file_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Acerca de pcap-hunter", command=self.about)
        menu.add_cascade(label="Ayuda", menu=help_menu)
        root.config(menu=menu)
        root.bind_all("<Control-o>", lambda _: self.choose())
        root.bind_all("<Control-s>", lambda _: self.save())

        top = ttk.Frame(root, padding=(14, 12, 14, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Captura:").pack(side="left")
        self.source_label = ttk.Label(top, text="(ninguna)", font=bold)
        self.source_label.pack(side="left", padx=(6, 10), fill="x", expand=True)
        ttk.Button(top, text="Ejemplo", command=self.open_sample).pack(side="right")
        ttk.Button(top, text="Abrir…", command=self.choose, style="Accent.TButton").pack(side="right", padx=(0, 8))

        self.info = ttk.Label(root, padding=(14, 2, 14, 8), foreground="#4b5563")
        self.info.pack(fill="x")

        self.tabs = ttk.Notebook(root, padding=(14, 0))
        self.tabs.pack(fill="both", expand=True)

        # Pestaña de hallazgos: la lista arriba y el detalle del seleccionado abajo.
        found = ttk.Frame(self.tabs)
        self.tabs.add(found, text="Hallazgos")
        panes = ttk.PanedWindow(found, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(8, 0))
        table = ttk.Frame(panes)
        columns = ("severity", "title", "src", "dst", "when")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", selectmode="browse")
        for column, text, width, stretch in (
            ("severity", "Gravedad", 90, False),
            ("title", "Qué ha pasado", 420, True),
            ("src", "Origen", 130, False),
            ("dst", "Destino", 130, False),
            ("when", "Cuándo", 150, False),
        ):
            self.tree.heading(column, text=text, anchor="w")
            self.tree.column(column, width=width, stretch=stretch)
        for severity, color in ROW_COLORS.items():
            self.tree.tag_configure(severity.label, background=color, foreground="#111827")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self.show_detail())
        panes.add(table, weight=3)

        self.detail = tk.Text(panes, height=7, wrap="word", relief="flat", padx=10, pady=8, font="TkDefaultFont")
        self.detail.tag_configure("title", font=bold)
        self.detail.configure(state="disabled")
        panes.add(self.detail, weight=1)

        # Pestaña de resumen: quién envía más y qué dominios se piden.
        summary = ttk.Frame(self.tabs, padding=(0, 8))
        self.tabs.add(summary, text="Resumen")
        self.talkers = self._small_table(summary, "Quién envía más", ("IP", "Enviado"))
        self.domains = self._small_table(summary, "Dominios más pedidos", ("Dominio", "Consultas"))
        self.protocols = self._small_table(summary, "Protocolos", ("Protocolo", "Paquetes"))

        bottom = ttk.Frame(root, padding=(14, 8, 14, 12))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=100)
        self.status = ttk.Label(bottom, foreground="#4b5563")
        self.status.pack(side="left")
        self.save_button = ttk.Button(bottom, text="Guardar informe…", command=self.save)
        self.save_button.pack(side="right")
        self.save_button.state(["disabled"])

    def _small_table(self, parent, title: str, headings: tuple[str, str]) -> ttk.Treeview:
        frame = ttk.LabelFrame(parent, text=title, padding=6)
        frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tree = ttk.Treeview(frame, columns=("a", "b"), show="headings", height=8)
        tree.heading("a", text=headings[0], anchor="w")
        tree.heading("b", text=headings[1], anchor="e")
        tree.column("a", width=180, stretch=True)
        tree.column("b", width=90, stretch=False, anchor="e")
        tree.pack(fill="both", expand=True)
        return tree

    def show_analysis(self, analysis: Analysis) -> None:
        self.analysis = analysis
        packets = analysis.packets
        if packets:
            start = datetime.fromtimestamp(packets[0].ts)
            total = _size(sum(p.length for p in packets))
            minutes = f"{analysis.duration / 60:.1f}".replace(".", ",")
            text = f"{len(packets)} paquetes ({total}) en {minutes} minutos, desde el {start:%d/%m/%Y a las %H:%M}"
        else:
            text = "La captura no tiene paquetes que se puedan leer"
        if analysis.malformed:
            text += f". {analysis.malformed} mal formados, saltados"
        self.info.config(text=text + ".")

        self.tree.delete(*self.tree.get_children())
        self.findings.clear()
        for finding in sorted(analysis.findings, key=lambda f: (-f.severity, f.first_seen)):
            span = _time(finding.first_seen)
            if finding.last_seen - finding.first_seen >= 1:
                span += f" – {_time(finding.last_seen)}"
            values = (finding.severity.label, finding.title, finding.src or "", finding.dst or "", span)
            item = self.tree.insert("", "end", values=values, tags=(finding.severity.label,))
            self.findings[item] = finding
        count = len(analysis.findings)
        self.tabs.tab(0, text=f"Hallazgos ({count})")
        worst = max((f.severity for f in analysis.findings), default=None)
        if count:
            self.status.config(
                text=f"{count} hallazgo{'s' if count != 1 else ''}; el más grave, {worst.label.lower()}."
            )
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
        else:
            self.status.config(text="Sin hallazgos: no se ha visto nada raro.")
            self.show_detail()

        for tree, rows in (
            (self.talkers, [(ip, _size(n)) for ip, n in analysis.top_talkers(10)]),
            (self.domains, analysis.top_domains(10)),
            (self.protocols, analysis.protocols().most_common()),
        ):
            tree.delete(*tree.get_children())
            for row in rows:
                tree.insert("", "end", values=row)
        self.save_button.state(["!disabled"])

    def show_detail(self) -> None:
        selected = self.tree.selection()
        finding = self.findings.get(selected[0]) if selected else None
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if finding:
            self.detail.insert("end", finding.title + "\n", "title")
            meta = [
                f"Gravedad: {finding.severity.label.lower()}",
                f"de {_time(finding.first_seen)} a {_time(finding.last_seen)}",
            ]
            if finding.mitre:
                meta.append(f"MITRE ATT&CK {finding.mitre}")
            self.detail.insert("end", " · ".join(meta) + "\n\n")
            self.detail.insert("end", finding.details)
        self.detail.configure(state="disabled")

    # Lo que hacen los botones

    def choose(self) -> None:
        if self.busy:
            return
        chosen = filedialog.askopenfilename(parent=self.root, title="Abrir una captura", filetypes=CAPTURES)
        if chosen:
            self.open(Path(chosen))

    def open_sample(self) -> None:
        if self.busy:
            return
        path = Path(tempfile.gettempdir()) / "pcap-hunter-oficina.pcap"
        write_sample(path)
        self.open(path, label="Ejemplo: 40 minutos en la red de una oficina (inventado)")

    def open(self, path: Path, label: str | None = None) -> None:
        self.source = path
        self.source_label.config(text=label or str(path))
        self.in_background(lambda: analyze_capture(path), self.show_analysis, "Analizando…")

    def save(self) -> None:
        if not self.analysis or self.busy:
            return
        target = filedialog.asksaveasfilename(
            parent=self.root,
            title="Guardar informe",
            defaultextension=".txt",
            initialfile=f"{self.source.stem}-informe.txt",
            filetypes=[("Texto", "*.txt"), ("JSON", "*.json")],
        )
        if not target:
            return
        make = to_json if target.lower().endswith(".json") else to_text
        # to_text pinta con colores solo si la salida es una terminal: aquí sale en limpio.
        Path(target).write_text(make(self.analysis, str(self.source)) + "\n", encoding="utf-8")
        self.status.config(text=f"Informe guardado en {target}")

    def about(self) -> None:
        messagebox.showinfo(
            "Acerca de pcap-hunter",
            f"pcap-hunter {__version__}\n\nBusca escaneos de puertos, ARP spoofing, túneles DNS, beaconing y "
            "contraseñas en claro en capturas de red.\n\nhttps://github.com/espi0207/pcap-hunter",
            parent=self.root,
        )

    # Trabajo en segundo plano

    def in_background(self, work, done, message: str) -> None:
        self.busy = True
        self.status.config(text=message)
        self.progress.pack(side="left", padx=(0, 10), before=self.status)
        self.progress.start(12)

        def worker():
            try:
                self.jobs.put((done, work(), None))
            except Exception as exc:  # que un error no deje la ventana esperando para siempre
                self.jobs.put((done, None, exc))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self) -> None:
        try:
            while True:
                done, result, error = self.jobs.get_nowait()
                self.busy = False
                self.progress.stop()
                self.progress.pack_forget()
                if error:
                    self.status.config(text="")
                    reason = error.strerror if isinstance(error, OSError) and error.strerror else error
                    kind = (
                        "no es una captura que sepa leer"
                        if isinstance(error, CaptureError)
                        else "no se ha podido abrir"
                    )
                    messagebox.showerror("pcap-hunter", f"{self.source}: {kind}.\n\n{reason}", parent=self.root)
                else:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)


def self_check() -> int:
    """Para la CI: abre la ventana con la captura de ejemplo, espera al análisis y comprueba
    que salen los hallazgos que tiene que haber, sin que nadie toque nada. Así se sabe que el
    programa instalado funciona de verdad (con Tkinter y todo), no solo que se ha creado."""
    root = tk.Tk()
    app = App(root, None)
    app.open_sample()
    outcome = {"code": 1}

    def check():
        if app.busy:
            root.after(100, check)
            return
        rules = {f.rule for f in app.analysis.findings} if app.analysis else set()
        expected = {"port_scan", "network_sweep", "arp_spoofing", "dns_tunnel", "beaconing", "cleartext_credentials"}
        outcome["code"] = 0 if expected <= rules and len(app.tree.get_children()) == len(app.analysis.findings) else 1
        root.destroy()

    root.after(200, check)
    root.after(60_000, root.destroy)  # por si algo se queda colgado
    root.mainloop()
    return outcome["code"]


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if sys.platform == "win32":
        try:  # sin esto, en pantallas con zoom Windows estira la ventana y se ve borrosa
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    if "--comprobar" in args:
        sys.exit(self_check())
    # Un archivo como argumento: el que llega con "Abrir con" desde el explorador de archivos.
    capture = Path(args[0]) if args else None
    root = tk.Tk()
    App(root, capture if capture and capture.is_file() else None)
    root.mainloop()


if __name__ == "__main__":
    main()
