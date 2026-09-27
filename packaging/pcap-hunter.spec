# Receta de PyInstaller para el programa de Windows y la app de macOS:
#     pyinstaller --noconfirm packaging/pcap-hunter.spec
# Deja el resultado en dist/pcap-hunter (y dist/pcap-hunter.app en macOS).
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

root = Path(SPECPATH).parent
sys.path.insert(0, str(root))
from pcaphunter import __version__  # noqa: E402

icon = str(root / "packaging" / "icon.png")  # PyInstaller lo pasa a .ico o .icns con Pillow

a = Analysis(
    [str(root / "packaging" / "pcap-hunter-app.py")],
    pathex=[str(root)],
    datas=collect_data_files("pcaphunter"),
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="pcap-hunter", console=False, icon=icon)
coll = COLLECT(exe, a.binaries, a.datas, name="pcap-hunter")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="pcap-hunter.app",
        icon=icon,
        bundle_identifier="io.github.espigares07.pcaphunter",
        version=__version__,
        info_plist={"CFBundleDisplayName": "pcap-hunter", "NSHighResolutionCapable": True, "LSMinimumSystemVersion": "11.0"},
    )
