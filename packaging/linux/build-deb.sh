#!/bin/sh
# Construye dist/pcap-hunter-linux.deb para Ubuntu, Debian, Linux Mint y derivados.
#
# No lleva un Python dentro: instala el paquete tal cual y usa el Python del sistema, más
# python3-tk para la ventana. Por eso pesa unos pocos KB y vale para cualquier
# arquitectura. Uso: packaging/linux/build-deb.sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$root/pcaphunter/__init__.py")
pkg=$(mktemp -d)
trap 'rm -rf "$pkg"' EXIT
chmod 755 "$pkg"  # mktemp la crea solo para su dueño, y es la raíz del paquete

mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/lib/python3/dist-packages" \
  "$pkg/usr/share/applications" "$pkg/usr/share/doc/pcap-hunter" \
  "$pkg/usr/share/icons/hicolor/scalable/apps" "$pkg/usr/share/icons/hicolor/256x256/apps"

cp -r "$root/pcaphunter" "$pkg/usr/lib/python3/dist-packages/"
find "$pkg" -name __pycache__ -prune -exec rm -rf {} +

cat > "$pkg/usr/bin/pcaphunter" <<'PY'
#!/usr/bin/python3
from pcaphunter.__main__ import main

raise SystemExit(main())
PY
cat > "$pkg/usr/bin/pcaphunter-app" <<'PY'
#!/usr/bin/python3
from pcaphunter.gui import main

main()
PY
chmod 755 "$pkg/usr/bin/pcaphunter" "$pkg/usr/bin/pcaphunter-app"

cp "$root/packaging/linux/pcap-hunter.desktop" "$pkg/usr/share/applications/"
cp "$root/packaging/icon.svg" "$pkg/usr/share/icons/hicolor/scalable/apps/pcap-hunter.svg"
cp "$root/pcaphunter/icon.png" "$pkg/usr/share/icons/hicolor/256x256/apps/pcap-hunter.png"
cp "$root/LICENSE" "$pkg/usr/share/doc/pcap-hunter/copyright"

cat > "$pkg/DEBIAN/control" <<CONTROL
Package: pcap-hunter
Version: $version
Architecture: all
Maintainer: espi0207 <espi0207@users.noreply.github.com>
Depends: python3 (>= 3.10), python3-tk
Section: utils
Priority: optional
Homepage: https://github.com/espi0207/pcap-hunter
Description: busca ataques en capturas de red
 Analiza capturas de red (pcap y pcapng) y avisa de escaneos de puertos, ARP
 spoofing, túneles DNS, beaconing y contraseñas en claro. Tiene ventana y línea
 de órdenes.
CONTROL

# Compilar a bytecode al instalar (como hacen los paquetes de Python de Debian) y
# limpiarlo al desinstalar, que dpkg no sabe que esos archivos son del paquete.
cat > "$pkg/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
python3 -m compileall -q /usr/lib/python3/dist-packages/pcaphunter >/dev/null 2>&1 || true
SH
cat > "$pkg/DEBIAN/prerm" <<'SH'
#!/bin/sh
set -e
rm -rf /usr/lib/python3/dist-packages/pcaphunter/__pycache__
SH
chmod 755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/prerm"

mkdir -p "$root/dist"
dpkg-deb --build --root-owner-group "$pkg" "$root/dist/pcap-hunter-linux.deb"
