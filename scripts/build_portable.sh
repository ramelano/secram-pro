#!/usr/bin/env bash
# Build x86_64 portable bundle from the already-created local virtualenv.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYVER=${PYVER:-3.12}
OUT=${1:-/home/ubuntu/deliverables}
APPDIR="$ROOT/build/SecRam-Pro.AppDir"
PY_SITE="$ROOT/.venv/lib/python${PYVER}/site-packages"
mkdir -p "$OUT"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/opt/secram/src" "$APPDIR/opt/python" "$APPDIR/opt/qt/lib" "$APPDIR/opt/qt/plugins/platforms" "$APPDIR/usr/bin"

# Application source and metadata.
cp -a "$ROOT/src/secram" "$APPDIR/opt/secram/src/"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/SECURITY.md" "$APPDIR/opt/secram/"
cp "$ROOT/resources/icons/secram-pro.svg" "$APPDIR/secram-pro.svg" 2>/dev/null || cat > "$APPDIR/secram-pro.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256"><rect width="256" height="256" rx="32" fill="#12263a"/><path d="M64 72h128v112H64z" fill="none" stroke="#4fd1c5" stroke-width="16"/><path d="M88 120h80M88 152h48" stroke="#f6e05e" stroke-width="12" stroke-linecap="round"/></svg>
SVG

# Runtime Python packages; exclude development/build tools and caches.
cp -a "$PY_SITE/." "$APPDIR/opt/python/"
rm -rf "$APPDIR/opt/python"/__pycache__ "$APPDIR/opt/python"/pip* \
  "$APPDIR/opt/python"/setuptools* "$APPDIR/opt/python"/wheel* \
  "$APPDIR/opt/python"/pytest* "$APPDIR/opt/python"/_pytest
find "$APPDIR/opt/python" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$APPDIR/opt/python" -type f -name '*.pyc' -delete

# PySide bindings without Qt's documentation, QML, translations, samples and headers.
rm -rf "$APPDIR/opt/python/PySide6/Qt"
rm -rf "$APPDIR/opt/python/PySide6" "$APPDIR/opt/python/shiboken6"
cp -a "$PY_SITE/PySide6" "$APPDIR/opt/python/"
cp -a "$PY_SITE/shiboken6" "$APPDIR/opt/python/"
find "$APPDIR/opt/python/PySide6" "$APPDIR/opt/python/shiboken6" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$APPDIR/opt/python/PySide6" "$APPDIR/opt/python/shiboken6" -type f -name '*.pyc' -delete

# Only Qt libraries required by QtCore/Gui/Widgets plus headless/desktop plugins.
for lib in libQt6Core.so* libQt6Gui.so* libQt6Widgets.so* libQt6DBus.so*; do
  compgen -G "$PY_SITE/PySide6/Qt/lib/$lib" | xargs -r -I{} cp -a {} "$APPDIR/opt/qt/lib/"
done
for plugin in libqoffscreen.so libqminimal.so libqxcb.so; do
  test -f "$PY_SITE/PySide6/Qt/plugins/platforms/$plugin" && cp -a "$PY_SITE/PySide6/Qt/plugins/platforms/$plugin" "$APPDIR/opt/qt/plugins/platforms/"
done

cat > "$APPDIR/AppRun" <<'RUN'
#!/usr/bin/env bash
set -euo pipefail
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${SECRAM_PYTHON:-python3}
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "SecRam-Pro portable: python3 >= 3.12 is required on the host" >&2; exit 1
fi
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)'; then
  echo "SecRam-Pro portable: Python >= 3.12 is required" >&2; exit 1
fi
export PYTHONPATH="$HERE/opt/secram/src:$HERE/opt/python${PYTHONPATH:+:$PYTHONPATH}"
export QT_PLUGIN_PATH="$HERE/opt/qt/plugins${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
export LD_LIBRARY_PATH="$HERE/opt/qt/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$PYTHON" -m secram "$@"
RUN
chmod +x "$APPDIR/AppRun"

cat > "$APPDIR/secram-pro.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=SecRam-Pro
Comment=Offline scoped Linux security assessment platform
Exec=secram-pro
Icon=secram-pro
Categories=System;Security;
Terminal=true
DESKTOP
ln -sf AppRun "$APPDIR/usr/bin/secram-pro"

# A portable tarball is useful even when AppImage execution is blocked by FUSE/policy.
tar -C "$ROOT/build" -czf "$OUT/SecRam-Pro-v0.4.0-portable-x86_64.tar.gz" SecRam-Pro.AppDir
printf 'AppDir: %s\nPortable archive: %s\n' "$APPDIR" "$OUT/SecRam-Pro-v0.4.0-portable-x86_64.tar.gz"
du -sh "$APPDIR" "$OUT/SecRam-Pro-v0.4.0-portable-x86_64.tar.gz"
