#!/usr/bin/env bash
# Build the Ubuntu Desktop .deb: GUI + CLI + helper service + app-menu entry.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$HOME/.cargo/env" 2>/dev/null || true

VERSION="${VERSION:-0.1.1}"
ARCH="${ARCH:-amd64}"
OUT="$ROOT/packaging/out"
STAGE="$OUT/easy-connection_${VERSION}_${ARCH}"

echo "==> Icons (from apps/desktop/src-tauri/icon.png)"
python3 "$ROOT/scripts/gen-app-icons.py"

echo "==> Frontend"
if [[ ! -d "$ROOT/apps/desktop/node_modules" ]]; then
  if [[ -f "$ROOT/apps/desktop/package-lock.json" ]]; then
    (cd "$ROOT/apps/desktop" && npm ci)
  else
    (cd "$ROOT/apps/desktop" && npm install)
  fi
fi
(cd "$ROOT/apps/desktop" && npm run build)

echo "==> Release binaries (CLI, helper, desktop)"
cargo build -p easy-cli -p easy-helper -p easy-desktop --release

DESKTOP_BIN="$ROOT/target/release/easy-desktop"
if [[ ! -x "$DESKTOP_BIN" ]]; then
  DESKTOP_BIN="$ROOT/apps/desktop/src-tauri/target/release/easy-desktop"
fi
if [[ ! -x "$DESKTOP_BIN" ]]; then
  echo "easy-desktop binary not found after cargo build" >&2
  exit 1
fi
if [[ ! -x "$ROOT/target/release/easy" || ! -x "$ROOT/target/release/easy-helper" ]]; then
  echo "easy / easy-helper binaries not found in target/release" >&2
  exit 1
fi

ICONS="$ROOT/apps/desktop/src-tauri/icons"

rm -rf "$STAGE"
mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/lib/easy" \
  "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/share/applications" \
  "$STAGE/usr/share/metainfo" \
  "$STAGE/usr/share/polkit-1/actions" \
  "$STAGE/usr/share/icons/hicolor/32x32/apps" \
  "$STAGE/usr/share/icons/hicolor/128x128/apps" \
  "$STAGE/usr/share/icons/hicolor/256x256/apps" \
  "$STAGE/usr/share/pixmaps" \
  "$STAGE/usr/share/doc/easy-connection"

install -Dm755 "$ROOT/target/release/easy" "$STAGE/usr/bin/easy"
install -Dm755 "$DESKTOP_BIN" "$STAGE/usr/bin/easy-desktop"
install -Dm755 "$ROOT/target/release/easy-helper" "$STAGE/usr/lib/easy/easy-helper"
ln -sf ../lib/easy/easy-helper "$STAGE/usr/bin/easy-helper"
install -Dm755 "$ROOT/packaging/deb/cleanup-network.sh" "$STAGE/usr/lib/easy/cleanup-network.sh"
install -Dm644 "$ROOT/packaging/deb/easy-helper.service" "$STAGE/usr/lib/systemd/system/easy-helper.service"
sed -i 's|^ExecStart=.*|ExecStart=/usr/lib/easy/easy-helper --socket /run/easy/helper.sock --allow-active-sessions|' \
  "$STAGE/usr/lib/systemd/system/easy-helper.service"
install -Dm644 "$ROOT/packaging/polkit/com.easyconnection.helper.policy" \
  "$STAGE/usr/share/polkit-1/actions/com.easyconnection.helper.policy"

install -Dm644 "$ROOT/packaging/deb/easy-connection.desktop" \
  "$STAGE/usr/share/applications/easy-connection.desktop"
install -Dm644 "$ROOT/packaging/deb/app.easyconnection.linux.metainfo.xml" \
  "$STAGE/usr/share/metainfo/app.easyconnection.linux.metainfo.xml"

install -Dm644 "$ICONS/32x32.png" "$STAGE/usr/share/icons/hicolor/32x32/apps/easy-connection.png"
install -Dm644 "$ICONS/128x128.png" "$STAGE/usr/share/icons/hicolor/128x128/apps/easy-connection.png"
if [[ -f "$ICONS/128x128@2x.png" ]]; then
  mkdir -p "$STAGE/usr/share/icons/hicolor/256x256/apps"
  install -Dm644 "$ICONS/128x128@2x.png" \
    "$STAGE/usr/share/icons/hicolor/256x256/apps/easy-connection.png"
  install -Dm644 "$ICONS/128x128@2x.png" "$STAGE/usr/share/pixmaps/easy-connection.png"
elif [[ -f "$ICONS/icon.png" ]]; then
  install -Dm644 "$ICONS/icon.png" "$STAGE/usr/share/pixmaps/easy-connection.png"
else
  install -Dm644 "$ICONS/128x128.png" "$STAGE/usr/share/pixmaps/easy-connection.png"
fi
# High-res for GNOME scaling
if [[ -f "$ICONS/icon-1024.png" ]]; then
  mkdir -p "$STAGE/usr/share/icons/hicolor/512x512/apps"
  install -Dm644 "$ICONS/icon.png" "$STAGE/usr/share/icons/hicolor/512x512/apps/easy-connection.png"
fi

install -Dm644 "$ROOT/packaging/deb/copyright" "$STAGE/usr/share/doc/easy-connection/copyright"
gzip -9 -c "$ROOT/packaging/deb/changelog" > "$STAGE/usr/share/doc/easy-connection/changelog.Debian.gz"
install -Dm644 "$ROOT/README.md" "$STAGE/usr/share/doc/easy-connection/README.md"
install -Dm644 "$ROOT/docs/INSTALL.md" "$STAGE/usr/share/doc/easy-connection/INSTALL.md"
install -Dm644 "$ROOT/docs/TROUBLESHOOTING.md" "$STAGE/usr/share/doc/easy-connection/TROUBLESHOOTING.md"

install -m644 "$ROOT/packaging/deb/control" "$STAGE/DEBIAN/control"
sed -i "s/^Version:.*/Version: ${VERSION}/" "$STAGE/DEBIAN/control"
sed -i "s/^Architecture:.*/Architecture: ${ARCH}/" "$STAGE/DEBIAN/control"
SIZE_KB="$(du -sk "$STAGE" | awk '{print $1}')"
sed -i "s/^Installed-Size:.*/Installed-Size: ${SIZE_KB}/" "$STAGE/DEBIAN/control"

install -m755 "$ROOT/packaging/deb/postinst" "$STAGE/DEBIAN/postinst"
install -m755 "$ROOT/packaging/deb/prerm" "$STAGE/DEBIAN/prerm"
install -m755 "$ROOT/packaging/deb/postrm" "$STAGE/DEBIAN/postrm"

echo "==> Building dpkg"
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT/easy-connection_${VERSION}_${ARCH}.deb"
echo
echo "Wrote $OUT/easy-connection_${VERSION}_${ARCH}.deb"
echo "Install with:"
echo "  sudo apt install ./packaging/out/easy-connection_${VERSION}_${ARCH}.deb"
echo "Then open \"Easy Connection\" from the Ubuntu app menu."
