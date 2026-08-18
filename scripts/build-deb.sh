#!/usr/bin/env bash
# Build the easy-connection .deb (CLI + privileged helper) for Ubuntu 26.04.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$HOME/.cargo/env" 2>/dev/null || true

VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-amd64}"
OUT="$ROOT/packaging/out"
STAGE="$OUT/easy-connection_${VERSION}_${ARCH}"

echo "==> Building release binaries"
cargo build -p easy-cli -p easy-helper --release

rm -rf "$STAGE"
mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/lib/easy" \
  "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/share/doc/easy-connection"

install -Dm755 "$ROOT/target/release/easy" "$STAGE/usr/bin/easy"
install -Dm755 "$ROOT/target/release/easy-helper" "$STAGE/usr/lib/easy/easy-helper"
install -Dm755 "$ROOT/packaging/deb/cleanup-network.sh" "$STAGE/usr/lib/easy/cleanup-network.sh"
install -Dm644 "$ROOT/packaging/deb/easy-helper.service" "$STAGE/usr/lib/systemd/system/easy-helper.service"

# Packaged unit must match the installed helper path.
sed -i 's|^ExecStart=.*|ExecStart=/usr/lib/easy/easy-helper --socket /run/easy/helper.sock --allow-active-sessions|' \
  "$STAGE/usr/lib/systemd/system/easy-helper.service"

install -Dm644 "$ROOT/packaging/deb/copyright" "$STAGE/usr/share/doc/easy-connection/copyright"
gzip -9 -c "$ROOT/packaging/deb/changelog" > "$STAGE/usr/share/doc/easy-connection/changelog.Debian.gz"
install -Dm644 "$ROOT/README.md" "$STAGE/usr/share/doc/easy-connection/README.md"
install -Dm644 "$ROOT/docs/INSTALL.md" "$STAGE/usr/share/doc/easy-connection/INSTALL.md"
install -Dm644 "$ROOT/docs/TROUBLESHOOTING.md" "$STAGE/usr/share/doc/easy-connection/TROUBLESHOOTING.md"

install -m644 "$ROOT/packaging/deb/control-cli" "$STAGE/DEBIAN/control"
SIZE_KB="$(du -sk "$STAGE" | awk '{print $1}')"
sed -i "s/^Installed-Size:.*/Installed-Size: ${SIZE_KB}/" "$STAGE/DEBIAN/control"

install -m755 "$ROOT/packaging/deb/postinst" "$STAGE/DEBIAN/postinst"
install -m755 "$ROOT/packaging/deb/prerm" "$STAGE/DEBIAN/prerm"
install -m755 "$ROOT/packaging/deb/postrm" "$STAGE/DEBIAN/postrm"

echo "==> Building dpkg"
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT/easy-connection_${VERSION}_${ARCH}.deb"
echo "Wrote $OUT/easy-connection_${VERSION}_${ARCH}.deb"
