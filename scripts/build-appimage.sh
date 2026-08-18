#!/usr/bin/env bash
# Build Tauri desktop .deb + AppImage (needs WebKit/GTK; see docs/DEVELOPMENT.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$HOME/.cargo/env" 2>/dev/null || true

echo "==> Release CLI + helper (bundled into the desktop package)"
cargo build -p easy-cli -p easy-helper --release

if [[ ! -f "$ROOT/apps/desktop/src-tauri/icons/32x32.png" ]]; then
  python3 "$ROOT/scripts/gen-icons.py"
fi

echo "==> Frontend deps"
if [[ ! -d "$ROOT/apps/desktop/node_modules" ]]; then
  (cd "$ROOT/apps/desktop" && npm install)
fi

echo "==> Tauri bundle (deb + appimage)"
(cd "$ROOT/apps/desktop" && npm run tauri -- build --bundles deb,appimage)

echo "Look under target/release/bundle/ (or apps/desktop/src-tauri/target/release/bundle/)."
echo "For a user-facing Ubuntu install (app menu + helper service), prefer:"
echo "  ./scripts/build-desktop-deb.sh"
