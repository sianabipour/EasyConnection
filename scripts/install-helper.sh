#!/usr/bin/env bash
# Install easy-helper as a systemd service (requires root).
# Prefer the .deb for end users — this script is for source / AppImage setups.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Re-run with sudo: sudo $0" >&2
  exit 1
fi

if [[ ! -x "$ROOT/target/release/easy-helper" ]]; then
  echo "Building easy-helper…"
  if [[ -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H bash -lc "cd '$ROOT' && source \"\$HOME/.cargo/env\" 2>/dev/null; cargo build -p easy-helper --release"
  else
    cargo build -p easy-helper --release
  fi
fi

install -Dm755 "$ROOT/target/release/easy-helper" /usr/lib/easy/easy-helper
install -Dm644 "$ROOT/packaging/deb/easy-helper.service" /etc/systemd/system/easy-helper.service

if [[ -f "$ROOT/packaging/polkit/com.easyconnection.helper.policy" ]]; then
  install -Dm644 "$ROOT/packaging/polkit/com.easyconnection.helper.policy" \
    /usr/share/polkit-1/actions/com.easyconnection.helper.policy
fi

systemctl daemon-reload
systemctl enable --now easy-helper.service
systemctl --no-pager --full status easy-helper.service || true
echo
echo "Helper socket: /run/easy/helper.sock"
echo "Polkit:        com.easyconnection.helper.run (pkexec elevation from Connect)"
echo "Emergency cleanup: sudo easy-helper --cleanup-and-exit"
echo "Uninstall: sudo scripts/uninstall.sh"
