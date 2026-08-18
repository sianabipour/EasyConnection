#!/usr/bin/env bash
# Stop the helper, restore TUN/nft/routes, and remove a source or package install.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Re-run with sudo: sudo $0 [--purge]" >&2
  exit 1
fi

PURGE=0
if [[ "${1:-}" == "--purge" ]]; then
  PURGE=1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLEANUP="$ROOT/packaging/deb/cleanup-network.sh"
if [[ -x /usr/lib/easy/cleanup-network.sh ]]; then
  CLEANUP=/usr/lib/easy/cleanup-network.sh
fi

systemctl disable --now easy-helper.service >/dev/null 2>&1 || true
if [[ -x "$CLEANUP" ]]; then
  "$CLEANUP" || true
elif [[ -x /usr/lib/easy/easy-helper ]]; then
  /usr/lib/easy/easy-helper --cleanup-and-exit || true
elif [[ -x "$ROOT/target/release/easy-helper" ]]; then
  "$ROOT/target/release/easy-helper" --cleanup-and-exit || true
fi

rm -f /usr/local/bin/easy /usr/bin/easy /usr/bin/easy-desktop /usr/bin/easy-helper
rm -f /usr/lib/easy/easy-helper /usr/lib/easy/cleanup-network.sh
rm -f /etc/systemd/system/easy-helper.service
rm -f /usr/lib/systemd/system/easy-helper.service
rm -f /usr/share/applications/easy-connection.desktop
rm -f /usr/share/metainfo/app.easyconnection.linux.metainfo.xml
rm -f /usr/share/pixmaps/easy-connection.png
rm -f /usr/share/icons/hicolor/32x32/apps/easy-connection.png
rm -f /usr/share/icons/hicolor/128x128/apps/easy-connection.png
rm -f /usr/share/icons/hicolor/256x256/apps/easy-connection.png
rmdir /usr/lib/easy >/dev/null 2>&1 || true
rm -rf /run/easy
systemctl daemon-reload >/dev/null 2>&1 || true

if [[ "$PURGE" -eq 1 ]]; then
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    HOME_DIR="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    rm -rf "${HOME_DIR}/.config/easy"
  fi
  echo "Removed user config under ~/.config/easy for $SUDO_USER"
fi

echo "Easy Connection networking helpers removed."
