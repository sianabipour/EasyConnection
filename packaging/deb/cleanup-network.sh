#!/bin/sh
# Best-effort restore of networking mutated by Easy Connection.
# Safe to run when the helper, TUN, or nft table are already gone.
set -e

HELPER=""
for candidate in /usr/lib/easy/easy-helper /usr/local/lib/easy/easy-helper; do
  if [ -x "$candidate" ]; then
    HELPER="$candidate"
    break
  fi
done

if [ -n "$HELPER" ]; then
  "$HELPER" --cleanup-and-exit >/dev/null 2>&1 || true
fi

if command -v resolvectl >/dev/null 2>&1; then
  resolvectl revert easy0 >/dev/null 2>&1 || true
fi

if command -v nft >/dev/null 2>&1; then
  nft delete table inet easy >/dev/null 2>&1 || true
fi

if command -v ip >/dev/null 2>&1; then
  ip link delete easy0 >/dev/null 2>&1 || true
fi

rm -rf /run/easy
exit 0
