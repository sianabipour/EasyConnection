#!/usr/bin/env bash
# fmt, clippy, tests, cargo audit, frontend typecheck.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$HOME/.cargo/env" 2>/dev/null || true

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --workspace --exclude easy-desktop --all-targets -- -D warnings

echo "==> cargo test"
cargo test --workspace --exclude easy-desktop

if command -v cargo-audit >/dev/null 2>&1 || cargo audit -V >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
else
  echo "==> cargo audit (installing cargo-audit)"
  cargo install cargo-audit --locked
  cargo audit
fi

if [[ -f "$ROOT/apps/desktop/package.json" ]]; then
  echo "==> frontend lint (tsc)"
  if [[ ! -d "$ROOT/apps/desktop/node_modules" ]]; then
    (cd "$ROOT/apps/desktop" && npm install)
  fi
  (cd "$ROOT/apps/desktop" && npm run lint)
fi

echo "All checks passed."
