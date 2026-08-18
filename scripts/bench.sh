#!/usr/bin/env bash
# Micro-benchmarks for config, secrets, Shadowsocks key derivation, nft render.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$HOME/.cargo/env" 2>/dev/null || true

cargo run -p easy-bench --release
