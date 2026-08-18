#!/usr/bin/env bash
# End-to-end: SSH → local SOCKS5 against dockerized OpenSSH.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

source "$HOME/.cargo/env" 2>/dev/null || true

DATA="$(mktemp -d)"
SOCKS_PORT=$((11000 + RANDOM % 1000))
HTTP_PORT=$((12000 + RANDOM % 1000))
trap 'rm -rf "$DATA"; docker compose -f tests/integration/docker-compose.yml down -v >/dev/null 2>&1 || true' EXIT

echo "==> Starting OpenSSH test container"
docker compose -f tests/integration/docker-compose.yml up -d --build
echo "==> Waiting for SSH port"
for i in $(seq 1 60); do
  if (echo >/dev/tcp/127.0.0.1/2222) >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> Building CLI"
cargo build -p easy-cli --quiet
BIN="$ROOT/target/debug/easy"

echo "==> Adding profile (socks=$SOCKS_PORT http=$HTTP_PORT)"
ID=$("$BIN" --data-dir "$DATA" add-ssh \
  --name "docker-ssh" \
  --host 127.0.0.1 \
  --port 2222 \
  --username tunnel \
  --password tunnelpass \
  --socks-port "$SOCKS_PORT" \
  --http-port "$HTTP_PORT")

echo "profile=$ID"

echo "==> Connecting (background)"
"$BIN" --data-dir "$DATA" connect "$ID" >"$DATA/connect.json" 2>"$DATA/connect.err" &
CPID=$!
for i in $(seq 1 20); do
  if grep -q socks5 "$DATA/connect.json" 2>/dev/null; then break; fi
  if ! kill -0 "$CPID" 2>/dev/null; then
    echo "connect process exited early" >&2
    cat "$DATA/connect.err" >&2 || true
    cat "$DATA/connect.json" >&2 || true
    exit 1
  fi
  sleep 0.5
done

echo "==> SOCKS5 smoke via curl"
curl -fsS --max-time 20 -x "socks5h://127.0.0.1:${SOCKS_PORT}" https://example.com/ >/dev/null
echo "SOCKS5 OK"

kill -INT "$CPID" 2>/dev/null || true
wait "$CPID" 2>/dev/null || true
echo "==> Integration test passed"
