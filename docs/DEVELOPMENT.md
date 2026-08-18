# Developer setup (Ubuntu 26.04)

## Rust

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
rustc --version   # 1.80+
```

## Node (UI)

```bash
node -v   # 20+
cd apps/desktop && npm install
```

## Tauri system packages

```bash
sudo apt install \
  build-essential curl wget file pkg-config \
  libssl-dev libgtk-3-dev libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev patchelf
```

Without these packages you can still build and run the networking engine via:

```bash
cargo build -p easy-cli
cargo test -p rt-config -p rt-secrets
```

## Useful commands

```bash
./scripts/check.sh          # fmt, clippy, tests, cargo audit, frontend tsc
./scripts/bench.sh          # micro-benchmarks (easy-bench)
sudo scripts/install-helper.sh   # VPN / full tunnel only
./scripts/build-desktop-deb.sh   # Ubuntu Desktop .deb (GUI + helper)
./scripts/build-deb.sh
./scripts/e2e-ssh-socks.sh
```

Equivalent pieces:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude easy-desktop --all-targets -- -D warnings
cargo test --workspace --exclude easy-desktop
cargo audit
cd apps/desktop && npm run lint
```

## Phase workflow

Implement → compile → test → run → fix → document → next phase (`ROADMAP.md`).
