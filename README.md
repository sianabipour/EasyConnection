# Easy Connection

Native Ubuntu tunneling and proxy client. The desktop app is **Easy Connection**; the terminal command is `easy`.

## Install (Ubuntu)

1. Open the latest [GitHub Release](../../releases/latest) and download `easy-connection_*.deb`.
2. Install it:

```bash
sudo apt install ./easy-connection_*.deb
```

3. Open **Easy Connection** from the Ubuntu app menu (Activities → search “Easy Connection”).

That package installs:

- the desktop app (`easy-desktop`)
- the CLI (`easy`)
- the background helper (`easy-helper.service`), started automatically

Full-tunnel / VPN mode uses that helper. Local SOCKS/HTTP proxy mode works without extra setup.

### Build the `.deb` yourself

```bash
sudo apt install build-essential pkg-config libssl-dev openssl \
  libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
  librsvg2-dev patchelf iproute2 nftables python3
curl https://sh.rustup.rs -sSf | sh && source "$HOME/.cargo/env"
cd apps/desktop && npm install && cd ../..
./scripts/build-desktop-deb.sh
sudo apt install ./packaging/out/easy-connection_*.deb
```

Headless CLI + helper only: `./scripts/build-deb.sh`.

## Use

**Desktop:** add a connection in the UI and click Connect. For system-wide routing, pick full tunnel (the helper must be running — `systemctl status easy-helper.service`).

**CLI:**

```bash
easy add-ssh --name demo --host YOUR_HOST --username YOU --password '…'
easy connect <profile-uuid>
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

```bash
easy add-ss --name ss --host YOUR_HOST --port 8388 --method aes-256-gcm --password '…'
easy add-vless --name vless --host YOUR_HOST --port 443 --uuid YOUR-UUID --transport tls
```

Data lives in `~/.config/easy/`. See `docs/INSTALL.md` and `docs/TROUBLESHOOTING.md`.

## Uninstall

```bash
sudo apt remove easy-connection
```

Networking rules, TUN `easy0`, and the helper service are removed on uninstall. Optional: `rm -rf ~/.config/easy`.

## Developer notes

```bash
cargo build -p easy-cli
cd apps/desktop && npm install && npm run tauri dev
./scripts/check.sh
./scripts/e2e-ssh-socks.sh
```

Layout: `ARCHITECTURE.md`. License: Apache-2.0.
