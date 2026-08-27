# Install and run Easy Connection (Ubuntu 24.04+)

The supported install is the **desktop `.deb`**. It adds Easy Connection to the Ubuntu app menu and starts `easy-helper` in the background. Build artifacts are produced on Ubuntu 24.04 so they run on 24.04 and newer.

## From a GitHub Release (recommended)

1. Download `easy-connection_*_amd64.deb` from the repository **Releases** page.
2. In the folder where you saved it:

```bash
sudo apt install ./easy-connection_*_amd64.deb
```

`apt` pulls GTK/WebKit and nftables if they are missing.

3. Start the app:

- Activities overview → search **Easy Connection**, or
- terminal: `easy-desktop`

4. For VPN / full tunnel, Connect will start `easy-helper` via polkit (`pkexec`)
   if it is not already running (systemd unit or a prior session). Approve the
   system auth dialog when prompted. You can also enable the unit yourself:

```bash
systemctl status easy-helper.service
ls -l /run/easy/helper.sock
```

Proxy-only (local SOCKS on `127.0.0.1:1080`) works even if you never use full tunnel.

## Build and install from source

Needs Rust 1.80+, Node 22+, and Tauri Linux packages (see `docs/DEVELOPMENT.md`).

```bash
./scripts/build-desktop-deb.sh
sudo apt install ./packaging/out/easy-connection_*.deb
```

CLI-only (no GUI):

```bash
./scripts/build-deb.sh
sudo apt install ./packaging/out/easy-connection_*.deb
```

## First connection (CLI)

```bash
easy add-ssh --name demo --host YOUR_HOST --username YOU --password '…'
easy list
easy connect <uuid>
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

Full tunnel:

```bash
easy add-ssh --name vpn --host YOUR_HOST --username YOU --password '…' \
  --routing-mode full_tunnel
easy connect <uuid>
easy dns-status
```

TLS transports need `openssl` on `PATH`. UDPGW needs `badvpn-udpgw` on the SSH host.

## If networking is stuck after a crash

```bash
easy emergency-restore
sudo easy-helper --cleanup-and-exit
sudo /usr/lib/easy/cleanup-network.sh
```

## Uninstall

```bash
sudo apt remove easy-connection
# optional:
rm -rf ~/.config/easy
```

More recovery steps: `docs/TROUBLESHOOTING.md`.
