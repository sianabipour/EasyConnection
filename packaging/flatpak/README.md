# Flatpak

Easy Connection's privileged helper needs `CAP_NET_ADMIN` (TUN + nftables). That is **not practical inside Flatpak**, so this manifest ships the GUI and CLI as a **proxy-only** app.

Full-tunnel / VPN mode:

1. Install the host `.deb` (`./scripts/build-deb.sh`) so `easy-helper.service` runs on the host.
2. Keep `--filesystem=/run/easy:ro` so the sandbox can talk to `/run/easy/helper.sock`.
3. If the socket is missing, the UI still works for local SOCKS/HTTP.

Build (after `cargo build -p easy-cli -p easy-desktop --release`):

```bash
flatpak-builder --user --install build-dir packaging/flatpak/app.easyconnection.linux.yml
```
