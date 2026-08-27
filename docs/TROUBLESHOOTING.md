# Troubleshooting (Ubuntu 26.04)

## Desktop app is missing from the menu

The `.deb` installs `/usr/share/applications/easy-connection.desktop`. Log out/in once, or run:

```bash
update-desktop-database ~/.local/share/applications /usr/share/applications
easy-desktop
```

## Helper will not start / elevation denied

Symptoms: Connect with full tunnel fails with helper unavailable, **Elevation denied**,
or **pkexec is not available**.

1. Prefer the packaged path: Connect triggers `pkexec easy-helper --allow-uid <uid>`
   (polkit action `com.easyconnection.helper.run`). Approve the OS password dialog.
2. Or use the systemd unit: `systemctl status easy-helper.service`
3. Socket must exist: `ls -l /run/easy/helper.sock`
4. Override path: `export EASY_HELPER_SOCKET=/run/easy/helper.sock`
5. Manual foreground (debug only): `sudo easy-helper --allow-uid "$(id -u)"`
6. Missing `/dev/net/tun`: `sudo modprobe tun`
7. Missing polkit: install `polkitd` and `pkexec`

The helper needs `CAP_NET_ADMIN` (and `CAP_NET_RAW`). The packaged unit grants those via systemd. Running the binary as a normal user cannot create `easy0`.

## Connect succeeds but nothing is tunneled

- Proxy-only profiles only listen locally. Point the app at `socks5h://127.0.0.1:1080` (or the HTTP CONNECT port).
- Full tunnel needs the helper **and** nftables. Check `easy dns-status` and `nft list table inet easy`.
- Split tunnel skips listed CIDRs/domains on purpose.

## DNS leaks or broken name resolution

Easy Connection never overwrites `/etc/resolv.conf`. Full/split tunnel sets link DNS on `easy0` via `resolvectl`.

```bash
resolvectl status easy0
easy dns-status
```

If `resolvectl` is missing, install `systemd-resolved` and enable it. After disconnect, `resolvectl revert easy0` is part of helper teardown.

## Kill switch locked you out

```bash
easy emergency-restore
sudo easy-helper --cleanup-and-exit
sudo /usr/lib/easy/cleanup-network.sh
```

That removes `table inet easy` and `easy0`. You should have LAN access again.

## AppImage: full tunnel does not work

AppImage is the GUI. Privileged networking is a host systemd service. Install the `easy-connection` `.deb` (or `sudo scripts/install-helper.sh`) beside the AppImage.

## Flatpak: TUN / nftables fail

Expected. The Flatpak sandbox cannot hold `CAP_NET_ADMIN`. Use it for local SOCKS/HTTP only, or talk to a **host** helper by installing the `.deb` and allowing `/run/easy` in the Flatpak finish args (see `packaging/flatpak/README.md`).

## `openssl s_client` / TLS transport errors

TLS, WSS, and SSH-over-TLS spawn system `openssl s_client`. Install `openssl`. Fingerprint profiles only set ALPN — they are not JA3.

## Desktop will not build

Install WebKit/GTK packages listed in `docs/DEVELOPMENT.md`. The CLI and helper do not need those packages:

```bash
cargo build -p easy-cli -p easy-helper
```

## Quality / security checks fail

```bash
./scripts/check.sh
```

`cargo audit` needs `cargo install cargo-audit`. Frontend lint is `tsc --noEmit` in `apps/desktop`.

## Integration tests

Docker must be available:

```bash
./scripts/e2e-ssh-socks.sh
```

See `tests/integration/README.md`.
