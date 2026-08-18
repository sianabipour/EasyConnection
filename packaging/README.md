# Packaging

## Desktop `.deb` (what users install)

```bash
./scripts/build-desktop-deb.sh
sudo apt install ./packaging/out/easy-connection_*.deb
```

This package:

- puts **Easy Connection** in `/usr/share/applications` (Ubuntu app menu)
- installs `/usr/bin/easy-desktop` and `/usr/bin/easy`
- installs `/usr/lib/easy/easy-helper` and enables `easy-helper.service` in the background

GitHub Actions (`.github/workflows/release.yml`) builds this `.deb` on every push to `main` / `master` and attaches it to a Release. Existing CI in `.github/workflows/ci.yml` is unchanged.

## Other targets

| Format | Script | Notes |
|--------|--------|--------|
| Desktop `.deb` | `./scripts/build-desktop-deb.sh` | GUI + CLI + helper (Ubuntu Desktop) |
| CLI `.deb` | `./scripts/build-deb.sh` | Headless CLI + helper |
| AppImage | `./scripts/build-appimage.sh` | GUI; helper still comes from the `.deb` |
| Flatpak | `packaging/flatpak/` | GUI / proxy-only |

Outputs: `packaging/out/` (gitignored).

## Uninstall contract

Packages and `scripts/uninstall.sh` must remove:

- TUN `easy0`
- `table inet easy`
- systemd unit `easy-helper.service`
- `/usr/lib/easy/*`, `/usr/bin/easy`, `/usr/bin/easy-desktop`
- leftover routes created by the helper

User config under `~/.config/easy/` is kept unless the user deletes it.

`packaging/deb/prerm` runs cleanup before binaries are removed. `packaging/deb/postinst` starts the helper and refreshes the desktop/icon databases.
