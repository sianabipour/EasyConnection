# Docker integration tests

The compose stack provides a password-auth OpenSSH server on `127.0.0.1:2222`.

```bash
docker compose -f tests/integration/docker-compose.yml up -d --build
./scripts/e2e-ssh-socks.sh
```

`scripts/e2e-ssh-socks.sh` starts the stack, builds `easy`, adds an SSH profile, and curls through local SOCKS5.

## CI image (Ubuntu 26.04 toolchain)

`tests/integration/Dockerfile.ci` installs the packages needed to compile the CLI/helper and run `cargo test` inside Ubuntu 26.04. It does not run the privileged helper (no TUN in a typical CI container).

```bash
docker build -f tests/integration/Dockerfile.ci -t easy-ci .
docker run --rm -v "$PWD":/src -w /src easy-ci ./scripts/check.sh
```

Helper / nftables tests that need `CAP_NET_ADMIN` stay on a real Ubuntu 26.04 host (see `docs/INSTALL.md`).
