# Implementation Roadmap

Work is incremental. Each phase must compile, test, and document before the next.

## Phase 1 — Foundation

- [x] Repository layout
- [x] Architecture docs (`ARCHITECTURE.md`, `ROADMAP.md`, `SECURITY.md`, `PROTOCOLS.md`, `NETWORKING.md`)
- [x] Rust workspace + crate stubs with real module boundaries
- [x] Tauri 2 + React + TypeScript + TailwindCSS desktop shell
- [x] SQLite configuration store + versioned profile model
- [x] Secrets manager (encrypted file vault; Secret Service hook planned)
- [x] Application controller IPC surface
- [x] Basic polished UI: Home, Servers, Add Connection, Proxy, Logs, Settings, About
- [x] Connection state model (real states, not hardcoded Connected)
- [x] Headless CLI (`easy`)

**Exit criteria:** app launches; profiles CRUD; secrets stored safely; no tunnel yet. ✅ (plus early Phase 2)

## Phase 2 — SSH → local SOCKS5

- [x] `russh`-based SSH adapter (password, pubkey, agent, known_hosts)
- [x] Dynamic port forwarding / SOCKS5 through SSH (`direct-tcpip`)
- [x] Local SOCKS4/4a/5 + HTTP CONNECT listeners
- [x] Connection manager state machine (proxy mode)
- [x] Structured logging (`tracing`)
- [x] End-to-end Docker OpenSSH test (`scripts/e2e-ssh-socks.sh`)

**Exit criteria:** select SSH profile → Connect → apps using local SOCKS work. ✅

## Phase 3 — SSH → TUN → system-wide TCP

- [x] Privileged helper + systemd unit
- [x] TUN `easy0` create/destroy
- [x] nftables `table inet easy` (TCP redirect + optional kill switch)
- [x] System-wide TCP via kernel intercept → SSH `direct-tcpip`
- [x] DNS-over-TCP fallback for UDP/53
- [x] Crash/SIGTERM / client-disconnect cleanup
- [x] Kill-switch foundation (optional)

**Exit criteria:** VPN mode routes TCP system-wide; disconnect restores networking. (TUN packet IO / default-route-via-TUN arrives with a userspace IP stack in a later increment; Phase 3 does not point `0.0.0.0/0` at the TUN.)

## Phase 4 — DNS + IPv6

- [x] DNS manager (system / tunnel / custom / remote)
- [x] systemd-resolved integration (no blind `/etc/resolv.conf` overwrite)
- [x] DNS-over-TCP fallback
- [x] Leak prevention diagnostics
- [x] IPv6 TUN + routing when enabled

**Exit criteria:** full/split tunnel sets link DNS via `resolvectl` (never overwrites `/etc/resolv.conf`); IPv6-off rejects public IPv6; IPv6-on adds TUN ULA and dual-stack intercept; Routing page / `easy dns-status` report leaks.

## Phase 5 — UDPGW + UDP

- [x] BadVPN UDPGW-compatible client
- [x] Transparent DNS via UDPGW
- [x] UDP relay diagnostics and compatibility status
- [x] Honest UI about protocol limitations

**Exit criteria:** when a profile enables UDPGW and the SSH host runs a compatible `badvpn-udpgw`, leftover UDP is redirected (not rejected) and carried over SSH; DNS can use UDPGW with DNS-over-TCP fallback; status never claims all UDP works. Without a remote daemon the session is Degraded and UDP stays rejected.

## Phase 6 — Transports + additional protocols

- [x] Transport adapters: Direct, TLS, WebSocket, WSS, HTTP Upgrade
- [x] TLS fingerprint profile architecture (Chrome/Firefox/Safari/Custom)
- [x] Shadowsocks AEAD TCP (`aes-128-gcm`, `aes-256-gcm`)
- [x] VLESS TCP (`encryption=none`)
- [x] SSH-over-TLS / SOCKS-over-TLS composition

**Exit criteria:** a profile can select protocol (SSH / Shadowsocks / VLESS) and transport; TLS uses system `openssl s_client` with verify on by default; fingerprint profiles only set ALPN (not JA3); SSH can run over TLS/WS/WSS/Upgrade; SS/VLESS feed the same local SOCKS/HTTP and full-tunnel TCP path. SS2022, chacha20, and VLESS Vision/XTLS are rejected, not faked.

## Phase 7 — Advanced networking UX

- [x] Split tunnel (IP, domain; process-based architecture hooks only)
- [x] Local network bypass
- [x] Proxy sharing (LAN) with security warnings
- [x] Diagnostics panel (DNS/TCP/TLS/SSH/SOCKS/UDP/MTU/leak)
- [x] Ping / traceroute through tunnel (TCP connect probe + `traceroute -T`)
- [x] Traffic statistics + light graph
- [x] Config import (JSON/URI/clipboard)
- [x] System tray

## Phase 8 — Packaging & hardening

- [x] `.deb` + AppImage (+ Flatpak where practical)
- [x] Uninstall cleanup of rules/routes/TUN/services
- [x] `cargo audit` / clippy / fmt / frontend lint
- [x] Performance benchmarks
- [x] Docker integration-test environment
- [x] Ubuntu 26.04 install + troubleshooting docs

**Exit criteria:** packages restore networking on uninstall; CI runs fmt/clippy/test/audit; Docker OpenSSH e2e exists; install docs target Ubuntu 26.04. ✅

## Dependency decisions (locked for Phase 1–2)

| Need | Decision |
|------|----------|
| SSH | `russh` |
| Async | `tokio` |
| DB | `rusqlite` + migrations |
| Secrets | `secret-service` + encrypted file fallback |
| UI | Tauri 2, React 19, Vite, Tailwind 4 |
| Logging | `tracing` + `tracing-subscriber` |

## Protocol readiness matrix

| Protocol | Phase | Status |
|----------|-------|--------|
| SSH + SOCKS5 | 2 | Implemented |
| SSH + TUN TCP | 3 | Implemented |
| UDPGW | 5 | Implemented (SSH-only) |
| Shadowsocks AEAD TCP | 6 | Implemented (`aes-128-gcm` / `aes-256-gcm`) |
| Shadowsocks 2022 / UDP | 6 | Not in this build |
| VLESS TCP | 6 | Implemented (`encryption=none`) |
| VLESS Vision / XTLS | — | Not invented; rejected |
| TLS / WS / WSS / HTTP Upgrade | 6 | Implemented (`openssl s_client` + RFC 6455) |

## Definition of done (product)

A native Ubuntu 26.04 client that can establish real tunnels, manage Linux networking safely, expose honest diagnostics, and package cleanly — not a demo or mock.
