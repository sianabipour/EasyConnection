# Easy Connection — Architecture

## Purpose

Native Ubuntu 26.04 desktop client for SSH/SOCKS/VPN-style tunneling with system-wide routing, local proxies, DNS control, and protocol adapters. The tunnel engine is independent of the GUI.

## High-level layers

```text
Desktop UI (React + Tailwind via Tauri 2)
    |
    | IPC (typed Tauri commands + events)
    v
Application Controller (crates/core)
    |
    +---- Configuration Manager   (crates/config + SQLite)
    +---- Connection Manager      (crates/tunnel)
    +---- Routing Manager         (crates/routing)
    +---- DNS Manager             (crates/dns)
    +---- Firewall/NFT Manager    (crates/nftables)
    +---- TUN Manager             (crates/tun)
    +---- Proxy Manager           (crates/socks + local HTTP)
    +---- Diagnostics Engine      (crates/diagnostics)
    +---- Secrets Manager         (crates/secrets → Secret Service)
    |
    | restricted Unix socket / D-Bus-style IPC
    v
Privileged Helper (services/privileged-helper)
    |
    +---- TUN create/destroy
    +---- nftables table inet easy
    +---- routes / policy routing
    +---- systemd-resolved DNS hooks
    |
    v
Tunnel Engine (crates/tunnel)
    |
    +---- SSH Adapter           (crates/ssh)
    +---- SOCKS Adapter         (crates/socks)
    +---- Shadowsocks Adapter   (crates/shadowsocks)
    +---- VLESS Adapter         (crates/vless)
    +---- TLS/XTLS Transport    (crates/tls)
    +---- WebSocket Adapter     (crates/websocket)
    +---- HTTP Upgrade Adapter  (crates/websocket / http-upgrade)
    +---- UDPGW Adapter         (crates/udpgw)
```

## Design principles

1. **Single source of truth** — connection state lives in the Rust controller; UI only observes and requests actions.
2. **No root GUI** — the desktop process never holds CAP_NET_ADMIN permanently.
3. **Transactional networking** — snapshot → apply → verify → rollback on failure.
4. **Identifiable firewall ownership** — only `table inet easy` (and named chains) are touched.
5. **Secrets out of SQLite** — credentials stored via Linux Secret Service; DB holds SecretRefs only.
6. **Protocol/transport split** — application protocol adapters compose with transport adapters (direct, TLS, WS, WSS, HTTP upgrade).
7. **Honest compatibility** — standards-based protocols are implemented; undocumented proprietary wire formats are stubbed behind traits, not invented.

## Process model

| Process | Privilege | Role |
|---------|-----------|------|
| `easy-desktop` (Tauri app) | user | UI, config, orchestrates tunnels |
| `easy` (CLI) | user | same controller as the desktop |
| `easy-helper` | root (systemd) | TUN, nftables, routes, DNS |

IPC between GUI and helper is authenticated (socket credentials / token file with `0600`), command-allowlisted, and never a shell.

## Connection state machine

```text
Disconnected
  → Connecting (resolve → TCP → transport → auth → tunnel → routes → DNS)
  → Connected (healthy | degraded)
  → Reconnecting (backoff)
  → Disconnecting → Disconnected
  → Error
```

## Data flow — Proxy Only

```text
App → local SOCKS5/HTTP → protocol adapter → transport → remote
```

## Data flow — Full Tunnel (VPN)

```text
App → kernel stack → TUN easy0 → userspace packet IO
    → TCP: via tunnel adapter
    → UDP: via UDPGW (when enabled) or protocol UDP path
    → remote
```

## Configuration persistence

- SQLite at `~/.config/easy/state.db`.
- Secrets via `org.freedesktop.secrets` (libsecret).
- Versioned JSON profile export (`version: 1`).

## Workspace layout

```text
├── apps/desktop/          # Tauri 2 + React + Tailwind
├── apps/cli/              # `easy` binary
├── crates/
│   ├── core/              # controller, IPC surface for Tauri
│   ├── tunnel/            # engine + connection manager
│   ├── ssh/
│   ├── socks/
│   ├── shadowsocks/
│   ├── vless/
│   ├── tls/
│   ├── websocket/
│   ├── udpgw/
│   ├── dns/
│   ├── routing/
│   ├── nftables/
│   ├── tun/
│   ├── diagnostics/
│   ├── config/
│   ├── secrets/
│   └── perf/              # micro-benchmarks (`easy-bench`)
├── services/privileged-helper/
├── tests/
├── packaging/             # .deb, systemd unit, Flatpak manifest
├── docs/
└── scripts/
```

## Library choices (initial)

| Area | Choice | Notes |
|------|--------|-------|
| SSH | `russh` | modern async SSH |
| TLS | system `openssl s_client` | verify by default; fingerprint = ALPN only |
| SOCKS | custom + `tokio` | SOCKS4/4a/5 + HTTP CONNECT |
| Shadowsocks | `rt-shadowsocks` | SIP004 AEAD TCP (`aes-128-gcm` / `aes-256-gcm`) |
| VLESS | `rt-vless` | public UUID TCP header; encryption=none |
| TUN | `tun` / netlink | Linux only |
| nftables | `nftables` CLI via typed args or libnftnl later | no shell concatenation |
| SQLite | `rusqlite` / `sqlx` | migrations |
| Secrets | `secret-service` | FreeDesktop |
| Async runtime | `tokio` | |

## Privilege requirements

| Operation | Capability / mechanism |
|-----------|------------------------|
| Create TUN | CAP_NET_ADMIN (helper) |
| nftables | CAP_NET_ADMIN |
| routes | CAP_NET_ADMIN |
| systemd-resolved | D-Bus as root/helper or PolicyKit |
| Local proxy bind | user (loopback); LAN bind needs care |

## UI architecture

- React + TypeScript + TailwindCSS inside Tauri WebView.
- Navigation: Home, Servers, Add Connection, Proxy, Routing, DNS, Diagnostics, Logs, Settings, About.
- System tray via Tauri tray API.
- Advanced settings collapsed; primary flow is Add → Connect.

## Safety invariants

1. Never silently disable SSH host-key or TLS certificate verification.
2. Never leave `table inet easy` or `easy0` after clean disconnect/uninstall.
3. On crash: helper/service recovers and rolls back networking state.
4. No credentials in logs.
5. Imported configs are parsed/validated only — never executed.
