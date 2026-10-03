# Protocols

This document records what we implement, how it behaves, and where undocumented proprietary behavior is **not** invented.

Legend:

- **Standards-compatible:** implemented against public RFCs / documented protocol specs.
- **Proprietary / undocumented:** proprietary wire behavior — **not implemented** without a public specification.

---

## SSH

| Aspect | Behavior |
|--------|----------|
| Protocol | SSH-2 |
| Transport | Direct TCP, or TLS / WebSocket / WSS / HTTP Upgrade |
| Authentication | password, public key (incl. encrypted keys), SSH agent |
| Encryption | negotiated modern algorithms via `russh` |
| Handshake | standard SSH KEX + auth |
| DNS | remote resolution via SOCKS5 when using dynamic forward |
| UDP | not native; use UDPGW adapter |
| IPv6 | supported for server and forwarded destinations |
| Routing | proxy-only (local SOCKS/HTTP) or TUN full-tunnel TCP |

Full-tunnel TCP is intercepted with the owned nftables table and forwarded by the local transparent proxy through SSH `direct-tcpip`. `easy0` is lifecycle-owned by the helper, but this build does not route a default route into a userspace IP stack. It does **not** use undocumented proprietary packet formats.

UDP: not native to SSH. DNS/53 is carried with DNS-over-TCP (Phase 3) and optionally UDPGW (Phase 5). Arbitrary UDP uses a BadVPN UDPGW client when the remote runs a compatible daemon.

**Exit zones:** RocketTunnel's zone picker belongs to an imported Smart Config
`/i/` link, not a plain SSH Direct profile. Easy can decode that link in memory
and preview its JSON zone list (`POST <smart.path>` with `command: zone`).
RocketTunnel applies the selected id with `X-Zone-Id` on a separate encrypted
Smart Config GET, whose response/tunnel flow is not implemented in Easy.
Easy does not offer forced-country SSH Direct connections or rewrite the SSH
username. Plain OpenSSH continues to connect as before. See `docs/ZONES.md`.

**Proprietary compatibility:** Smart Config zone-list preview only; selected-
country tunnel is not implemented.
**Standards-compatible implementation:** Implemented (Phase 2+).

Host-key verification is mandatory by default.

---

## SOCKS (local sharing)

| Aspect | Behavior |
|--------|----------|
| Protocol | SOCKS4, SOCKS4a, SOCKS5; HTTP CONNECT |
| Auth | none or username/password (SOCKS5 / HTTP) |
| UDP | SOCKS5 UDP ASSOCIATE where tunnel supports UDP |
| DNS | local or remote (SOCKS5 domain) |

Default ports: SOCKS5 `1080`, HTTP `8080` (configurable).

---

## SSH-XTLS / SOCKS-XTLS

Some products advertise SSH-XTLS and SOCKS-XTLS. Undocumented proprietary XTLS framing is **not** reverse-engineered here.

Architecture:

```text
SSH | SOCKS | VLESS | Shadowsocks
        → TransportAdapter { Direct, Tls, WebSocket, Wss, HttpUpgrade }
```

**Proprietary compatibility:** Not implemented (proprietary wire unavailable).  
**Standards-compatible implementation:** SSH/SOCKS over standard TLS / WS / WSS / HTTP Upgrade as transport wrappers (in-process OpenSSL + RFC 6455). See `crates/tls/COMPAT.md`.

---

## TLS transport

| Aspect | Behavior |
|--------|----------|
| SNI | configurable |
| ALPN | configurable |
| Versions | TLS 1.2 / 1.3 (safe defaults) |
| Verification | ON by default |
| Fingerprint profiles | Default / Chrome / Firefox / Safari / Custom (ALPN hint only) |
| Implementation | in-process OpenSSL via Rust bindings (not JA3 impersonation) |

Fingerprint profiles never imply “skip verify”. Chrome/Firefox/Safari only add `http/1.1` for WSS / HTTP Upgrade when the user left ALPN empty. SSH-over-TLS keeps ALPN empty unless the user set it.

---

## Shadowsocks

| Aspect | Behavior |
|--------|----------|
| Protocol | Shadowsocks SIP004 AEAD TCP (`aes-128-gcm`, `aes-256-gcm`) |
| Auth | password (EVP_BytesToKey + HKDF-SHA1 `ss-subkey`) |
| UDP | not in this build |
| Transport wrappers | Direct, TLS, WS, WSS, HTTP Upgrade |

**Proprietary:** N/A.  
**Standards-compatible:** Implemented (Phase 6). SS2022 and chacha20 are not in this build. See `crates/shadowsocks/COMPAT.md`.

---

## VLESS

| Aspect | Behavior |
|--------|----------|
| Identity | UUID |
| Encryption / Flow | `none`; Vision is delegated to the external engine |
| Transports | TCP, TLS, Reality, WS/WSS, gRPC, HTTP Upgrade; XHTTP with Xray |
| Config fields | UUID, server, port, encryption, flow, network, security, host/path, Reality and gRPC/XHTTP fields |
| Engine | External Xray first, then sing-box in automatic mode |

UI shows only settings valid for the selected transport.

`rt-vless` is now a process/config/SOCKS adapter rather than a second VLESS implementation. This keeps protocol compatibility in maintained upstream engines. The app currently exposes TCP streams; VLESS UDP and engine mux controls are not exposed. See `crates/vless/COMPAT.md`.

---

## BadVPN UDPGW

| Aspect | Behavior |
|--------|----------|
| Role | Carry UDP (incl. DNS) over a TCP tunnel path |
| Config | host/port (often `127.0.0.1:7300`), transparent DNS toggle |
| Limits | Not every UDP protocol works over every SSH setup — UI exposes status |

**Compatibility:** BadVPN-style UDPGW client (public protocol behavior). See `crates/udpgw/COMPAT.md`.  
**Claim discipline:** diagnostics report availability; no false “all UDP works” claims.

Remote typically: `badvpn-udpgw --listen-addr 127.0.0.1:7300`. The client opens SSH `direct-tcpip` to that host:port.

---

## DNS modes

| Mode | Meaning |
|------|---------|
| System | leave system resolver behavior |
| Tunnel | send DNS via tunnel path |
| Custom | user-specified resolvers |
| Remote | remote/side-channel resolution where protocol allows |

DNS-over-TCP fallback when UDPGW/UDP DNS unavailable.

---

## Documentation rule for new adapters

Every adapter crate must include a `COMPAT.md` section covering:

1. Protocol  
2. Transport  
3. Authentication  
4. Encryption  
5. Handshake  
6. DNS behavior  
7. UDP behavior  
8. IPv6 behavior  
9. Routing behavior  
10. Proprietary vs standards-compatible status  
