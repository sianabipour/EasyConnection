# TLS / transport adapter compatibility

1. **Protocol** — byte-stream transports: Direct TCP, TLS, WebSocket, WSS, HTTP Upgrade.
2. **Transport** — `rt-tls::dial` opens the selected wrapper, then the protocol (SSH / SS / VLESS) speaks on the stream.
3. **Authentication** — none at this layer. TLS uses the system CA store via `openssl s_client`.
4. **Encryption** — TLS 1.2/1.3 as negotiated by OpenSSL. Direct / plain WebSocket / plain HTTP Upgrade are unencrypted.
5. **Handshake** — TLS: `openssl s_client -connect host:port -servername SNI` (plus `-verify_return_error` when verify is on, `-alpn` when set). WebSocket / Upgrade: see `crates/websocket/COMPAT.md`.
6. **DNS** — server hostname is resolved by the OS before connect. Application DNS is a higher layer.
7. **UDP** — not carried here. UDPGW remains SSH-only (Phase 5).
8. **IPv6** — `TcpStream::connect` / OpenSSL `-connect` accept IPv6 literals and names.
9. **Routing** — transport is only the path to the remote server. System routing is unchanged until the tunnel engine applies nft/TUN.
10. **Status** — standards-compatible wrappers. Fingerprint profiles (Chrome/Firefox/Safari/Custom) only pick conventional ALPN when the user left ALPN empty. They are **not** JA3 / rustls impersonation. Verification stays on unless the profile sets `verify = false`. SSH-over-TLS keeps ALPN empty unless the user set it (`h2` would break SSH). Requires `openssl` on PATH.
