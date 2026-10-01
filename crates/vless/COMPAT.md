# VLESS adapter compatibility

1. **Protocol engine** — an installed Xray or sing-box process owns VLESS framing, TLS/Reality, and transport behavior. Easy Connection does not implement the VLESS wire protocol.
2. **Selection** — `EASY_VLESS_ENGINE=auto` (default) tries Xray and then sing-box. Use `xray` or `sing-box` to force one. Custom binary paths can be supplied with `EASY_XRAY_PATH` and `EASY_SING_BOX_PATH`.
3. **Transport** — TCP, WebSocket, gRPC, and HTTP Upgrade work with either engine. XHTTP requires Xray.
4. **Security / flow** — `none`, TLS, Reality, and `xtls-rprx-vision` are passed to the selected engine. `xtls-rprx-vision-udp443` and XHTTP require Xray.
5. **Integration** — the engine exposes a randomly selected SOCKS5 port bound only to `127.0.0.1`. The existing local SOCKS/HTTP and transparent TCP paths connect through it.
6. **Secrets** — generated engine configuration is written mode `0600`, is never logged, and is removed after startup.
7. **Lifecycle** — the child process is tied to the active connector and is terminated on disconnect or startup failure.
8. **DNS / IPv6** — SOCKS domain names and IPv4/IPv6 literals are forwarded to the engine.
9. **UDP** — the current Easy Connection upstream interface is TCP. VLESS UDP is not exposed yet.
10. **Failure behavior** — a missing or incompatible engine produces a connection error; it must not crash the desktop process.
