# WebSocket / HTTP Upgrade compatibility

1. **Protocol** — RFC 6455 WebSocket client (binary frames) and raw HTTP/1.1 `Upgrade` (no WebSocket framing).
2. **Transport** — runs on an already-open TCP or TLS stream supplied by `rt-tls`.
3. **Authentication** — none. No cookies or extra headers beyond Host / Upgrade / Sec-WebSocket-*.
4. **Encryption** — none at this layer; use WSS (TLS then WS) for encryption.
5. **Handshake** — WS: `GET path` + `Upgrade: websocket` + `Sec-WebSocket-Key` / Version 13; expects `101` and matching `Sec-WebSocket-Accept`. HTTP Upgrade: `GET path` + `Connection: Upgrade` + `Upgrade: websocket`; expects `101`.
6. **DNS** — Host header comes from profile `tls.host`, then SNI, then server host.
7. **UDP** — not applicable; this is a byte pipe for TCP protocols.
8. **IPv6** — inherited from the underlying stream.
9. **Routing** — path/host are profile fields (`tls.path`, `tls.host`). Default path is `/`.
10. **Status** — standards-compatible client. Not a full browser WS stack (no extensions, no permessage-deflate, client masking only). HTTP Upgrade is the V2Ray-style raw upgrade, not WebSocket.
