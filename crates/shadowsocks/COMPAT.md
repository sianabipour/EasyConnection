# Shadowsocks adapter compatibility

1. **Protocol** — Shadowsocks SIP004 AEAD TCP (`aes-128-gcm`, `aes-256-gcm`).
2. **Transport** — Direct, TLS, WebSocket, WSS, or HTTP Upgrade via `rt-tls::dial`.
3. **Authentication** — password in the secrets vault; key is OpenSSL `EVP_BytesToKey` (MD5) then HKDF-SHA1 (`ss-subkey`).
4. **Encryption** — AES-GCM chunked AEAD (2-byte length + payload, 16-byte tags, little-endian nonce counter).
5. **Handshake** — client salt, then AEAD chunks. First plaintext chunk is a SOCKS address (ATYP + dest + port).
6. **DNS** — destination hostnames are sent as SOCKS domains (remote resolve). System DNS still follows the profile DNS mode in full/split tunnel.
7. **UDP** — not implemented. No SS UDP relay / SS2022. Full-tunnel leftover UDP is rejected unless a later phase adds it.
8. **IPv6** — destination IPv6 addresses are encoded in the SOCKS header. Server connect uses the selected transport.
9. **Routing** — same local SOCKS/HTTP listeners and nft TCP redirect as SSH. UDPGW is SSH-only.
10. **Status** — standards-compatible SIP004 TCP client. **Not implemented:** Shadowsocks 2022, `chacha20-ietf-poly1305`, UDP. A remote `ss-server` (or compatible) with a matching AEAD method is required.
