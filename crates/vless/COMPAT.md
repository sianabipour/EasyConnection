# VLESS adapter compatibility

1. **Protocol** — VLESS TCP request (version 0, UUID, no addons, command TCP).
2. **Transport** — Direct, TLS, WebSocket, WSS, or HTTP Upgrade via `rt-tls::dial`.
3. **Authentication** — UUID only. No extra user/password.
4. **Encryption** — `none` only. Payload after the header is plaintext on the transport (use TLS/WSS for confidentiality).
5. **Handshake** — write request (version, UUID, addon_len=0, cmd=0x01, port BE, ATYP + address); read response (version + addon_len + addons). Remainder is the TCP stream.
6. **DNS** — domains are sent as ATYP 0x02. System DNS follows the profile DNS mode in full/split tunnel.
7. **UDP** — command UDP is not implemented. UDPGW is SSH-only.
8. **IPv6** — ATYP 0x03 for IPv6 destinations.
9. **Routing** — same local SOCKS/HTTP listeners and nft TCP redirect as SSH.
10. **Status** — public VLESS TCP header only. **Not implemented:** `xtls-rprx-vision`, XTLS, Reality, Mux, UDP. Encryption other than `none` is rejected. A remote VLESS inbound with encryption=none is required.
