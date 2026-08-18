# UDPGW adapter compatibility

1. **Protocol** — BadVPN UDPGW over PacketProto (public headers in `badvpn`).
2. **Transport** — reliable stream; Easy Connection uses SSH `direct-tcpip` to the configured host/port (usually remote `127.0.0.1:7300`).
3. **Authentication** — none on the UDPGW socket; access is the SSH session.
4. **Encryption** — whatever the SSH channel already provides.
5. **Handshake** — none; first PacketProto frame is a UDPGW header.
6. **DNS** — optional `FLAG_DNS` datagrams to a resolver:53; DNS-over-TCP remains the fallback.
7. **UDP** — multiplexed by 16-bit `conid`. Not every UDP application survives NAT + TCP encapsulation (QUIC/games vary).
8. **IPv6** — `FLAG_IPV6` when the destination is IPv6; requires a dual-stack remote udpgw.
9. **Routing** — system UDP is nft-redirected only in full/split tunnel after the client connects. Proxy-only does not intercept host UDP.
10. **Status** — standards-compatible BadVPN client. Remote must run `badvpn-udpgw` (or a compatible daemon). The UI never claims “all UDP works”.
