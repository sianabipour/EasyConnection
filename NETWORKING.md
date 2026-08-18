# Networking

Linux networking ownership, TUN/nftables/DNS/routing design for Ubuntu 26.04.

## Ownership boundaries

| Component | Who mutates | Notes |
|-----------|-------------|-------|
| Local SOCKS/HTTP listeners | user engine | no root |
| TUN `easy0` | privileged helper | CAP_NET_ADMIN |
| Routes / rules | privileged helper | snapshot + restore |
| `table inet easy` | privileged helper | isolated table only |
| systemd-resolved DNS | privileged helper | D-Bus / resolvectl typed calls |
| NetworkManager | observe + optional hooks | do not fight NM blindly |

The GUI never calls `nft`, `ip`, or `resolvectl` directly.

## TUN design

- Interface name: `easy0`
- Address: typically point-to-point or `/30`-style userspace TUN addressing (exact plan documented per phase)
- MTU: Automatic (detect overhead) or manual override; **no** silent system-wide MTU changes
- IPv6: optional `::/0` when IPv6 enabled

Packet path (full tunnel):

```text
Application → kernel → easy0 → tunnel engine → remote
```

## nftables

Isolated table:

```text
table inet easy {
  # mark, redirect, kill-switch, DNS intercept chains — named & owned
}
```

Rules:

1. Never edit other tables casually.
2. Every object is removable by name.
3. Startup: detect stale table/interface → clean.
4. Shutdown / SIGTERM: flush owned objects.

## Routing modes

| Mode | Behavior |
|------|----------|
| Proxy Only | no TUN; local listeners only |
| Full Tunnel | default routes via TUN (`0.0.0.0/0`, `::/0` if IPv6) |
| Split Tunnel | selective prefixes/domains (+ future cgroup/process) |
| Bypass private | RFC1918 / ULA / link-local bypass unless user forces full |

Policy routing (fwmark + ip rules) is preferred for split/kill-switch composability.

## Transactional apply

```text
1. Snapshot routes, DNS, nft ownership, interface list
2. Apply minimal delta
3. Verify (interface up, rule present, optional probe)
4. On failure → rollback snapshot
```

## DNS integration (Ubuntu 26.04)

Prefer **systemd-resolved**:

- Set DNS / Domains / DNSOverTLS via helper for the TUN or default link as appropriate.
- Do **not** blindly overwrite `/etc/resolv.conf` when it is a symlink to stub-resolv.conf.
- Leak prevention: ensure DNS queries follow intended path (tunnel / UDPGW / DoT-TCP fallback).

## Kill switch

When enabled and tunnel down: block non-bypass traffic that would leak outside the tunnel.

Recovery:

- Explicit “Disable kill switch & restore networking” in UI and CLI.
- Helper safe-mode on boot if last session crashed with kill switch armed.

## Network change handling

Listen for:

- NetworkManager state / link changes
- suspend/resume (logind)
- default route changes

On change: health-check → reconnect with backoff; re-apply routes if still connected.

## Cleanup contract

Disconnect / crash recovery / uninstall must leave:

- no `easy0`
- no `table inet easy`
- no leftover default routes pointing at our TUN
- DNS restored to pre-connect snapshot

## Phase mapping

| Capability | Phase |
|------------|-------|
| Proxy-only (no netns mutation) | 2 (implemented) |
| TUN + full tunnel TCP | 3 (implemented) |
| DNS + IPv6 | 4 (implemented) |
| UDPGW / transparent DNS | 5 (implemented; SSH-only) |
| TLS / WS / SS / VLESS | 6 (implemented) |
| Split / kill switch / share | 7 (kill-switch foundation is in Phase 3) |

Full tunnel is **not** SSH `Tunnel=point-to-point` (that would require server-side tun). The engine intercepts locally generated TCP with nftables and forwards it over the selected protocol (SSH `direct-tcpip`, Shadowsocks AEAD, or VLESS):

```text
Application → kernel TCP → nftables table inet easy (output NAT redirect)
           → 127.0.0.1:13450 transproxy → upstream connector → remote
```

The path to the remote server may be Direct TCP or TLS / WebSocket / WSS / HTTP Upgrade (`openssl s_client` + RFC 6455).

`easy0` is created, addressed, and owned by the helper. Phase 3 does **not** run a userspace TCP/IP stack on the TUN, so default routes are **not** pointed at the TUN (that would blackhole traffic).

Phase 5 UDP: when UDPGW connects, leftover UDP is nft-redirected to `127.0.0.1:13451` (original dest via `IP_RECVORIGDSTADDR`) and framed as BadVPN UDPGW over SSH `direct-tcpip` to the configured remote (default `127.0.0.1:7300`). If UDPGW is off or unreachable, leftover UDP is still rejected. This is not a userspace IP stack on the TUN.

DNS for processes using UDP/53 is redirected to a local listener and answered with DNS-over-TCP through the same SSH path.

Phase 4 DNS policy (helper uses `resolvectl` on `easy0` only — never a blind `/etc/resolv.conf` overwrite):

| Mode | Behavior |
|------|----------|
| System | Leave systemd-resolved alone (proxy-only). Full/split tunnel upgrades this to Tunnel so LAN DNS does not leak. |
| Tunnel / Remote | `resolvectl dns/domain/default-route` on the TUN (`1.1.1.1` `8.8.8.8` unless the profile lists servers) + UDP/53 → DNS-over-TCP. |
| Custom | Same path with the profile's DNS IPs. |
| Disconnect | `resolvectl revert easy0` and flush caches. |

IPv6: when the profile has IPv6 off, nftables rejects public IPv6 so Happy Eyeballs falls back to IPv4. When on, the helper adds ULA `fd72:6f63:6b65::2/64` on the TUN, dual-stack `meta l4proto` redirect, and the engine listens on `[::1]:13450` / `[::1]:13453`. There is still no userspace IPv6 stack, so `::/0` is not pointed at the TUN.

Leak report: `easy dns-status` or Routing → Run check (TUN present, nft table, link DNS, global IPv6, UDP redirect).

nftables: only `table inet easy`. Kill switch adds a final `reject` after accepts for lo/TUN/server/bypass.

Emergency restore: `easy emergency-restore` or `sudo easy-helper --cleanup-and-exit`.

