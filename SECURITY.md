# Security Model

## Threat model (summary)

| Threat | Mitigation |
|--------|------------|
| Credential theft from disk | Secret Service / encrypted store; SQLite holds refs only |
| Credential leakage in logs | Redaction filters; never log passwords/keys/tokens |
| Privilege escalation via GUI | Separate root helper; allowlisted IPC; no shell |
| Command injection | No `bash -c` / `system()` with user input; typed APIs |
| Path traversal on import/export | Canonicalize + confine to app dirs |
| Malicious config import | Schema validation; no code execution |
| MITM on SSH/TLS | Host-key verification + cert validation ON by default |
| Networking state corruption | Snapshot/apply/verify/rollback; startup stale cleanup |
| Kill switch lockout | Explicit recovery path + safe-mode disconnect |
| LAN proxy exposure | Opt-in; clear warning; optional auth |

## Privileged helper

- Runs as systemd service with minimal capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW` as needed).
- Socket `/run/easy/helper.sock` (mode 0666 when `--allow-active-sessions`, otherwise 0660). Override with `EASY_HELPER_SOCKET`.
- Authorization: `SO_PEERCRED` uid must be root, listed with `--allow-uid`, or have `/run/user/$UID` when active-session auth is on.
- Commands are an enum allowlist (`Ping`, `Apply`, `Teardown`, `Cleanup`, `EmergencyRestore`).
- `Apply` only accepts TUN name `easy0` and already-parsed IP addresses.
- No arbitrary command execution channel.
- Client disconnect, SIGTERM, helper start, and `--cleanup-and-exit` all restore routes / nft / TUN.
- All mutations are journaled under `/run/easy/session.json` for rollback.

## Cryptography & trust

- SSH: verify `known_hosts`; configurable policy (`Strict`, `Ask`, `TOFU` with UI confirmation — never silent ignore).
- TLS: `rustls` with WebPKI roots; verification enabled by default; optional user-supplied CA.
- Fingerprint mimicry (when implemented) does **not** disable certificate verification.

## Secrets

- Preferred: FreeDesktop Secret Service (`libsecret`).
- Fallback (dev/CI/headless): AES-GCM encrypted file under `~/.config/easy/secrets.bin` with key from OS keyring or machine-bound material; document limitations.
- Export format omits secrets unless user selects encrypted export.

## Logging rules

Forbidden in any log level:

- passwords
- private keys / key passphrases
- Secret Service items
- full Authorization headers
- SOCKS/HTTP proxy credentials

Allowed: usernames (optional), hostnames, ports, error codes, redacted digests.

## IPC hardening

- Tauri commands validate all inputs (ports, paths, UUIDs, enums).
- Helper protocol uses length-prefixed bincode/JSON with schema version.
- Reject unknown fields that imply execution.

## Filesystem permissions

| Path | Mode |
|------|------|
| `~/.config/easy/` | `0700` |
| `state.db` | `0600` |
| `secrets.bin` | `0600` |
| known_hosts (app) | `0600` |
| helper socket | `0660` root:`easy` group (planned) |

## Supply chain

- Pin crate versions in workspace.
- CI runs `cargo audit`, `cargo clippy`, `cargo fmt --check`, `npm audit`.
- Prefer maintained crates over custom crypto.

## Import safety

- JSON/URI parsers only.
- Size limits and recursion limits.
- Reject `file://` that escape allowed directories.
- Never treat config values as shell fragments.

## Crash & uninstall safety

On helper start: detect stale `easy0`, stale nft tables, leftover routes → clean.

On package uninstall: stop service, remove table/routes/TUN, remove unit files.

## Reporting

Security issues should be handled privately until fixed; do not file public issues with exploit details for privilege-escalation bugs.
