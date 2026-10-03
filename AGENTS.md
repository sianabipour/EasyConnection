# Easy development handoff

## Current work: RocketTunnel Smart Config zones (2026-10-03)

The user's country picker in RocketTunnel is attached to a **Smart Config `/i/` link**, not to a manually entered SSH Direct profile. Do not treat an SSH login banner such as `Welcome to DE4` as a zone list. Do not put the user's private link, credentials, or decoded hostnames in this repository or logs.

Verified against the local RocketTunnel 3.0.8 APK and the user-authorized Smart Config link:

- Hermes `extractMpackedLink` calls the Smart Config decoder. The `/i/` payload has a two-byte header: version/lock/compression flags and a seed. The observed link is version 1, XOR-obfuscated, zlib-compressed MessagePack. The XOR mask starts `[58,127,178,217,76,133,225,98]`, with each byte combined with the shifted seed. The MessagePack root contains a `smart` config with username, password, path, and flagged hosts.
- `SmartConfigZoneRepository.getHostsForFetchingZones` selects hosts with the zone bit (`0x10`) and HTTP (`0x01`) or HTTPS (`0x02`) flags. `fetchWithCommand("zone")` sends `POST <smart.path>` with JSON `{command,username,password}` to these hosts. The authorized live request returned HTTP 200 and JSON keys `defaultZoneId`, `zones`, `hash`, with 40 zones. Zone IDs include lowercase country IDs (e.g. `al1`) and special IDs beginning `#`.
- The native smart worker issues `GET <smart.path>` with `X-Zone-Id: <zone.id>` when selected; Auto omits the header. Live GETs for Auto and two zone IDs returned HTTP 200 `application/octet-stream` with different bodies. These are encrypted/opaque tunnel configs, not instructions to modify an SSH username. The native `smart` flowgraph consumes the decrypted response. **Easy does not yet implement this decrypt/tunnel path.** Do not claim a selected exit country works until end-to-end traffic is verified.
- The old Easy SSH code invented a 29-country catalog from an SSH welcome banner, then tried HTTP/TLS on the SSH port. That cannot list or apply Smart Config zones. This is being removed/disabled.

Implemented in the current checkout (uncommitted; do not discard user changes):

- `crates/config/src/smart_link.rs`: read-only `/i/` link decoder with synthetic envelope tests. It parses the observed version-1 envelope and Smart Config host metadata. No private fixture is committed.
- `crates/core/src/app.rs`: `preview_smart_zones` reads zones from decoded Smart Config hosts; `fetch_zones` for plain SSH gives an explicit error; forced zone on plain SSH is rejected, while clearing a legacy selection is allowed.
- `crates/ssh/src/zones.rs`: removed the invented country catalog, SSH-password banner probe, and HTTP/TLS guessing on SSH ports; requires the Smart Config host's explicit scheme/path for the real HTTP zone request. `crates/ssh/src/session.rs` rejects legacy `selected_zone` on plain SSH instead of silently connecting to a random exit.
- `apps/desktop/src-tauri`, `apps/desktop/src/lib/api.ts`, `apps/desktop/src/pages/HomePage.tsx`, and `SmartZonePreview.tsx`: read-only Smart Config zone preview from Import, with search/count/loading/error; old SSH Change Zone UI removed and legacy selections can be cleared. Dashboard holds the single Connect button; Servers page has no per-profile Connect button.
- `apps/cli/src/main.rs`: `easy preview-smart-zones /path/to/private-link-file` outputs only the zone list. Plain SSH `fetch-zones` is explanatory; `connect --zone auto` clears a legacy value.
- `docs/ZONES.md`, `PROTOCOLS.md`, `README.md`, `ROADMAP.md`: now state the verified contract and missing encrypted tunnel step without claiming selected-country Connect works.

Verification: `cargo check --workspace --offline`, `cargo test --workspace --offline` (unit and doc tests passed), `cargo clippy --workspace --all-targets --offline -- -D warnings`, `cargo fmt --all -- --check`, `npm run lint`, and `npm run build` passed. The sandbox denies even loopback socket binds; a local HTTP-server test was therefore replaced by no-network request/response tests. Clippy required narrow `too_many_arguments` allowances on six pre-existing, flattened Tauri command/helper signatures to keep the current IPC shape. Temporary decoded/request buffers are zeroized where practical; no credential is persisted by preview.

Next steps:

1. For deeper validation, use a private local test fixture or a manually approved runtime test against the user's own Smart Config link; never print or commit the link. Assess parser hardening and secret lifetimes further. A loopback HTTP integration test needs an environment that permits socket binds.
2. Investigate the encrypted GET response and implement a genuine Smart Config transport/profile with credentials in `SecretsStore` before offering selectable-zone Connect. The APK's native smart worker is ARM64 and decryption is not yet understood. This is the major unresolved blocker; `X-Zone-Id` alone is **not** a working SSH-direct routing mechanism.
3. Test end-to-end traffic through multiple explicitly selected zones only after native response/tunnel support exists. Never infer routing from only the SSH welcome banner or claim HTTP GET alone applies a zone to a separate SSH session.

Temporary reverse-engineering files are under `/tmp/easy-hermes-dec`, `/tmp/easy-rocket.hasm`, and `/tmp/rt-inspect`. The private link is **not** stored there; do not copy the live link into tests or docs. The user's only live Smart Config requests so far were to hosts decoded from their own link, under explicit authorization.
