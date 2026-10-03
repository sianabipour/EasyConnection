# RocketTunnel Smart Config exit zones

Status: **listing/preview implemented; selected-country tunneling not implemented**.
The reference client's country picker belongs to an imported Smart Config
`/i/` link. A manually entered SSH Direct host/port/username/password is a
different flow. Its `Welcome to DE4` login banner reports the exit chosen for
that one session; it does not enumerate or select the provider's other exits.

## Evidence and wire format

Analysis of the local RocketTunnel Android 3.0.8 APK identified
`extractMpackedLink`, `getHostsForFetchingZones`, `fetchWithCommand("zone")`,
and the native `smart` flowgraph. An authorized live test with a user-provided
Smart Config link confirmed the following without publishing that link, hosts,
path, or credentials:

1. The `/i/` URL holds a base64 envelope. The observed version-1 payload is
   XOR-obfuscated with a seed, zlib-compressed, and MessagePack-encoded. It
   contains Smart Config hosts, per-host flags, a request path, and credentials.
   Easy decodes this in memory for preview; it does not save the link/password.
2. Hosts with the zone flag (`0x10`) and HTTP (`0x01`) or HTTPS (`0x02`) flag
   receive `POST <smart.path>` with `Content-Type: application/json`,
   `User-Agent: smart_config/1.0`, and the body below. The successful response
   was JSON with `defaultZoneId`, `hash`, and a `zones` array (40 zone objects in
   the tested account). Each object's `id` is the selection key; there is no
   need to guess countries from the SSH banner.

   ```json
   {"command":"zone","username":"<smart username>","password":"<smart password>"}
   ```

3. The native Smart worker fetches an opaque binary tunnel config with
   `GET <smart.path>`. A selected zone is sent in `X-Zone-Id: <zone.id>`;
   automatic/best omits that header. Live requests with and without the header
   returned different `application/octet-stream` bodies. The APK reports
   `smart_config: decrypt failed` for invalid content and routes the decrypted
   result into its `smart` flowgraph. Easy does **not** yet decrypt or run that
   result. Merely sending GET does not change a separate SSH session's exit.

The SSH username remains unchanged. No username suffix or other SSH-direct
selection convention has been verified. RocketTunnel's `forced_country` /
`smart.forced_country.iso` is **destination routing**, not the Smart Config
exit-zone picker.

## Current Easy behavior

- Desktop: Import menu → paste a Smart Config `/i/` link → **Load countries**
  shows a searchable, read-only provider zone list. The link and credentials
  remain in memory for that preview and are not stored as an SSH profile.
- CLI: `easy preview-smart-zones /path/to/private-link-file` lists zones as
  JSON. Use a private local file; never commit the link or pass it in shell
  arguments/history.
- Plain SSH Direct continues to connect normally with automatic exit. Old
  `selected_zone` values are rejected on connect until cleared. The dashboard
  exposes **Clear old zone** for such profiles. `easy fetch-zones <ssh-id>` now
  gives an explanatory error instead of attempting HTTP on the SSH port.
- `ConnectionConfig.selected_zone` and `zones_cache` remain in the database
  schema for compatibility, but Easy does not claim they apply to plain SSH.

## Remaining work for selectable-country Connect

Reverse-engineer and verify the native Smart Config GET response decryption and
its tunnel flowgraph, then add a real Smart Config profile/transport with
credentials in `SecretsStore`. Only after traffic through several explicitly
selected zones has been verified should a selectable-country Connect control
be enabled. Do not synthesize a country catalog, retry SSH until its welcome
banner matches, disable TLS verification, or claim that the GET header alone
applies a zone to SSH Direct.
