# SSH-direct zones

RocketTunnel 3.0.8 (`com.hypertunnel.android`, package inspected locally) calls this
**zones**. One SSH entry host can offer many exit countries. Easy implements the
plaintext parts of that contract. It does not invent the encrypted smart-config
blob decryptor.

## What the reference client does

Two different mechanisms share the word “zone”:

1. **Exit zones** (this feature). `SmartConfigZoneRepository.fetchZones` POSTs JSON
   to entry hosts whose flag has the `zone` bit (`0x10`) plus `http` (`0x01`) or
   `https` (`0x02`). The UI is `SmartConfigZonePickerView`: search, tap to select,
   tap again to clear. Copy in the client: if nothing is selected, the best zone
   is chosen automatically. Cache key `smartConfigZonesCache`. Errors:
   `Could not load zones. Check connection and try again.` and
   `Invalid response: no zones`.
2. **Destination routing.** `router.smart.mode` is one of
   `restricted_regions`, `forced_country`, `auto_detect_country`, `disabled`.
   `smart.forced_country.iso` plus ipdeny `*.zone` files decide which *destination*
   countries go through the tunnel. That is not an exit-country picker.

`ssh_common_parse_banner` reads `settings.banner.version` and
`settings.banner.comment` from the flowgraph config. It is not the zone list.

## Listing zones

Easy sends this to the profile host and port (path `/`):

```http
POST / HTTP/1.1
Host: <host>[:port]
Connection: close
User-Agent: smart_config/1.0
Accept: */*
Content-Type: application/json

{"command":"zone","username":"<user>","password":"<password>"}
```

A usable body is JSON with a `zones` array (also accepted under `response.zones`)
and an optional `hash` used as the cache token. Each item is a string id or an
object. `id` is what connect sends later. Display name and ISO are taken from
`name` / `countryName` / `iso` / `isoCode` / `code` when present.

An OpenSSH banner (`SSH-2.0-…`) or a body without `zones` is a failed load.
The picker stays empty and SSH connect is unchanged.

## Applying a selection

The native smart-config worker builds:

```http
GET <path> HTTP/1.1
Host: <host>[:port if not 80]
Connection: close
User-Agent: smart_config/1.0
Accept: */*
X-Zone-Id: <zone.id>
```

`X-Zone-Id` is omitted when no zone is selected (Auto / best). The response body
of that GET is decrypted by RocketTunnel (`smart_config: decrypt failed`).
That decrypt format is proprietary and is **not** implemented here.

Easy keeps the SSH username as stored (`ssh_username_for_zone` does not rewrite
it). When a zone id is saved, connect sends the `X-Zone-Id` GET to the entry
host before the SSH handshake, then opens SSH with the normal username and
password. If that HTTP request fails (typical for a plain OpenSSH port), SSH
still connects.

## Where it lives

- `ConnectionConfig.selected_zone` and `zones_cache` in `crates/config`
- `ZoneProvider` / `HttpZoneProvider` in `crates/ssh`
- `easy fetch-zones <id>` and `easy connect <id> --zone <id|auto>`
- Desktop: edit an SSH profile → Load countries
