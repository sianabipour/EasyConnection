# RocketTunnel Smart Config exit zones

Import a version-1 `/i/` link and use **Change zone** on its dashboard profile.
Selecting a row saves the provider ID for the next connection. Disconnect an
active tunnel before connecting with the new choice.

The link contains compressed MessagePack with credentials, a path and flagged
hosts. Zone-capable HTTP(S) hosts accept a POST to that path with JSON fields
`command` (value `zone`), `username` and `password`. The response lists zones
by ID. Connect sends a GET to the path with `X-Zone-Id` set to that ID. Auto
omits the header. The encrypted response contains a 12-byte nonce followed by
AES-256-GCM ciphertext and a 16-byte tag. The decrypted patch supplies the SSH
endpoint. Easy substitutes the link credentials for literal `<<username>>`
and `<<password>>` markers. A password-authenticated `ssh_direct` endpoint
uses TCP. The supported `ssh_darktunnel` variant requires its payload and
banner-matching shim before SSH begins.

Live SOCKS5 HTTPS checks returned DE for de4 and AT for at1. For al1, both
Cloudflare and IPinfo reported PL. Zone IDs express a provider selection;
IP geolocation is measured separately. Plain SSH profiles have no zone API.
