//! SSH-2 adapter using `russh`.
//!
//! Standards-compatible SSH tunneling. RocketTunnel Smart Config zone-list
//! previews use a separate HTTP contract; selecting an exit for SSH Direct is
//! not implemented. See `docs/ZONES.md`.

mod error;
mod host_key;
mod session;
mod zones;

pub use error::SshError;
pub use host_key::HostKeyVerifier;
pub use session::{SshConnectOptions, SshSession, SshUpstream};
pub use zones::{
    http_request, parse_zone_list, ssh_username_for_zone, zone_command_body, zones_from_welcome,
    HttpZoneProvider, ZoneFetchRequest, ZoneHttpRequest, ZoneList, ZoneProvider,
};

pub type Result<T> = std::result::Result<T, SshError>;
