//! SSH-2 adapter using `russh`.
//!
//! Standards-compatible SSH tunneling. Optional exit zones use the
//! plaintext smart-config HTTP contract in `docs/ZONES.md`. The encrypted
//! smart-config blob is not implemented.

mod error;
mod host_key;
mod session;
mod zones;

pub use error::SshError;
pub use host_key::HostKeyVerifier;
pub use session::{SshConnectOptions, SshSession, SshUpstream};
pub use zones::{
    http_request, parse_zone_list, ssh_username_for_zone, zone_command_body, HttpZoneProvider,
    ZoneFetchRequest, ZoneHttpRequest, ZoneList, ZoneProvider,
};

pub type Result<T> = std::result::Result<T, SshError>;
