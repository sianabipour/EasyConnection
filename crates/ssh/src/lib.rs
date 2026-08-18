//! SSH-2 adapter using `russh`.
//!
//! Standards-compatible SSH tunneling. Undocumented proprietary
//! dialects are not implemented.

mod error;
mod host_key;
mod session;

pub use error::SshError;
pub use host_key::HostKeyVerifier;
pub use session::{SshConnectOptions, SshSession, SshUpstream};

pub type Result<T> = std::result::Result<T, SshError>;
