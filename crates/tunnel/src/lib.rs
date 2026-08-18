//! Tunnel engine — connection state machine and session orchestration.

mod error;
mod manager;
mod state;
mod transproxy;

pub use error::TunnelError;
pub use manager::ConnectionManager;
pub use state::{ConnectionPhase, ConnectionSnapshot, ConnectionState, TrafficStats};

pub type Result<T> = std::result::Result<T, TunnelError>;
