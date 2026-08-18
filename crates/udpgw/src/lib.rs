//! BadVPN-compatible UDPGW client (Phase 5).
//!
//! Carries UDP (and optional DNS) over a reliable stream such as SSH
//! `direct-tcpip` to a remote `badvpn-udpgw` (typically `127.0.0.1:7300`).

mod client;
mod proto;

pub use client::{run_udpgw, IoStream, UdpgwHandle};
pub use proto::{
    decode_body, encode_body, encode_frame, UdpgwPacket, FLAG_DNS, FLAG_IPV6, FLAG_KEEPALIVE,
    FLAG_REBIND,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UdpgwError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Packet(String),
    #[error("UDPGW connection closed")]
    Closed,
    #[error("UDPGW DNS query timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, UdpgwError>;

/// Default remote listen address used by `badvpn-udpgw`.
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 7300;
