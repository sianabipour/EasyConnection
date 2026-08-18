//! WebSocket and HTTP Upgrade byte pipes (RFC 6455 client + raw HTTP/1.1 Upgrade).

mod http_upgrade;
mod ws;

pub use http_upgrade::http_upgrade;
pub use ws::{websocket_client, WsByteStream};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, WsError>;
