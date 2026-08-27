//! Shared TCP socket tweaks for low-latency proxying.

use tokio::net::TcpStream;

/// Disable Nagle so small TLS/HTTP writes are not delayed (~40ms).
pub fn set_nodelay(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "TCP_NODELAY failed");
    }
}
