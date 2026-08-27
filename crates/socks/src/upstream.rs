use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::server::ProxyStats;
use crate::{Result, SocksError};

/// Combined stream trait for tunnel upstreams (avoids trait-object limits).
pub trait UpstreamIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> UpstreamIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Opens a TCP connection to the target — either direct or via SSH/tunnel.
#[async_trait]
pub trait UpstreamConnector: Send + Sync + 'static {
    async fn connect(&self, host: &str, port: u16) -> Result<Box<dyn UpstreamIo>>;
}

/// Direct (non-tunneled) connector for testing and proxy-chaining later.
#[allow(dead_code)]
pub struct DirectConnector;

#[async_trait]
impl UpstreamConnector for DirectConnector {
    async fn connect(&self, host: &str, port: u16) -> Result<Box<dyn UpstreamIo>> {
        let addr = format!("{host}:{port}");
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| SocksError::Upstream(format!("connect {addr}: {e}")))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }
}

/// Bidirectional copy until either side EOF.
pub async fn relay_both<A, B>(mut a: A, mut b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok(v) => Ok(v),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok((0, 0)),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok((0, 0)),
        Err(e) => Err(e),
    }
}

/// Count bytes: client→upstream as up, upstream→client as down.
pub fn record_relay(stats: &ProxyStats, a_to_b: u64, b_to_a: u64) {
    use std::sync::atomic::Ordering;
    stats.bytes_up.fetch_add(a_to_b, Ordering::Relaxed);
    stats.bytes_down.fetch_add(b_to_a, Ordering::Relaxed);
}
