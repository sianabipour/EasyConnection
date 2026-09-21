//! Transport adapters: Direct, TLS, WebSocket, WSS, HTTP Upgrade.
//!
//! TLS uses the system OpenSSL library in-process (not `openssl s_client`).
//! Fingerprint profiles only set conventional ALPN. rustls/JA3 impersonation
//! is not claimed. Verification stays on unless the profile sets `verify = false`.

mod fingerprint;
mod openssl_pipe;
mod pool;
mod tcp;

pub use fingerprint::{alpn_for_profile, encode_alpn_wire};
pub use pool::IdlePool;

use std::sync::LazyLock;
use std::time::Duration;

use rt_config::{TlsSettings, Transport};
use rt_websocket::{http_upgrade, websocket_client};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tracing::warn;

use crate::tcp::connect_tcp;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("WebSocket error: {0}")]
    Ws(#[from] rt_websocket::WsError),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

pub trait TransportIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> TransportIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(Debug, Clone)]
pub struct DialRequest {
    pub host: String,
    pub port: u16,
    pub transport: Transport,
    pub tls: TlsSettings,
}

impl DialRequest {
    pub fn from_profile(host: &str, port: u16, transport: Transport, tls: TlsSettings) -> Self {
        Self {
            host: host.to_string(),
            port,
            transport,
            tls,
        }
    }

    pub(crate) fn sni(&self) -> String {
        self.tls
            .sni
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.host)
            .to_string()
    }

    fn host_header(&self) -> String {
        self.tls
            .host
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(self.tls.sni.as_deref())
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.host)
            .to_string()
    }

    fn path(&self) -> String {
        self.tls
            .path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string()
    }
}

/// Cap concurrent TCP/TLS handshakes so a browser connection burst cannot
/// exhaust file descriptors (the failure mode of per-flow `s_client` processes).
static HANDSHAKES: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(64));

/// Open a byte stream to the server using the selected transport.
pub async fn dial(req: &DialRequest) -> Result<Box<dyn TransportIo>> {
    let permit = handshake_permit().await?;
    let stream = dial_unlocked(req).await;
    drop(permit);
    stream
}

async fn handshake_permit() -> Result<tokio::sync::SemaphorePermit<'static>> {
    tokio::time::timeout(Duration::from_secs(20), HANDSHAKES.acquire())
        .await
        .map_err(|_| TransportError::Other("too many concurrent tunnel handshakes".into()))?
        .map_err(|_| TransportError::Other("tunnel handshake limiter closed".into()))
}

async fn dial_unlocked(req: &DialRequest) -> Result<Box<dyn TransportIo>> {
    match req.transport {
        Transport::Direct => {
            let tcp = connect_tcp(&req.host, req.port).await?;
            Ok(Box::new(tcp))
        }
        Transport::Tls => {
            let tls = openssl_pipe::connect(req).await?;
            Ok(Box::new(tls))
        }
        Transport::WebSocket => {
            let tcp = connect_tcp(&req.host, req.port).await?;
            let ws = websocket_client(tcp, &req.host_header(), &req.path()).await?;
            Ok(Box::new(ws))
        }
        Transport::Wss => {
            let tls = openssl_pipe::connect(req).await?;
            let ws = websocket_client(tls, &req.host_header(), &req.path()).await?;
            Ok(Box::new(ws))
        }
        Transport::HttpUpgrade => {
            if req.tls.sni.is_some() || !req.tls.alpn.is_empty() {
                let tls = openssl_pipe::connect(req).await?;
                let upgraded = http_upgrade(tls, &req.host_header(), &req.path()).await?;
                Ok(Box::new(upgraded))
            } else {
                let tcp = connect_tcp(&req.host, req.port).await?;
                let upgraded = http_upgrade(tcp, &req.host_header(), &req.path()).await?;
                Ok(Box::new(upgraded))
            }
        }
    }
}

pub(crate) fn warn_insecure(req: &DialRequest) {
    if !req.tls.verify {
        warn!(
            host = %req.host,
            "TLS certificate verification is disabled for this profile"
        );
    }
}
