//! Transport adapters: Direct, TLS, WebSocket, WSS, HTTP Upgrade.
//!
//! TLS uses the system `openssl s_client` so we do not invent a TLS stack and
//! do not need extra crates. Fingerprint profiles only set conventional ALPN.
//! rustls/JA3 impersonation is not claimed. Verification stays on unless the
//! profile sets `verify = false`.

mod fingerprint;
mod openssl_pipe;

pub use fingerprint::alpn_for_profile;

use rt_config::{TlsSettings, Transport};
use rt_websocket::{http_upgrade, websocket_client};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::warn;

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

/// Open a byte stream to the server using the selected transport.
pub async fn dial(req: &DialRequest) -> Result<Box<dyn TransportIo>> {
    match req.transport {
        Transport::Direct => {
            let tcp = TcpStream::connect((req.host.as_str(), req.port)).await?;
            let _ = tcp.set_nodelay(true);
            Ok(Box::new(tcp))
        }
        Transport::Tls => {
            let tls = openssl_pipe::connect(req).await?;
            Ok(Box::new(tls))
        }
        Transport::WebSocket => {
            let tcp = TcpStream::connect((req.host.as_str(), req.port)).await?;
            let _ = tcp.set_nodelay(true);
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
                let tcp = TcpStream::connect((req.host.as_str(), req.port)).await?;
                let _ = tcp.set_nodelay(true);
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
