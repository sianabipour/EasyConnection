//! VLESS TCP client (public UUID header, encryption=none).
//! Vision / XTLS flow is not implemented.

mod header;

pub use header::{encode_request, read_response};

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rt_config::{ConnectionConfig, ProtocolSettings};
use rt_socks::{SocksError, UpstreamConnector, UpstreamIo};
use rt_tls::{DialRequest, IdlePool};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum VlessError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("transport: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, VlessError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct VlessConnector {
    uuid: Uuid,
    pool: Arc<IdlePool>,
}

impl VlessConnector {
    pub fn from_profile(cfg: &ConnectionConfig) -> Result<Self> {
        let (uuid, encryption, flow, host, path) = match &cfg.settings {
            ProtocolSettings::Vless {
                uuid,
                encryption,
                flow,
                host,
                path,
            } => (uuid, encryption, flow, host, path),
            _ => return Err(VlessError::Config("not a VLESS profile".into())),
        };
        if !encryption.is_empty() && !encryption.eq_ignore_ascii_case("none") {
            return Err(VlessError::Config(
                "VLESS encryption must be none (Vision/XTLS is not implemented)".into(),
            ));
        }
        if flow.to_ascii_lowercase().contains("vision") {
            return Err(VlessError::Config(
                "VLESS xtls-rprx-vision is not implemented".into(),
            ));
        }
        let uuid = Uuid::parse_str(uuid).map_err(|e| VlessError::Config(e.to_string()))?;
        let mut tls = cfg.tls.clone();
        if tls.path.is_none() {
            tls.path = path.clone();
        }
        if tls.host.is_none() {
            tls.host = host.clone();
        }
        let dial = DialRequest::from_profile(&cfg.host, cfg.port, cfg.transport, tls);
        // Keep a few warm TLS/TCP sessions so the first filtered-site open
        // does not wait on a fresh handshake (and we never spawn openssl).
        let pool = IdlePool::new(dial, 4);
        Ok(Self { uuid, pool })
    }

    /// Prefill idle transports in the background after the tunnel is up.
    pub fn warm_up(&self) {
        let pool = Arc::clone(&self.pool);
        tokio::spawn(async move {
            pool.fill(3).await;
        });
    }
}

#[async_trait]
impl UpstreamConnector for VlessConnector {
    async fn connect(&self, host: &str, port: u16) -> rt_socks::Result<Box<dyn UpstreamIo>> {
        let pool = Arc::clone(&self.pool);
        let uuid = self.uuid;
        let host = host.to_string();
        let timeout_host = host.clone();
        tokio::time::timeout(CONNECT_TIMEOUT, async move {
            let mut raw = pool
                .take()
                .await
                .map_err(|e| SocksError::Upstream(format!("VLESS transport {e}")))?;
            let req = encode_request(uuid, &host, port);
            raw.write_all(&req)
                .await
                .map_err(|e| SocksError::Upstream(e.to_string()))?;
            raw.flush()
                .await
                .map_err(|e| SocksError::Upstream(e.to_string()))?;
            read_response(raw.as_mut())
                .await
                .map_err(|e| SocksError::Upstream(e.to_string()))?;
            Ok(Box::new(raw) as Box<dyn UpstreamIo>)
        })
        .await
        .map_err(|_| SocksError::Upstream(format!("VLESS connect to {timeout_host}:{port} timed out")))?
    }
}
