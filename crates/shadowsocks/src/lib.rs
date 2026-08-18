//! Shadowsocks AEAD (SIP004) TCP client. SS2022 is not implemented.

mod addr;
mod aead;

pub use addr::encode_socks_addr;
pub use aead::{evp_bytes_to_key, AeadMethod, SsStream};

use async_trait::async_trait;
use rt_config::{ConnectionConfig, ProtocolSettings};
use rt_secrets::SecretsStore;
use rt_socks::{SocksError, UpstreamConnector, UpstreamIo};
use rt_tls::{dial, DialRequest};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("transport: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, SsError>;

#[derive(Clone)]
pub struct ShadowsocksConnector {
    server_host: String,
    server_port: u16,
    method: AeadMethod,
    key: Vec<u8>,
    dial: DialRequest,
}

impl ShadowsocksConnector {
    pub fn from_profile(cfg: &ConnectionConfig, secrets: &SecretsStore) -> Result<Self> {
        let method = match &cfg.settings {
            ProtocolSettings::Shadowsocks { method } => AeadMethod::parse(method)?,
            _ => return Err(SsError::Config("not a Shadowsocks profile".into())),
        };
        let password = match &cfg.authentication {
            rt_config::AuthMethod::Password { secret: Some(s) } => secrets
                .get_secret(s)
                .map_err(|e| SsError::Config(e.to_string()))?,
            _ => {
                return Err(SsError::Config(
                    "Shadowsocks password is missing from the secrets vault".into(),
                ))
            }
        };
        let key = aead::evp_bytes_to_key(password.as_bytes(), method.key_len());
        Ok(Self {
            server_host: cfg.host.clone(),
            server_port: cfg.port,
            method,
            key,
            dial: DialRequest::from_profile(&cfg.host, cfg.port, cfg.transport, cfg.tls.clone()),
        })
    }
}

#[async_trait]
impl UpstreamConnector for ShadowsocksConnector {
    async fn connect(&self, host: &str, port: u16) -> rt_socks::Result<Box<dyn UpstreamIo>> {
        let raw = dial(&self.dial)
            .await
            .map_err(|e| SocksError::Upstream(format!("SS transport {e}")))?;
        let mut ss = SsStream::handshake(raw, self.method, &self.key)
            .await
            .map_err(|e| SocksError::Upstream(e.to_string()))?;
        let header = encode_socks_addr(host, port);
        ss.write_payload(&header)
            .await
            .map_err(|e| SocksError::Upstream(e.to_string()))?;
        let _ = (self.server_host.as_str(), self.server_port);
        Ok(Box::new(ss))
    }
}
