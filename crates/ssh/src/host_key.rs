use std::path::PathBuf;
use std::sync::Arc;

use rt_config::HostKeyPolicy;
use russh::keys::{self, HashAlg, PublicKey, PublicKeyBase64};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{Result, SshError};

#[derive(Clone)]
pub struct HostKeyVerifier {
    pub host: String,
    pub port: u16,
    pub policy: HostKeyPolicy,
    pub known_hosts_path: PathBuf,
    /// Set when Ask/TOFU needs UI confirmation — engine may learn after approval.
    pending: Arc<Mutex<Option<PublicKey>>>,
}

impl HostKeyVerifier {
    pub fn new(host: String, port: u16, policy: HostKeyPolicy, known_hosts_path: PathBuf) -> Self {
        Self {
            host,
            port,
            policy,
            known_hosts_path,
            pending: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn verify(&self, key: &PublicKey) -> Result<bool> {
        let path = &self.known_hosts_path;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match keys::check_known_hosts_path(&self.host, self.port, key, path) {
            Ok(true) => Ok(true),
            Ok(false) => match self.policy {
                HostKeyPolicy::Strict => {
                    warn!(host = %self.host, port = self.port, "unknown host key rejected (Strict)");
                    Err(SshError::HostKeyMismatch {
                        host: self.host.clone(),
                        port: self.port,
                    })
                }
                HostKeyPolicy::Tofu => {
                    info!(
                        host = %self.host,
                        port = self.port,
                        fingerprint = %key.fingerprint(HashAlg::Sha256),
                        "trusting host key on first use"
                    );
                    keys::known_hosts::learn_known_hosts_path(&self.host, self.port, key, path)?;
                    Ok(true)
                }
                HostKeyPolicy::Ask => {
                    // Store pending; default deny until UI learns/approves.
                    *self.pending.lock().await = Some(key.clone());
                    warn!(
                        host = %self.host,
                        port = self.port,
                        key = %key.public_key_base64(),
                        "host key unknown — Ask policy requires confirmation"
                    );
                    Err(SshError::HostKeyMismatch {
                        host: self.host.clone(),
                        port: self.port,
                    })
                }
            },
            Err(keys::Error::KeyChanged { line }) => Err(SshError::HostKeyChanged {
                host: self.host.clone(),
                port: self.port,
                line,
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn learn_pending(&self) -> Result<()> {
        let key = self
            .pending
            .lock()
            .await
            .take()
            .ok_or_else(|| SshError::Config("no pending host key".into()))?;
        keys::known_hosts::learn_known_hosts_path(
            &self.host,
            self.port,
            &key,
            &self.known_hosts_path,
        )?;
        Ok(())
    }
}
