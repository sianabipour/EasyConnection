use std::sync::Arc;

use rt_config::{
    validate_connection, AppSettings, AuthMethod, ConfigStore, ConnectionConfig, ExportDocument,
};
use rt_secrets::{SecretRef, SecretsStore};
use rt_tunnel::{ConnectionManager, ConnectionSnapshot};
use tokio::sync::watch;
use uuid::Uuid;

use crate::Result;

pub struct AppController {
    pub store: ConfigStore,
    pub secrets: Arc<SecretsStore>,
    pub connections: Arc<ConnectionManager>,
}

impl AppController {
    pub fn bootstrap() -> Result<Self> {
        let store = ConfigStore::open_default()?;
        let secrets = Arc::new(SecretsStore::open_default()?);
        let connections = Arc::new(ConnectionManager::new(Arc::clone(&secrets)));
        Ok(Self {
            store,
            secrets,
            connections,
        })
    }

    pub fn bootstrap_at(
        db_path: impl AsRef<std::path::Path>,
        secrets_path: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let store = ConfigStore::open(db_path.as_ref())?;
        let secrets = Arc::new(SecretsStore::open_path(
            secrets_path.as_ref().to_path_buf(),
            b"dev-binding",
        )?);
        let known_hosts = db_path.as_ref().parent().map(|p| p.join("known_hosts"));
        let connections = Arc::new(ConnectionManager::with_known_hosts(
            Arc::clone(&secrets),
            known_hosts,
        ));
        Ok(Self {
            store,
            secrets,
            connections,
        })
    }

    pub fn list_profiles(&self) -> Result<Vec<ConnectionConfig>> {
        Ok(self.store.list_profiles()?)
    }

    pub fn get_profile(&self, id: Uuid) -> Result<ConnectionConfig> {
        Ok(self.store.get_profile(id)?)
    }

    pub fn save_profile(&self, mut cfg: ConnectionConfig) -> Result<ConnectionConfig> {
        cfg.updated_at = chrono::Utc::now();
        validate_connection(&cfg)?;
        self.store.upsert_profile(&cfg)?;
        Ok(cfg)
    }

    pub fn delete_profile(&self, id: Uuid) -> Result<()> {
        Ok(self.store.delete_profile(id)?)
    }

    pub fn duplicate_profile(&self, id: Uuid) -> Result<ConnectionConfig> {
        let mut cfg = self.store.get_profile(id)?;
        cfg.id = Uuid::new_v4();
        cfg.name = format!("{} (copy)", cfg.name);
        cfg.created_at = chrono::Utc::now();
        cfg.updated_at = cfg.created_at;
        // Do not copy secret refs blindly onto a new profile without cloning vault entries.
        match &mut cfg.authentication {
            AuthMethod::Password { secret } => {
                if let Some(old) = secret.take() {
                    let value = self.secrets.get_secret(&old)?;
                    *secret = Some(self.secrets.put_secret(value.as_str())?);
                }
            }
            AuthMethod::PrivateKey {
                passphrase,
                key_material,
                ..
            } => {
                if let Some(old) = passphrase.take() {
                    let value = self.secrets.get_secret(&old)?;
                    *passphrase = Some(self.secrets.put_secret(value.as_str())?);
                }
                if let Some(old) = key_material.take() {
                    let value = self.secrets.get_secret(&old)?;
                    *key_material = Some(self.secrets.put_secret(value.as_str())?);
                }
            }
            _ => {}
        }
        self.store.upsert_profile(&cfg)?;
        Ok(cfg)
    }

    pub fn set_password_secret(
        &self,
        profile_id: Uuid,
        password: &str,
    ) -> Result<ConnectionConfig> {
        let mut cfg = self.store.get_profile(profile_id)?;
        let reference = match &cfg.authentication {
            AuthMethod::Password {
                secret: Some(existing),
            } => {
                self.secrets.update_secret(existing, password)?;
                existing.clone()
            }
            _ => self.secrets.put_secret(password)?,
        };
        cfg.authentication = AuthMethod::Password {
            secret: Some(reference),
        };
        cfg.updated_at = chrono::Utc::now();
        self.store.upsert_profile(&cfg)?;
        Ok(cfg)
    }

    pub fn export_profile(&self, id: Uuid) -> Result<ExportDocument> {
        let cfg = self.store.get_profile(id)?;
        Ok(cfg.export_safe())
    }

    pub fn import_profile_json(&self, raw: &str) -> Result<ConnectionConfig> {
        self.import_profile_text(raw)
    }

    pub fn import_profile_text(&self, raw: &str) -> Result<ConnectionConfig> {
        let parsed = rt_config::parse_import(raw)?;
        let mut cfg = parsed.config;
        if let Some(password) = parsed.password {
            let secret = self.secrets.put_secret(&password)?;
            cfg.authentication = AuthMethod::Password {
                secret: Some(secret),
            };
        }
        self.save_profile(cfg)
    }

    pub async fn tcp_probe(&self, host: &str, port: u16) -> rt_diagnostics::ProbeResult {
        rt_diagnostics::tcp_connect_probe(host, port).await
    }

    pub async fn traceroute(&self, host: &str) -> rt_diagnostics::ProbeResult {
        rt_diagnostics::traceroute_tcp(host).await
    }

    pub fn get_settings(&self) -> Result<AppSettings> {
        Ok(self.store.get_settings()?)
    }

    pub fn save_settings(&self, settings: AppSettings) -> Result<()> {
        Ok(self.store.save_settings(&settings)?)
    }

    pub async fn connect(&self, id: Uuid) -> Result<ConnectionSnapshot> {
        let profile = self.store.get_profile(id)?;
        Ok(self.connections.connect(profile).await?)
    }

    pub async fn disconnect(&self) -> Result<ConnectionSnapshot> {
        Ok(self.connections.disconnect().await?)
    }

    pub fn connection_snapshot(&self) -> ConnectionSnapshot {
        self.connections.snapshot()
    }

    pub async fn leak_report(&self) -> rt_diagnostics::LeakReport {
        let ipv6 = self.connections.snapshot().ipv6;
        rt_diagnostics::leak_report(ipv6).await
    }

    pub fn subscribe_connection(&self) -> watch::Receiver<ConnectionSnapshot> {
        self.connections.subscribe()
    }

    pub fn put_secret(&self, value: &str) -> Result<SecretRef> {
        Ok(self.secrets.put_secret(value)?)
    }
}
