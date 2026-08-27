use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rt_config::{AuthMethod, ConnectionConfig, HostKeyPolicy, ProtocolSettings};
use rt_secrets::SecretsStore;
use rt_socks::{Result as SocksResult, SocksError, UpstreamConnector, UpstreamIo};
use russh::client::{self, Handle, Msg};
use russh::keys::{self, key::PrivateKeyWithHashAlg};
use russh::{ChannelStream, Preferred};
use tokio::time::timeout;
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::host_key::HostKeyVerifier;
use crate::{Result, SshError};

struct ClientHandler {
    verifier: HostKeyVerifier,
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        self.verifier.verify(server_public_key).await
    }
}

pub struct SshConnectOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub keepalive_secs: u64,
    pub connect_timeout_secs: u64,
    pub host_key_policy: HostKeyPolicy,
    pub known_hosts_path: Option<PathBuf>,
}

impl SshConnectOptions {
    pub fn from_config(cfg: &ConnectionConfig) -> Result<Self> {
        let (keepalive_secs, connect_timeout_secs, host_key_policy) = match &cfg.settings {
            ProtocolSettings::Ssh {
                keepalive_secs,
                connect_timeout_secs,
                host_key_policy,
            } => (*keepalive_secs, *connect_timeout_secs, *host_key_policy),
            _ => return Err(SshError::Config("connection settings are not SSH".into())),
        };
        let username = cfg
            .username
            .clone()
            .ok_or_else(|| SshError::Config("SSH username required".into()))?;
        Ok(Self {
            host: cfg.host.clone(),
            port: cfg.port,
            username,
            auth: cfg.authentication.clone(),
            keepalive_secs,
            connect_timeout_secs,
            host_key_policy,
            known_hosts_path: None,
        })
    }
}

pub struct SshSession {
    handle: Handle<ClientHandler>,
    pub host: String,
    pub port: u16,
}

impl SshSession {
    pub async fn connect(opts: SshConnectOptions, secrets: &SecretsStore) -> Result<Self> {
        let known_hosts = opts.known_hosts_path.unwrap_or_else(default_known_hosts);
        let verifier = HostKeyVerifier::new(
            opts.host.clone(),
            opts.port,
            opts.host_key_policy,
            known_hosts,
        );

        let config = client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(opts.keepalive_secs.max(5))),
            keepalive_max: 5,
            // Larger window reduces SSH-level stalls on parallel page loads.
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: 32768,
            preferred: Preferred::default(),
            ..Default::default()
        };

        let handler = ClientHandler { verifier };
        // Dial ourselves so we can set TCP_NODELAY on the SSH TCP (russh connect does not).
        let tcp = timeout(
            Duration::from_secs(opts.connect_timeout_secs.max(1)),
            tokio::net::TcpStream::connect((opts.host.as_str(), opts.port)),
        )
        .await
        .map_err(|_| SshError::Timeout(opts.connect_timeout_secs))?
        .map_err(SshError::from)?;
        let _ = tcp.set_nodelay(true);

        let connect_fut = client::connect_stream(Arc::new(config), tcp, handler);
        let mut handle = timeout(
            Duration::from_secs(opts.connect_timeout_secs.max(1)),
            connect_fut,
        )
        .await
        .map_err(|_| SshError::Timeout(opts.connect_timeout_secs))??;

        authenticate(&mut handle, &opts.username, &opts.auth, secrets).await?;

        info!(host = %opts.host, port = opts.port, user = %opts.username, "SSH session established");
        Ok(Self {
            handle,
            host: opts.host,
            port: opts.port,
        })
    }

    /// SSH over an already-dialed transport (TLS / WebSocket / HTTP Upgrade).
    pub async fn connect_over_transport(
        opts: SshConnectOptions,
        secrets: &SecretsStore,
        stream: Box<dyn rt_tls::TransportIo>,
    ) -> Result<Self> {
        let known_hosts = opts.known_hosts_path.unwrap_or_else(default_known_hosts);
        let verifier = HostKeyVerifier::new(
            opts.host.clone(),
            opts.port,
            opts.host_key_policy,
            known_hosts,
        );

        let config = client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(opts.keepalive_secs.max(5))),
            keepalive_max: 5,
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: 32768,
            preferred: Preferred::default(),
            ..Default::default()
        };

        let handler = ClientHandler { verifier };
        let connect_fut = client::connect_stream(Arc::new(config), stream, handler);
        let mut handle = timeout(
            Duration::from_secs(opts.connect_timeout_secs.max(1)),
            connect_fut,
        )
        .await
        .map_err(|_| SshError::Timeout(opts.connect_timeout_secs))??;

        authenticate(&mut handle, &opts.username, &opts.auth, secrets).await?;
        info!(
            host = %opts.host,
            port = opts.port,
            user = %opts.username,
            "SSH session established over transport"
        );
        Ok(Self {
            handle,
            host: opts.host,
            port: opts.port,
        })
    }

    pub fn upstream(self: &Arc<Self>) -> SshUpstream {
        SshUpstream {
            session: Arc::clone(self),
        }
    }

    pub async fn open_direct_tcpip(&self, host: &str, port: u16) -> Result<ChannelStream<Msg>> {
        use tracing::Instrument;
        async {
            let started = std::time::Instant::now();
            debug!(%host, port, "opening SSH direct-tcpip channel");
            let channel = self
                .handle
                .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0u32)
                .await?;
            debug!(
                %host,
                port,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "SSH direct-tcpip channel ready"
            );
            Ok(channel.into_stream())
        }
        .instrument(tracing::info_span!("ssh_direct_tcpip", %host, port))
        .await
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}

pub struct SshUpstream {
    session: Arc<SshSession>,
}

#[async_trait]
impl UpstreamConnector for SshUpstream {
    async fn connect(&self, host: &str, port: u16) -> SocksResult<Box<dyn UpstreamIo>> {
        let stream = self
            .session
            .open_direct_tcpip(host, port)
            .await
            .map_err(|e| SocksError::Upstream(e.to_string()))?;
        Ok(Box::new(stream))
    }
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    auth: &AuthMethod,
    secrets: &SecretsStore,
) -> Result<()> {
    let ok = match auth {
        AuthMethod::Password { secret } => {
            let secret_ref = secret
                .as_ref()
                .ok_or_else(|| SshError::Config("password secret reference missing".into()))?;
            let password = secrets
                .get_secret(secret_ref)
                .map_err(|e| SshError::Secrets(e.to_string()))?;
            handle
                .authenticate_password(username, password.as_str())
                .await?
        }
        AuthMethod::PrivateKey {
            path,
            passphrase,
            key_material,
        } => {
            let pass = load_optional_passphrase(secrets, passphrase)?;
            let pass_ref = pass.as_ref().map(|p| p.as_str());
            let key = if let Some(material_ref) = key_material {
                let pem = secrets
                    .get_secret(material_ref)
                    .map_err(|e| SshError::Secrets(e.to_string()))?;
                keys::decode_secret_key(pem.as_str(), pass_ref)?
            } else if let Some(path) = path {
                keys::load_secret_key(path, pass_ref)?
            } else {
                return Err(SshError::Config(
                    "private key path or key material required".into(),
                ));
            };
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), None)?;
            handle.authenticate_publickey(username, key).await?
        }
        AuthMethod::Agent => {
            let mut agent = keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| SshError::Config(format!("SSH agent unavailable: {e}")))?;
            let identities = agent
                .request_identities()
                .await
                .map_err(|e| SshError::Russh(e.to_string()))?;
            let mut success = false;
            for identity in identities {
                match handle
                    .authenticate_publickey_with(username, identity, &mut agent)
                    .await
                {
                    Ok(true) => {
                        success = true;
                        break;
                    }
                    Ok(false) => continue,
                    Err(e) => {
                        debug!(error = %e, "agent identity rejected");
                    }
                }
            }
            success
        }
        AuthMethod::None => handle.authenticate_none(username).await?,
    };

    if ok {
        Ok(())
    } else {
        Err(SshError::AuthenticationFailed)
    }
}

fn load_optional_passphrase(
    secrets: &SecretsStore,
    passphrase: &Option<rt_secrets::SecretRef>,
) -> Result<Option<Zeroizing<String>>> {
    match passphrase {
        Some(r) => Ok(Some(
            secrets
                .get_secret(r)
                .map_err(|e| SshError::Secrets(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

fn default_known_hosts() -> PathBuf {
    match rt_secrets::app_config_dir() {
        Ok(dir) => dir.join("known_hosts"),
        Err(_) => PathBuf::from("known_hosts"),
    }
}
