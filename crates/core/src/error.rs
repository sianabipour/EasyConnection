use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Config(#[from] rt_config::ConfigError),
    #[error(transparent)]
    Secrets(#[from] rt_secrets::SecretsError),
    #[error(transparent)]
    Tunnel(#[from] rt_tunnel::TunnelError),
    #[error("{0}")]
    Other(String),
}
