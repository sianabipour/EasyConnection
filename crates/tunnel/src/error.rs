use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("not connected")]
    NotConnected,
    #[error("already connected")]
    AlreadyConnected,
    #[error("unsupported protocol for this phase: {0}")]
    UnsupportedProtocol(String),
    #[error("SSH error: {0}")]
    Ssh(#[from] rt_ssh::SshError),
    #[error("proxy error: {0}")]
    Proxy(#[from] rt_socks::SocksError),
    #[error("privileged helper: {0}")]
    Helper(#[from] rt_tun::TunError),
    #[error("config error: {0}")]
    Config(String),
    #[error("secrets error: {0}")]
    Secrets(String),
    #[error("{0}")]
    Other(String),
}
