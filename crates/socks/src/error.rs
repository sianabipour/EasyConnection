use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication required")]
    AuthRequired,
    #[error("authentication failed")]
    AuthFailed,
    #[error("command not supported")]
    CommandNotSupported,
    #[error("address type not supported")]
    AddressNotSupported,
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("server stopped")]
    Stopped,
}
