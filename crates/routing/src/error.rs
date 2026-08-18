use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no default route found — cannot protect the SSH server path")]
    NoDefaultRoute,
    #[error("{0}")]
    Other(String),
}
