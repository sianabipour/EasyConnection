use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("invalid secret reference")]
    InvalidRef,
    #[error("encryption error: {0}")]
    Crypto(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("secret service unavailable: {0}")]
    Backend(String),
}
