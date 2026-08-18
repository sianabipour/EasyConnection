use thiserror::Error;

#[derive(Debug, Error)]
pub enum NftError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
