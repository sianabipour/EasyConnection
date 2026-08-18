use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("secrets error: {0}")]
    Secrets(String),
    #[error("import error: {0}")]
    Import(String),
}
