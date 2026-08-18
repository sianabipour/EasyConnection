//! Secure credential storage for Easy Connection.
//!
//! Prefer FreeDesktop Secret Service when available. Fall back to an
//! AES-256-GCM encrypted file under the app config directory for CI/dev
//! environments without a keyring daemon.

mod encrypted_file;
mod error;
mod paths;
mod store;

pub use error::SecretsError;
pub use paths::{app_config_dir, secret_binding_tag};
pub use store::{SecretRef, SecretsStore};

pub type Result<T> = std::result::Result<T, SecretsError>;
