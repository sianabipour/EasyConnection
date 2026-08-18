//! Configuration models, validation, import, and SQLite persistence.

mod db;
mod error;
mod import;
mod model;
mod validate;

pub use db::ConfigStore;
pub use error::ConfigError;
pub use import::{parse_import, ParsedImport};
pub use model::*;
pub use validate::validate_connection;

pub type Result<T> = std::result::Result<T, ConfigError>;
