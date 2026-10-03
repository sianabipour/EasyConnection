//! Configuration models, validation, import, and SQLite persistence.

mod db;
mod error;
mod import;
mod model;
mod smart_link;
mod validate;

pub use db::ConfigStore;
pub use error::ConfigError;
pub use import::{parse_import, ParsedImport};
pub use model::*;
pub use smart_link::{decode_rocket_smart_link, RocketSmartConfig, RocketSmartHost};
pub use validate::validate_connection;

pub type Result<T> = std::result::Result<T, ConfigError>;
