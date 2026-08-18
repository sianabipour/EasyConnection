//! Application controller — single source of truth for the desktop UI.

mod app;
mod error;
mod logging;

pub use app::AppController;
pub use error::CoreError;
pub use logging::init_logging;

pub type Result<T> = std::result::Result<T, CoreError>;
