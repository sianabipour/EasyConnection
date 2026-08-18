use tracing_subscriber::{fmt, EnvFilter};

/// Initialize structured logging. Credentials must never be logged by callers.
pub fn init_logging(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .try_init();
}
