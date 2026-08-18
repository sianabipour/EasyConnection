//! App config directory for Easy Connection.

use std::path::PathBuf;

use directories::ProjectDirs;

use crate::{Result, SecretsError};

pub fn app_config_dir() -> Result<PathBuf> {
    let dir = ProjectDirs::from("app", "EasyConnection", "easy")
        .ok_or_else(|| SecretsError::Backend("cannot resolve config directory".into()))?
        .config_dir()
        .to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn secret_binding_tag() -> &'static [u8] {
    b"easy-connection"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_is_easy() {
        let dir = app_config_dir().unwrap();
        assert!(dir.to_string_lossy().contains("easy"));
        assert_eq!(secret_binding_tag(), b"easy-connection");
    }
}
