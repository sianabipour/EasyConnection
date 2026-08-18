use crate::model::{AppSettings, ConnectionConfig, CONFIG_VERSION};
use crate::validate::validate_connection;
use crate::{ConfigError, Result};
use rusqlite::{params, Connection};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

pub struct ConfigStore {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl ConfigStore {
    pub fn open_default() -> Result<Self> {
        let dir = rt_secrets::app_config_dir().map_err(|e| ConfigError::Secrets(e.to_string()))?;
        std::fs::create_dir_all(&dir)?;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        Self::open(dir.join("state.db"))
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            ",
        )?;
        let store = Self {
            conn: Mutex::new(conn),
            path,
        };
        store.migrate()?;
        let _ = std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600));
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().expect("db lock");
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_profiles_name ON profiles(name);
            CREATE TABLE IF NOT EXISTS app_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                json TEXT NOT NULL
            );
            "#,
        )?;
        let version: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .ok();
        if version.is_none() {
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                params![CONFIG_VERSION.to_string()],
            )?;
            conn.execute(
                "INSERT INTO app_settings(id, json) VALUES (1, ?1)",
                params![serde_json::to_string(&AppSettings::default())?],
            )?;
        }
        Ok(())
    }

    pub fn list_profiles(&self) -> Result<Vec<ConnectionConfig>> {
        let conn = self.conn.lock().expect("db lock");
        let mut stmt =
            conn.prepare("SELECT json FROM profiles ORDER BY name COLLATE NOCASE ASC")?;
        let rows = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            out.push(serde_json::from_str(&json)?);
        }
        Ok(out)
    }

    pub fn get_profile(&self, id: Uuid) -> Result<ConnectionConfig> {
        let conn = self.conn.lock().expect("db lock");
        let json: String = conn
            .query_row(
                "SELECT json FROM profiles WHERE id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .map_err(|_| ConfigError::NotFound(id.to_string()))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn upsert_profile(&self, cfg: &ConnectionConfig) -> Result<()> {
        validate_connection(cfg)?;
        let conn = self.conn.lock().expect("db lock");
        let json = serde_json::to_string(cfg)?;
        conn.execute(
            r#"
            INSERT INTO profiles(id, name, json, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                json = excluded.json,
                updated_at = excluded.updated_at
            "#,
            params![
                cfg.id.to_string(),
                cfg.name,
                json,
                cfg.created_at.to_rfc3339(),
                cfg.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn delete_profile(&self, id: Uuid) -> Result<()> {
        let conn = self.conn.lock().expect("db lock");
        let n = conn.execute(
            "DELETE FROM profiles WHERE id = ?1",
            params![id.to_string()],
        )?;
        if n == 0 {
            return Err(ConfigError::NotFound(id.to_string()));
        }
        Ok(())
    }

    pub fn get_settings(&self) -> Result<AppSettings> {
        let conn = self.conn.lock().expect("db lock");
        let json: String =
            conn.query_row("SELECT json FROM app_settings WHERE id = 1", [], |r| {
                r.get(0)
            })?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<()> {
        let conn = self.conn.lock().expect("db lock");
        conn.execute(
            "UPDATE app_settings SET json = ?1 WHERE id = 1",
            params![serde_json::to_string(settings)?],
        )?;
        Ok(())
    }

    pub fn import_json(&self, raw: &str) -> Result<ConnectionConfig> {
        let value: serde_json::Value = serde_json::from_str(raw)?;
        let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
        if version > CONFIG_VERSION as u64 {
            return Err(ConfigError::Import(format!(
                "unsupported config version {version}"
            )));
        }
        let mut profile: ConnectionConfig = if value.get("profile").is_some() {
            serde_json::from_value(value.get("profile").cloned().unwrap())?
        } else {
            serde_json::from_value(value)?
        };
        profile.id = Uuid::new_v4();
        profile.updated_at = chrono::Utc::now();
        validate_connection(&profile)?;
        self.upsert_profile(&profile)?;
        Ok(profile)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AuthMethod;
    use tempfile::tempdir;

    #[test]
    fn crud_profile() {
        let dir = tempdir().unwrap();
        let store = ConfigStore::open(dir.path().join("state.db")).unwrap();
        let mut cfg = ConnectionConfig::new_ssh("Lab", "203.0.113.10", 22);
        cfg.username = Some("ops".into());
        cfg.authentication = AuthMethod::Password { secret: None };
        store.upsert_profile(&cfg).unwrap();
        let listed = store.list_profiles().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Lab");
        store.delete_profile(cfg.id).unwrap();
        assert!(store.list_profiles().unwrap().is_empty());
    }
}
