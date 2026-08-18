use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::encrypted_file::EncryptedFileStore;
use crate::{Result, SecretsError};

/// Opaque reference stored in SQLite — never the secret itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub id: String,
}

impl SecretRef {
    pub fn new() -> Self {
        Self {
            id: format!("sec_{}", Uuid::new_v4()),
        }
    }
}

impl Default for SecretRef {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SecretsStore {
    file: EncryptedFileStore,
}

impl SecretsStore {
    pub fn open_default() -> Result<Self> {
        let dir = crate::app_config_dir()?;
        let path = dir.join("secrets.bin");
        let binding = machine_binding(&dir);
        Ok(Self {
            file: EncryptedFileStore::open(path, &binding)?,
        })
    }

    pub fn open_path(path: PathBuf, binding: &[u8]) -> Result<Self> {
        Ok(Self {
            file: EncryptedFileStore::open(path, binding)?,
        })
    }

    pub fn put_secret(&self, value: &str) -> Result<SecretRef> {
        let reference = SecretRef::new();
        self.file.put(&reference.id, value)?;
        Ok(reference)
    }

    pub fn update_secret(&self, reference: &SecretRef, value: &str) -> Result<()> {
        if reference.id.is_empty() || !reference.id.starts_with("sec_") {
            return Err(SecretsError::InvalidRef);
        }
        self.file.put(&reference.id, value)
    }

    pub fn get_secret(&self, reference: &SecretRef) -> Result<Zeroizing<String>> {
        if reference.id.is_empty() {
            return Err(SecretsError::InvalidRef);
        }
        self.file.get(&reference.id)
    }

    pub fn delete_secret(&self, reference: &SecretRef) -> Result<()> {
        self.file.delete(&reference.id)
    }
}

fn machine_binding(config_dir: &std::path::Path) -> Vec<u8> {
    let mut binding = Vec::new();
    binding.extend_from_slice(crate::secret_binding_tag());
    binding.extend_from_slice(config_dir.to_string_lossy().as_bytes());
    if let Ok(hostname) = std::fs::read_to_string("/etc/machine-id") {
        binding.extend_from_slice(hostname.trim().as_bytes());
    } else if let Ok(hostname) = hostname::get() {
        binding.extend_from_slice(hostname.to_string_lossy().as_bytes());
    }
    binding
}

// hostname crate may not be in deps — use a tiny fallback without extra dep
mod hostname {
    pub fn get() -> std::io::Result<std::ffi::OsString> {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| std::ffi::OsString::from(s.trim()))
            .or_else(|_| Ok(std::ffi::OsString::from("unknown")))
    }
}
