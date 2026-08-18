use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::SecretsError;

const FILE_MAGIC: &[u8; 8] = b"EASYSEC1";
const NONCE_LEN: usize = 12;

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultFile {
    entries: HashMap<String, String>,
}

pub struct EncryptedFileStore {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl EncryptedFileStore {
    pub fn open(path: impl AsRef<Path>, machine_binding: &[u8]) -> Result<Self, SecretsError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        let key = derive_key(machine_binding);
        let store = Self { path, key };

        if !store.path.exists() {
            store.persist(&VaultFile::default())?;
        }

        Ok(store)
    }

    pub fn put(&self, id: &str, value: &str) -> Result<(), SecretsError> {
        let mut vault = self.load()?;
        vault.entries.insert(id.to_string(), value.to_string());
        self.persist(&vault)
    }

    pub fn get(&self, id: &str) -> Result<Zeroizing<String>, SecretsError> {
        let vault = self.load()?;
        vault
            .entries
            .get(id)
            .cloned()
            .map(Zeroizing::new)
            .ok_or_else(|| SecretsError::NotFound(id.to_string()))
    }

    pub fn delete(&self, id: &str) -> Result<(), SecretsError> {
        let mut vault = self.load()?;
        vault.entries.remove(id);
        self.persist(&vault)
    }

    fn load(&self) -> Result<VaultFile, SecretsError> {
        let mut file = File::open(&self.path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        if buf.len() < FILE_MAGIC.len() + NONCE_LEN + 16 {
            return Err(SecretsError::Crypto("vault file truncated".into()));
        }
        if &buf[..8] != FILE_MAGIC {
            return Err(SecretsError::Crypto("invalid vault magic".into()));
        }
        let nonce = Nonce::from_slice(&buf[8..8 + NONCE_LEN]);
        let ciphertext = &buf[8 + NONCE_LEN..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_ref()));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| SecretsError::Crypto(format!("decrypt failed: {e}")))?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn persist(&self, vault: &VaultFile) -> Result<(), SecretsError> {
        let plaintext = serde_json::to_vec(vault)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_ref()));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|e| SecretsError::Crypto(format!("encrypt failed: {e}")))?;

        let tmp = self.path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(FILE_MAGIC)?;
            file.write_all(&nonce_bytes)?;
            file.write_all(&ciphertext)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        Ok(())
    }
}

fn derive_key(binding: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"easy-connection-secrets-v1");
    hasher.update(binding);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Zeroizing::new(key)
}

impl Drop for EncryptedFileStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secrets.bin");
        let store = EncryptedFileStore::open(&path, b"test-machine").unwrap();
        store.put("s1", "hunter2").unwrap();
        let got = store.get("s1").unwrap();
        assert_eq!(got.as_str(), "hunter2");
        store.delete("s1").unwrap();
        assert!(store.get("s1").is_err());
    }
}
