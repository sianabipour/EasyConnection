//! Shadowsocks AEAD TCP (SIP004): salt + chunked AEAD.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::{Result, SsError};

const INFO: &[u8] = b"ss-subkey";
const MAX_CHUNK: usize = 0x3fff;

#[derive(Debug, Clone, Copy)]
pub enum AeadMethod {
    Aes128Gcm,
    Aes256Gcm,
}

impl AeadMethod {
    pub fn parse(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            other => Err(SsError::Config(format!(
                "unsupported method `{other}`. Supported: aes-128-gcm, aes-256-gcm. SS2022 / chacha20 not in this build."
            ))),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last = Vec::new();
    while out.len() < key_len {
        let mut ctx = md5::Context::new();
        ctx.consume(&last);
        ctx.consume(password);
        last = ctx.compute().0.to_vec();
        out.extend_from_slice(&last);
    }
    out.truncate(key_len);
    out
}

fn hkdf_subkey(key: &[u8], salt: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut okm = vec![0u8; len];
    hk.expand(INFO, &mut okm)
        .map_err(|_| SsError::Crypto("HKDF expand failed".into()))?;
    Ok(okm)
}

fn nonce(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl Cipher {
    fn new(method: AeadMethod, key: &[u8]) -> Result<Self> {
        match method {
            AeadMethod::Aes128Gcm => Ok(Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|e| SsError::Crypto(e.to_string()))?,
            ))),
            AeadMethod::Aes256Gcm => Ok(Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|e| SsError::Crypto(e.to_string()))?,
            ))),
        }
    }

    fn seal(&self, n: u64, plain: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = nonce(n);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plain,
            aad: &[],
        };
        match self {
            Self::Aes128(c) => c.encrypt(nonce, payload),
            Self::Aes256(c) => c.encrypt(nonce, payload),
        }
        .map_err(|e| SsError::Crypto(e.to_string()))
    }

    fn open(&self, n: u64, cipher: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = nonce(n);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: cipher,
            aad: &[],
        };
        match self {
            Self::Aes128(c) => c.decrypt(nonce, payload),
            Self::Aes256(c) => c.decrypt(nonce, payload),
        }
        .map_err(|e| SsError::Crypto(e.to_string()))
    }
}

/// Byte pipe that speaks Shadowsocks AEAD on the wire.
pub struct SsStream {
    inner: DuplexStream,
}

impl SsStream {
    pub async fn handshake(
        mut raw: Box<dyn rt_tls::TransportIo>,
        method: AeadMethod,
        master: &[u8],
    ) -> Result<Self> {
        let mut salt = vec![0u8; method.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        raw.write_all(&salt).await?;
        raw.flush().await?;
        let enc_key = hkdf_subkey(master, &salt, method.key_len())?;
        let enc = Cipher::new(method, &enc_key)?;
        let master = master.to_vec();

        let (local, mut peer) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            if let Err(e) = pump(raw, &mut peer, enc, method, master).await {
                tracing::debug!(error = %e, "Shadowsocks AEAD pump ended");
            }
        });
        Ok(Self { inner: local })
    }

    pub async fn write_payload(&mut self, plain: &[u8]) -> Result<()> {
        self.inner.write_all(plain).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn pump(
    mut raw: Box<dyn rt_tls::TransportIo>,
    peer: &mut DuplexStream,
    enc: Cipher,
    method: AeadMethod,
    master: Vec<u8>,
) -> Result<()> {
    let mut enc_nonce = 0u64;
    let mut dec: Option<Cipher> = None;
    let mut dec_nonce = 0u64;
    let mut plain = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            n = peer.read(&mut plain) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                for chunk in plain[..n].chunks(MAX_CHUNK) {
                    let len = (chunk.len() as u16).to_be_bytes();
                    let c_len = enc.seal(enc_nonce, &len)?;
                    enc_nonce += 1;
                    let c_body = enc.seal(enc_nonce, chunk)?;
                    enc_nonce += 1;
                    raw.write_all(&c_len).await?;
                    raw.write_all(&c_body).await?;
                }
                raw.flush().await?;
            }
            res = read_chunk(&mut raw, &mut dec, &mut dec_nonce, method, &master) => {
                let data = res?;
                if data.is_empty() {
                    return Ok(());
                }
                peer.write_all(&data).await?;
            }
        }
    }
}

async fn read_chunk(
    raw: &mut Box<dyn rt_tls::TransportIo>,
    dec: &mut Option<Cipher>,
    dec_nonce: &mut u64,
    method: AeadMethod,
    master: &[u8],
) -> Result<Vec<u8>> {
    if dec.is_none() {
        let mut salt = vec![0u8; method.salt_len()];
        raw.read_exact(&mut salt).await?;
        let key = hkdf_subkey(master, &salt, method.key_len())?;
        *dec = Some(Cipher::new(method, &key)?);
    }
    let cipher = dec.as_ref().expect("dec ready");
    let mut len_c = vec![0u8; 2 + 16];
    match raw.read_exact(&mut len_c).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    let len_b = cipher.open(*dec_nonce, &len_c)?;
    *dec_nonce += 1;
    if len_b.len() != 2 {
        return Err(SsError::Crypto("bad length block".into()));
    }
    let len = u16::from_be_bytes([len_b[0], len_b[1]]) as usize;
    if len == 0 || len > MAX_CHUNK {
        return Err(SsError::Crypto(format!("invalid chunk length {len}")));
    }
    let mut body_c = vec![0u8; len + 16];
    raw.read_exact(&mut body_c).await?;
    let body = cipher.open(*dec_nonce, &body_c)?;
    *dec_nonce += 1;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_key_length() {
        let k = evp_bytes_to_key(b"password", 32);
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn nonce_little_endian_counter() {
        assert_eq!(&nonce(1)[..8], &1u64.to_le_bytes());
    }
}
