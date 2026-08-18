//! DNS-over-TCP fallback and systemd-resolved policy for tunnel mode.

mod policy;

pub use policy::{effective_policy, resolve_servers, should_configure_resolved, DnsPolicy};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS message too large")]
    TooLarge,
    #[error("empty DNS response")]
    Empty,
}

pub type Result<T> = std::result::Result<T, DnsError>;

/// Wrap a raw DNS message with the RFC 1035 TCP 2-byte length prefix, then
/// read the length-prefixed response.
pub async fn exchange_over_tcp<S>(query: &[u8], mut stream: S) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if query.is_empty() || query.len() > 65535 {
        return Err(DnsError::TooLarge);
    }
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    let n = u16::from_be_bytes(hdr) as usize;
    if n == 0 {
        return Err(DnsError::Empty);
    }
    if n > 65535 {
        return Err(DnsError::TooLarge);
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub fn default_dns_servers() -> [&'static str; 2] {
    ["1.1.1.1", "8.8.8.8"]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn length_prefix_roundtrip() {
        let query = vec![0x12, 0x34, 0x01, 0x00];
        let response = vec![0x12, 0x34, 0x81, 0x80];
        let (client, mut server) = duplex(64);

        let server_task = tokio::spawn(async move {
            let mut hdr = [0u8; 2];
            server.read_exact(&mut hdr).await.unwrap();
            let n = u16::from_be_bytes(hdr) as usize;
            let mut q = vec![0u8; n];
            server.read_exact(&mut q).await.unwrap();
            assert_eq!(q, vec![0x12, 0x34, 0x01, 0x00]);
            let rl = (response.len() as u16).to_be_bytes();
            server.write_all(&rl).await.unwrap();
            server.write_all(&response).await.unwrap();
        });

        let got = exchange_over_tcp(&query, client).await.unwrap();
        server_task.await.unwrap();
        assert_eq!(got, vec![0x12, 0x34, 0x81, 0x80]);
    }
}
