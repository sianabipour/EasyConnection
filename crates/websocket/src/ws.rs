//! Minimal RFC 6455 client that exposes a byte stream (binary frames).

use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::{Result, WsError};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub type WsByteStream = DuplexStream;

pub async fn websocket_client<S>(mut stream: S, host: &str, path: &str) -> Result<WsByteStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let path = if path.is_empty() { "/" } else { path };
    let mut key_raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_raw);
    let key = base64_encode(&key_raw);
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let headers = read_headers(&mut stream).await?;
    let status = headers.lines().next().unwrap_or("").to_ascii_uppercase();
    if !status.contains("101") {
        return Err(WsError::Handshake(format!(
            "WebSocket expected 101, got {}",
            headers.lines().next().unwrap_or("empty")
        )));
    }
    let expected = accept_key(&key);
    if let Some(got) = header_value(&headers, "sec-websocket-accept") {
        if !got.eq_ignore_ascii_case(&expected) {
            return Err(WsError::Handshake("Sec-WebSocket-Accept mismatch".into()));
        }
    }

    let (local, mut peer) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                n = peer.read(&mut buf) => {
                    match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if write_frame(&mut stream, 0x2, &buf[..n], true).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                frame = read_data_frame(&mut stream) => {
                    match frame {
                        Ok(data) => {
                            if peer.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
    Ok(local)
}

async fn read_data_frame<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    loop {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await?;
        let opcode = hdr[0] & 0x0f;
        let masked = hdr[1] & 0x80 != 0;
        let mut len = (hdr[1] & 0x7f) as u64;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await?;
            len = u16::from_be_bytes(ext) as u64;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).await?;
            len = u64::from_be_bytes(ext);
        }
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask).await?;
        }
        if len > 1_000_000 {
            return Err(WsError::Protocol("WS frame too large".into()));
        }
        let mut payload = vec![0u8; len as usize];
        if !payload.is_empty() {
            stream.read_exact(&mut payload).await?;
        }
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match opcode {
            0x0..=0x2 => return Ok(payload),
            0x8 => return Err(WsError::Protocol("WS close".into())),
            0x9 => {
                let _ = write_frame(stream, 0xA, &payload, true).await;
            }
            0xA => {}
            other => return Err(WsError::Protocol(format!("unsupported WS opcode {other}"))),
        }
    }
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
    mask: bool,
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.push(0x80 | opcode);
    let mut mask_key = [0u8; 4];
    if mask {
        rand::thread_rng().fill_bytes(&mut mask_key);
    }
    let len = payload.len();
    if len < 126 {
        out.push(if mask { 0x80 } else { 0 } | len as u8);
    } else if len <= 65535 {
        out.push(if mask { 0x80 } else { 0 } | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(if mask { 0x80 } else { 0 } | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        out.extend_from_slice(&mask_key);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask_key[i % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_headers<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    while buf.len() < 8192 {
        stream.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    Err(WsError::Handshake(
        "WebSocket response headers too large".into(),
    ))
}

fn accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(GUID.as_bytes());
    base64_encode(&h.finalize())
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (a << 16) | (b << 8) | c;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
