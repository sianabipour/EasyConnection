//! HTTP/1.1 Upgrade to a raw bidirectional stream (no WebSocket framing).
//! Used by V2Ray-style HTTPUpgrade and similar public transports.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Result, WsError};

pub async fn http_upgrade<S>(mut stream: S, host: &str, path: &str) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = if path.is_empty() { "/" } else { path };
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let headers = read_headers(&mut stream).await?;
    let status = headers.lines().next().unwrap_or("").to_ascii_uppercase();
    if !status.contains(" 101 ")
        && !status.starts_with("HTTP/1.1 101")
        && !status.starts_with("HTTP/1.0 101")
    {
        return Err(WsError::Handshake(format!(
            "HTTP Upgrade expected 101, got {}",
            headers.lines().next().unwrap_or("empty")
        )));
    }
    Ok(stream)
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
    Err(WsError::Handshake("HTTP response headers too large".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn upgrade_accepts_101() {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert!(std::str::from_utf8(&buf[..n])
                .unwrap()
                .contains("Upgrade: websocket"));
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
        });
        let _ = http_upgrade(client, "example.com", "/ws").await.unwrap();
        server_task.await.unwrap();
    }
}
