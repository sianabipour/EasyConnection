use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::upstream::{relay_both, UpstreamConnector};
use crate::{Result, SocksError};

pub async fn handle_http_connect<S>(client: S, upstream: &dyn UpstreamConnector) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(client);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Err(SocksError::Protocol("expected HTTP CONNECT".into()));
    }
    let target = parts[1];
    let (host, port) = split_host_port(target)?;

    // consume headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if line.len() > 8192 {
            return Err(SocksError::Protocol("header too long".into()));
        }
    }

    let mut client = reader.into_inner();
    match upstream.connect(&host, port).await {
        Ok(up) => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let _ = relay_both(client, up).await;
            Ok(())
        }
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            Err(e)
        }
    }
}

fn split_host_port(target: &str) -> Result<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        // [ipv6]:port
        let (host, port_part) = rest
            .rsplit_once("]:")
            .ok_or_else(|| SocksError::Protocol("invalid IPv6 CONNECT target".into()))?;
        let port: u16 = port_part
            .parse()
            .map_err(|_| SocksError::Protocol("invalid port".into()))?;
        Ok((host.to_string(), port))
    } else if let Some((host, port)) = target.rsplit_once(':') {
        let port: u16 = port
            .parse()
            .map_err(|_| SocksError::Protocol("invalid port".into()))?;
        Ok((host.to_string(), port))
    } else {
        Err(SocksError::Protocol("CONNECT target missing port".into()))
    }
}
