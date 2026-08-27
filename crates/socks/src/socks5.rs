use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use std::sync::Arc;

use crate::server::ProxyStats;
use crate::upstream::{record_relay, relay_both, UpstreamConnector};
use crate::{Result, SocksError};

const VER: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_CMD_UNSUP: u8 = 0x07;
const REP_ATYP_UNSUP: u8 = 0x08;

pub struct Socks5Auth {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Socks5Auth {
    pub fn none() -> Self {
        Self {
            username: None,
            password: None,
        }
    }

    pub fn required(user: String, pass: String) -> Self {
        Self {
            username: Some(user),
            password: Some(pass),
        }
    }
}

pub async fn handle_socks5<S>(
    mut client: S,
    upstream: &dyn UpstreamConnector,
    auth: &Socks5Auth,
    stats: Option<Arc<ProxyStats>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // greeting
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != VER {
        return Err(SocksError::Protocol(format!(
            "invalid socks version {}",
            header[0]
        )));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        client.read_exact(&mut methods).await?;
    }

    let want_userpass = auth.username.is_some();
    let selected = if want_userpass {
        if methods.contains(&AUTH_USERPASS) {
            AUTH_USERPASS
        } else {
            AUTH_NO_ACCEPTABLE
        }
    } else if methods.contains(&AUTH_NONE) {
        AUTH_NONE
    } else {
        AUTH_NO_ACCEPTABLE
    };

    client.write_all(&[VER, selected]).await?;
    if selected == AUTH_NO_ACCEPTABLE {
        return Err(SocksError::AuthRequired);
    }

    if selected == AUTH_USERPASS {
        // RFC 1929
        let mut ver = [0u8; 1];
        client.read_exact(&mut ver).await?;
        let mut ulen = [0u8; 1];
        client.read_exact(&mut ulen).await?;
        let mut uname = vec![0u8; ulen[0] as usize];
        client.read_exact(&mut uname).await?;
        let mut plen = [0u8; 1];
        client.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; plen[0] as usize];
        client.read_exact(&mut pass).await?;

        let ok = auth
            .username
            .as_ref()
            .zip(auth.password.as_ref())
            .map(|(u, p)| u.as_bytes() == uname.as_slice() && p.as_bytes() == pass.as_slice())
            .unwrap_or(false);
        client
            .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
            .await?;
        if !ok {
            return Err(SocksError::AuthFailed);
        }
    }

    // request
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(SocksError::Protocol("bad request version".into()));
    }
    let cmd = req[1];
    let atyp = req[3];

    let (host, port) = read_address(&mut client, atyp).await?;

    if cmd != CMD_CONNECT {
        write_reply(&mut client, REP_CMD_UNSUP).await?;
        return Err(SocksError::CommandNotSupported);
    }

    match upstream.connect(&host, port).await {
        Ok(up) => {
            write_reply(&mut client, REP_SUCCESS).await?;
            if let Ok((up_n, down_n)) = relay_both(client, up).await {
                if let Some(s) = stats.as_ref() {
                    record_relay(s, up_n, down_n);
                }
            }
            Ok(())
        }
        Err(e) => {
            tracing::debug!(error = %e, host, port, "socks5 upstream connect failed");
            write_reply(&mut client, REP_GENERAL).await?;
            Err(e)
        }
    }
}

async fn read_address<S>(client: &mut S, atyp: u8) -> Result<(String, u16)>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            Ok((
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
                port,
            ))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let host = String::from_utf8(domain)
                .map_err(|_| SocksError::Protocol("invalid domain utf-8".into()))?;
            Ok((host, port))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let ip = std::net::Ipv6Addr::from(addr);
            Ok((ip.to_string(), port))
        }
        _ => Err(SocksError::AddressNotSupported),
    }
}

async fn write_reply<S>(client: &mut S, rep: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // bind addr 0.0.0.0:0
    let mut buf = [0u8; 10];
    buf[0] = VER;
    buf[1] = rep;
    buf[2] = 0x00;
    buf[3] = ATYP_IPV4;
    client.write_all(&buf).await?;
    if rep == REP_ATYP_UNSUP {
        return Err(SocksError::AddressNotSupported);
    }
    Ok(())
}
