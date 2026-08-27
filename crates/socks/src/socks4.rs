use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::server::ProxyStats;
use crate::upstream::{record_relay, relay_both, UpstreamConnector};
use crate::{Result, SocksError};

const VER4: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;
const REP_GRANTED: u8 = 0x5A;
const REP_REJECTED: u8 = 0x5B;

pub async fn handle_socks4<S>(
    mut client: S,
    upstream: &dyn UpstreamConnector,
    stats: Option<Arc<ProxyStats>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 8];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != VER4 {
        return Err(SocksError::Protocol("not socks4".into()));
    }
    if hdr[1] != CMD_CONNECT {
        write_reply(&mut client, REP_REJECTED).await?;
        return Err(SocksError::CommandNotSupported);
    }
    let port = u16::from_be_bytes([hdr[2], hdr[3]]);
    let ip = [hdr[4], hdr[5], hdr[6], hdr[7]];

    // userid (null-terminated)
    let mut userid = Vec::new();
    loop {
        let mut b = [0u8; 1];
        client.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
        userid.push(b[0]);
        if userid.len() > 512 {
            return Err(SocksError::Protocol("userid too long".into()));
        }
    }

    let host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        // SOCKS4a — domain follows
        let mut domain = Vec::new();
        loop {
            let mut b = [0u8; 1];
            client.read_exact(&mut b).await?;
            if b[0] == 0 {
                break;
            }
            domain.push(b[0]);
            if domain.len() > 255 {
                return Err(SocksError::Protocol("domain too long".into()));
            }
        }
        String::from_utf8(domain).map_err(|_| SocksError::Protocol("invalid domain".into()))?
    } else {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    };

    match upstream.connect(&host, port).await {
        Ok(up) => {
            write_reply(&mut client, REP_GRANTED).await?;
            if let Ok((up_n, down_n)) = relay_both(client, up).await {
                if let Some(s) = stats.as_ref() {
                    record_relay(s, up_n, down_n);
                }
            }
            Ok(())
        }
        Err(e) => {
            write_reply(&mut client, REP_REJECTED).await?;
            Err(e)
        }
    }
}

async fn write_reply<S>(client: &mut S, code: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8];
    buf[0] = 0x00;
    buf[1] = code;
    client.write_all(&buf).await?;
    Ok(())
}
