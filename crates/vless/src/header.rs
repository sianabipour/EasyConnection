use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use crate::Result;

/// VLESS request: version, uuid, addon_len=0, command=TCP, port, address.
pub fn encode_request(uuid: Uuid, host: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + host.len());
    out.push(0); // version
    out.extend_from_slice(uuid.as_bytes());
    out.push(0); // no addons
    out.push(0x01); // TCP
    out.extend_from_slice(&port.to_be_bytes());
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v) => {
                out.push(0x01);
                out.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                out.push(0x03);
                out.extend_from_slice(&v.octets());
            }
        }
    } else {
        let b = host.as_bytes();
        let n = b.len().min(255);
        out.push(0x02);
        out.push(n as u8);
        out.extend_from_slice(&b[..n]);
    }
    out
}

/// Response: version + addon_len + addons. Remainder is payload.
pub async fn read_response<S: AsyncRead + Unpin + ?Sized>(stream: &mut S) -> Result<()> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    let addon_len = hdr[1] as usize;
    if addon_len > 0 {
        let mut addons = vec![0u8; addon_len];
        stream.read_exact(&mut addons).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ipv4() {
        let id = Uuid::nil();
        let b = encode_request(id, "1.2.3.4", 80);
        assert_eq!(b[0], 0);
        assert_eq!(&b[1..17], id.as_bytes());
        assert_eq!(b[17], 0);
        assert_eq!(b[18], 1);
        assert_eq!(&b[19..21], &[0, 80]);
        assert_eq!(b[21], 1);
        assert_eq!(&b[22..], &[1, 2, 3, 4]);
    }

    #[test]
    fn request_domain() {
        let b = encode_request(Uuid::nil(), "a.b", 443);
        assert_eq!(b[21], 2);
        assert_eq!(b[22], 3);
        assert_eq!(&b[23..26], b"a.b");
    }
}
