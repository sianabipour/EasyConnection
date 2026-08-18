use std::net::IpAddr;

pub fn encode_socks_addr(host: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v) => {
                out.push(0x01);
                out.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                out.push(0x04);
                out.extend_from_slice(&v.octets());
            }
        }
    } else {
        let bytes = host.as_bytes();
        let n = bytes.len().min(255);
        out.push(0x03);
        out.push(n as u8);
        out.extend_from_slice(&bytes[..n]);
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4() {
        let b = encode_socks_addr("8.8.8.8", 53);
        assert_eq!(b, vec![1, 8, 8, 8, 8, 0, 53]);
    }

    #[test]
    fn domain() {
        let b = encode_socks_addr("example.com", 443);
        assert_eq!(b[0], 3);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(&b[13..], &[1, 187]);
    }
}
