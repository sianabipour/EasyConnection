//! BadVPN UDPGW + PacketProto framing (public protocol).
//!
//! Stream encoding (little-endian length, then payload):
//!   u16le len | flags:u8 | conid:u16le | addr | payload
//!
//! Address is IPv4 (4 + port:u16be) or IPv6 (16 + port:u16be) when
//! `FLAG_IPV6` is set. Keepalives omit the address and payload.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{Result, UdpgwError};

pub const FLAG_KEEPALIVE: u8 = 1 << 0;
pub const FLAG_REBIND: u8 = 1 << 1;
pub const FLAG_DNS: u8 = 1 << 2;
pub const FLAG_IPV6: u8 = 1 << 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpgwPacket {
    pub flags: u8,
    pub conid: u16,
    pub dest: Option<SocketAddr>,
    pub payload: Vec<u8>,
}

impl UdpgwPacket {
    pub fn keepalive(conid: u16) -> Self {
        Self {
            flags: FLAG_KEEPALIVE,
            conid,
            dest: None,
            payload: Vec::new(),
        }
    }

    pub fn data(conid: u16, dest: SocketAddr, payload: Vec<u8>, dns: bool, rebind: bool) -> Self {
        let mut flags = 0;
        if dest.is_ipv6() {
            flags |= FLAG_IPV6;
        }
        if dns {
            flags |= FLAG_DNS;
        }
        if rebind {
            flags |= FLAG_REBIND;
        }
        Self {
            flags,
            conid,
            dest: Some(dest),
            payload,
        }
    }
}

/// Encode one PacketProto frame (2-byte LE length + UDPGW body).
pub fn encode_frame(pkt: &UdpgwPacket) -> Result<Vec<u8>> {
    let body = encode_body(pkt)?;
    if body.len() > u16::MAX as usize {
        return Err(UdpgwError::Packet("UDPGW payload exceeds 65535".into()));
    }
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn encode_body(pkt: &UdpgwPacket) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(3 + 18 + pkt.payload.len());
    body.push(pkt.flags);
    body.extend_from_slice(&pkt.conid.to_le_bytes());
    if pkt.flags & FLAG_KEEPALIVE != 0 {
        return Ok(body);
    }
    let dest = pkt
        .dest
        .ok_or_else(|| UdpgwError::Packet("data packet missing destination".into()))?;
    match dest.ip() {
        IpAddr::V4(ip) => {
            body.extend_from_slice(&ip.octets());
            body.extend_from_slice(&dest.port().to_be_bytes());
        }
        IpAddr::V6(ip) => {
            if pkt.flags & FLAG_IPV6 == 0 {
                return Err(UdpgwError::Packet("IPv6 dest without FLAG_IPV6".into()));
            }
            body.extend_from_slice(&ip.octets());
            body.extend_from_slice(&dest.port().to_be_bytes());
        }
    }
    body.extend_from_slice(&pkt.payload);
    Ok(body)
}

pub fn decode_body(body: &[u8]) -> Result<UdpgwPacket> {
    if body.len() < 3 {
        return Err(UdpgwError::Packet("UDPGW header truncated".into()));
    }
    let flags = body[0];
    let conid = u16::from_le_bytes([body[1], body[2]]);
    if flags & FLAG_KEEPALIVE != 0 {
        return Ok(UdpgwPacket {
            flags,
            conid,
            dest: None,
            payload: Vec::new(),
        });
    }
    let rest = &body[3..];
    if flags & FLAG_IPV6 != 0 {
        if rest.len() < 18 {
            return Err(UdpgwError::Packet("IPv6 address truncated".into()));
        }
        let mut oct = [0u8; 16];
        oct.copy_from_slice(&rest[..16]);
        let port = u16::from_be_bytes([rest[16], rest[17]]);
        Ok(UdpgwPacket {
            flags,
            conid,
            dest: Some(SocketAddr::from((Ipv6Addr::from(oct), port))),
            payload: rest[18..].to_vec(),
        })
    } else {
        if rest.len() < 6 {
            return Err(UdpgwError::Packet("IPv4 address truncated".into()));
        }
        let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
        let port = u16::from_be_bytes([rest[4], rest[5]]);
        Ok(UdpgwPacket {
            flags,
            conid,
            dest: Some(SocketAddr::from((ip, port))),
            payload: rest[6..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn ipv4_roundtrip() {
        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let pkt = UdpgwPacket::data(1, dest, b"hello".to_vec(), true, false);
        let frame = encode_frame(&pkt).unwrap();
        assert_eq!(&frame[..2], &(frame.len() as u16 - 2).to_le_bytes());
        let body = &frame[2..];
        let got = decode_body(body).unwrap();
        assert_eq!(got.conid, 1);
        assert_eq!(got.dest, Some(dest));
        assert_eq!(got.payload, b"hello");
        assert_ne!(got.flags & FLAG_DNS, 0);
    }

    #[test]
    fn ipv6_roundtrip() {
        let dest = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
        let pkt = UdpgwPacket::data(7, dest, vec![1, 2, 3], false, true);
        let got = decode_body(&encode_body(&pkt).unwrap()).unwrap();
        assert_eq!(got.dest, Some(dest));
        assert_ne!(got.flags & FLAG_IPV6, 0);
        assert_ne!(got.flags & FLAG_REBIND, 0);
    }

    #[test]
    fn keepalive_has_no_addr() {
        let pkt = UdpgwPacket::keepalive(0);
        let body = encode_body(&pkt).unwrap();
        assert_eq!(body, vec![FLAG_KEEPALIVE, 0, 0]);
        let got = decode_body(&body).unwrap();
        assert!(got.dest.is_none());
    }

    #[test]
    fn issue121_style_header() {
        // flags=0, conid=1 LE, 8.8.8.8:53 BE, then payload
        let mut body = vec![0, 1, 0, 8, 8, 8, 8, 0, 53];
        body.extend_from_slice(b"dns");
        let got = decode_body(&body).unwrap();
        assert_eq!(got.conid, 1);
        assert_eq!(
            got.dest,
            Some(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)))
        );
        assert_eq!(got.payload, b"dns");
    }
}
