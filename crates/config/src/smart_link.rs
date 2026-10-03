//! Read-only RocketTunnel `/i/` Smart Config link decoder.
//!
//! This implements the import envelope observed in the Android 3.0.8 Hermes
//! bytecode. It does not decrypt the binary tunnel config returned by GET.

use std::io::Read;

use base64::Engine;
use flate2::read::ZlibDecoder;
use zeroize::{Zeroize, Zeroizing};

use crate::{ConfigError, Result};

const MAX_LINK_BYTES: usize = 16 * 1024;
const MAX_DECODED_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MASK: [u8; 8] = [58, 127, 178, 217, 76, 133, 225, 98];

pub struct RocketSmartHost {
    pub host: String,
    pub port: u16,
    pub flag: u8,
    pub delay: u16,
}

impl Drop for RocketSmartHost {
    fn drop(&mut self) {
        self.host.zeroize();
    }
}

pub struct RocketSmartConfig {
    pub username: String,
    pub password: String,
    pub path: String,
    pub hosts: Vec<RocketSmartHost>,
}

impl Drop for RocketSmartConfig {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.path.zeroize();
    }
}

impl RocketSmartConfig {
    pub fn zone_hosts(&self) -> impl Iterator<Item = (&RocketSmartHost, bool)> {
        self.hosts.iter().flat_map(|host| {
            let http = (host.flag & 0x11) == 0x11;
            let https = (host.flag & 0x12) == 0x12;
            [(host, false, http), (host, true, https)]
                .into_iter()
                .filter_map(|(host, https, enabled)| enabled.then_some((host, https)))
        })
    }
}

fn import_error(message: &str) -> ConfigError {
    ConfigError::Import(format!("RocketTunnel Smart Config: {message}"))
}

fn decode_percent(input: &str) -> Result<String> {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = bytes
                .next()
                .and_then(|digit| (digit as char).to_digit(16))
                .ok_or_else(|| import_error("invalid link encoding"))?;
            let lo = bytes
                .next()
                .and_then(|digit| (digit as char).to_digit(16))
                .ok_or_else(|| import_error("invalid link encoding"))?;
            out.push(((hi << 4) | lo) as u8);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).map_err(|_| import_error("link is not UTF-8"))
}

pub fn decode_rocket_smart_link(link: &str) -> Result<RocketSmartConfig> {
    if link.len() > MAX_LINK_BYTES {
        return Err(import_error("link is too long"));
    }
    let url = url::Url::parse(link.trim()).map_err(|_| import_error("invalid URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(import_error("expected an HTTP(S) import URL"));
    }
    let token = url
        .path()
        .strip_prefix("/i/")
        .filter(|token| !token.is_empty())
        .ok_or_else(|| import_error("expected a /i/ Smart Config link"))?;
    let token = Zeroizing::new(decode_percent(token)?);
    let mut encoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(token.as_bytes()))
            .map_err(|_| import_error("invalid base64 payload"))?,
    );
    if encoded.len() < 3 || encoded.len() > MAX_DECODED_BYTES {
        return Err(import_error("invalid payload length"));
    }
    let flags = encoded[0];
    if flags >> 2 != 1 {
        return Err(import_error("unsupported envelope version"));
    }
    if flags & 2 != 0 {
        let seed = encoded[1];
        for (index, byte) in encoded[2..].iter_mut().enumerate() {
            *byte ^= MASK[index % MASK.len()] ^ seed.wrapping_shl((index % MASK.len()) as u32);
        }
    }
    let unpacked = Zeroizing::new(if flags & 1 != 0 {
        let mut decoder = ZlibDecoder::new(&encoded[2..]);
        let mut output = Vec::new();
        decoder
            .by_ref()
            .take((MAX_DECODED_BYTES + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| import_error("invalid compressed payload"))?;
        if output.len() > MAX_DECODED_BYTES {
            return Err(import_error("payload is too large"));
        }
        output
    } else {
        encoded[2..].to_vec()
    });
    let mut parser = PackedParser::new(&unpacked);
    let root = parser.read(0)?;
    if parser.position != unpacked.len() {
        return Err(import_error("unexpected trailing payload"));
    }
    let configs = root.as_array()?;
    let config = configs
        .iter()
        .find(|item| item.get("0").ok().and_then(|v| v.as_str().ok()) == Some("smart"))
        .ok_or_else(|| import_error("no Smart Config in link"))?;
    if config.get("13")?.as_int()? != 1 {
        return Err(import_error("unsupported Smart Config version"));
    }
    let hosts = config
        .get("14")?
        .as_array()?
        .iter()
        .map(|host| {
            let name = host.get("0")?.as_str()?;
            let port = u16::try_from(host.get("1")?.as_int()?)
                .map_err(|_| import_error("invalid Smart Config port"))?;
            let flag = u8::try_from(host.get("2")?.as_int()?)
                .map_err(|_| import_error("invalid host flags"))?;
            let delay = u16::try_from(host.get("3")?.as_int()?)
                .map_err(|_| import_error("invalid host delay"))?;
            if name.is_empty()
                || name.len() > 253
                || name.chars().any(|ch| {
                    ch.is_ascii_control() || ch.is_ascii_whitespace() || "/\\@?#".contains(ch)
                })
                || port == 0
            {
                return Err(import_error("invalid Smart Config host"));
            }
            Ok(RocketSmartHost {
                host: name.to_string(),
                port,
                flag,
                delay,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if hosts.is_empty() || hosts.len() > 64 {
        return Err(import_error("invalid Smart Config host count"));
    }
    let path = config.get("16")?.as_str()?.to_string();
    if !path.starts_with('/') || path.len() > 2048 || path.contains('\r') || path.contains('\n') {
        return Err(import_error("invalid Smart Config path"));
    }
    let username = config.get("4")?.as_str()?;
    let password = config.get("15")?.as_str()?;
    if username.len() > 4096 || password.len() > 4096 {
        return Err(import_error("Smart Config credentials are too long"));
    }
    Ok(RocketSmartConfig {
        username: username.to_string(),
        password: password.to_string(),
        path,
        hosts,
    })
}

enum Packed {
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<Packed>),
    Map(Vec<(String, Packed)>),
    Other,
}

impl Packed {
    fn get(&self, key: &str) -> Result<&Self> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value)
                .ok_or_else(|| import_error("missing Smart Config field")),
            _ => Err(import_error("expected Smart Config object")),
        }
    }

    fn as_str(&self) -> Result<&str> {
        match self {
            Self::Str(value) => Ok(value),
            _ => Err(import_error("expected Smart Config string")),
        }
    }

    fn as_int(&self) -> Result<i64> {
        match self {
            Self::Int(value) => Ok(*value),
            _ => Err(import_error("expected Smart Config integer")),
        }
    }

    fn as_array(&self) -> Result<&[Self]> {
        match self {
            Self::Array(values) => Ok(values),
            _ => Err(import_error("expected Smart Config array")),
        }
    }
}

struct PackedParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> PackedParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| import_error("invalid MessagePack length"))?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or_else(|| import_error("truncated MessagePack payload"))?;
        self.position = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn number(&mut self, count: usize) -> Result<i64> {
        Ok(self
            .take(count)?
            .iter()
            .fold(0_i64, |value, byte| (value << 8) | i64::from(*byte)))
    }

    fn string(&mut self, count: usize) -> Result<Packed> {
        let text = std::str::from_utf8(self.take(count)?)
            .map_err(|_| import_error("invalid MessagePack UTF-8"))?;
        Ok(Packed::Str(text.to_string()))
    }

    fn array(&mut self, count: usize, depth: usize) -> Result<Packed> {
        if count > 256 {
            return Err(import_error("MessagePack array is too large"));
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.read(depth + 1)?);
        }
        Ok(Packed::Array(values))
    }

    fn map(&mut self, count: usize, depth: usize) -> Result<Packed> {
        if count > 256 {
            return Err(import_error("MessagePack object is too large"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let key = match self.read(depth + 1)? {
                Packed::Str(key) => key,
                _ => return Err(import_error("invalid MessagePack map key")),
            };
            entries.push((key, self.read(depth + 1)?));
        }
        Ok(Packed::Map(entries))
    }

    fn read(&mut self, depth: usize) -> Result<Packed> {
        if depth > MAX_DEPTH {
            return Err(import_error("MessagePack nesting is too deep"));
        }
        let tag = self.byte()?;
        match tag {
            0x00..=0x7f => Ok(Packed::Int(i64::from(tag))),
            0xe0..=0xff => Ok(Packed::Int(i64::from(tag as i8))),
            0x80..=0x8f => self.map(usize::from(tag & 0x0f), depth),
            0x90..=0x9f => self.array(usize::from(tag & 0x0f), depth),
            0xa0..=0xbf => self.string(usize::from(tag & 0x1f)),
            0xc0 | 0xc2 | 0xc3 => Ok(Packed::Other),
            0xc4 => {
                let count = usize::from(self.byte()?);
                Ok(Packed::Bytes(self.take(count)?.to_vec()))
            }
            0xc5 => {
                let count = usize::try_from(self.number(2)?)
                    .map_err(|_| import_error("invalid MessagePack length"))?;
                Ok(Packed::Bytes(self.take(count)?.to_vec()))
            }
            0xcc | 0xd0 => Ok(Packed::Int(self.number(1)?)),
            0xcd | 0xd1 => Ok(Packed::Int(self.number(2)?)),
            0xce | 0xd2 => Ok(Packed::Int(self.number(4)?)),
            0xd9 => {
                let count = usize::from(self.byte()?);
                self.string(count)
            }
            0xda => {
                let count = usize::try_from(self.number(2)?)
                    .map_err(|_| import_error("invalid MessagePack length"))?;
                self.string(count)
            }
            0xdc => {
                let count = usize::try_from(self.number(2)?)
                    .map_err(|_| import_error("invalid MessagePack length"))?;
                self.array(count, depth)
            }
            0xde => {
                let count = usize::try_from(self.number(2)?)
                    .map_err(|_| import_error("invalid MessagePack length"))?;
                self.map(count, depth)
            }
            // The reference's PackedUint8/16 extension is followed by a bin
            // value containing the big-endian integer bytes.
            0xd4 => {
                let kind = self.byte()?;
                self.take(1)?;
                let bytes = match self.read(depth + 1)? {
                    Packed::Bytes(bytes) => bytes,
                    _ => return Err(import_error("invalid packed integer")),
                };
                match (kind, bytes.as_slice()) {
                    (16, [value]) => Ok(Packed::Int(i64::from(*value))),
                    (17, [hi, lo]) => Ok(Packed::Int(i64::from(u16::from_be_bytes([*hi, *lo])))),
                    _ => Err(import_error("invalid packed integer")),
                }
            }
            _ => Err(import_error("unsupported MessagePack tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use flate2::{write::ZlibEncoder, Compression};

    fn push_str(buf: &mut Vec<u8>, value: &str) {
        assert!(value.len() < 32);
        buf.push(0xa0 | value.len() as u8);
        buf.extend_from_slice(value.as_bytes());
    }

    fn push_field(buf: &mut Vec<u8>, key: &str, value: &str) {
        push_str(buf, key);
        push_str(buf, value);
    }

    fn fixture() -> String {
        let mut packed = vec![0x91, 0x86]; // one config; six fields
        push_field(&mut packed, "0", "smart");
        push_field(&mut packed, "4", "test-user");
        push_str(&mut packed, "13");
        packed.push(1);
        push_str(&mut packed, "14");
        packed.extend_from_slice(&[0x91, 0x84]); // one host; four fields
        push_field(&mut packed, "0", "entry.example");
        push_str(&mut packed, "1");
        packed.extend_from_slice(&[0xd4, 16, 0, 0xc4, 1, 80]); // PackedUint8 extension
        push_str(&mut packed, "2");
        packed.push(17);
        push_str(&mut packed, "3");
        packed.push(0);
        push_field(&mut packed, "15", "test-password");
        push_field(&mut packed, "16", "/config");

        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(&packed).unwrap();
        let compressed = zlib.finish().unwrap();
        let seed = 19_u8;
        let mut envelope = vec![7, seed]; // version 1, locked, compressed
        envelope.extend(compressed.iter().enumerate().map(|(index, byte)| {
            byte ^ MASK[index % MASK.len()] ^ seed.wrapping_shl((index % MASK.len()) as u32)
        }));
        let token = base64::engine::general_purpose::STANDARD.encode(envelope);
        format!(
            "https://import.example/i/{}",
            token.replace('+', "%2B").replace('/', "%2F")
        )
    }

    #[test]
    fn decodes_synthetic_smart_link_and_host_flags() {
        let config = decode_rocket_smart_link(&fixture()).unwrap();
        assert_eq!(config.username, "test-user");
        assert_eq!(config.password, "test-password");
        assert_eq!(config.path, "/config");
        assert_eq!(config.hosts.len(), 1);
        assert_eq!(config.hosts[0].port, 80);
        assert_eq!(config.zone_hosts().count(), 1);
        assert!(!config.zone_hosts().next().unwrap().1);
    }

    #[test]
    fn rejects_non_import_url_and_bad_payload() {
        assert!(decode_rocket_smart_link("https://import.example/other/abc").is_err());
        assert!(decode_rocket_smart_link("https://import.example/i/???").is_err());
    }
}
