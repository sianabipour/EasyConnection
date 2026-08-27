//! Import JSON exports and common share URIs (ss://, vless://, ssh://).

use crate::model::*;
use crate::{ConfigError, Result};

pub struct ParsedImport {
    pub config: ConnectionConfig,
    pub password: Option<String>,
}

/// Parse a JSON export, a raw profile JSON, or a share URI.
pub fn parse_import(raw: &str) -> Result<ParsedImport> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Import("empty import".into()));
    }
    if trimmed.starts_with('{') {
        return parse_json(trimmed);
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("ss://") {
        return parse_ss(trimmed);
    }
    if lower.starts_with("vless://") {
        return parse_vless(trimmed);
    }
    if lower.starts_with("ssh://") {
        return parse_ssh(trimmed);
    }
    Err(ConfigError::Import(
        "unrecognized import (need JSON, ss://, vless://, or ssh://)".into(),
    ))
}

fn parse_json(raw: &str) -> Result<ParsedImport> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    if version > CONFIG_VERSION as u64 {
        return Err(ConfigError::Import(format!(
            "unsupported config version {version}"
        )));
    }
    let mut profile: ConnectionConfig = if value.get("profile").is_some() {
        serde_json::from_value(value.get("profile").cloned().unwrap())?
    } else {
        serde_json::from_value(value)?
    };
    profile.id = uuid::Uuid::new_v4();
    profile.updated_at = chrono::Utc::now();
    // Routing mode is a dashboard/session choice — never import it from files.
    profile.routing_mode = RoutingMode::ProxyOnly;
    crate::validate_connection(&profile)?;
    Ok(ParsedImport {
        config: profile,
        password: None,
    })
}

fn parse_ss(raw: &str) -> Result<ParsedImport> {
    let rest = raw.trim()[5..].trim();
    let (body, fragment) = split_fragment(rest);
    let decoded = if body.contains('@') {
        percent_decode(body)
    } else {
        let b64 = body.split('#').next().unwrap_or(body);
        let bytes = decode_base64(b64).map_err(ConfigError::Import)?;
        String::from_utf8(bytes).map_err(|_| ConfigError::Import("ss:// is not UTF-8".into()))?
    };
    // method:password@host:port
    let (userinfo, hostport) = decoded
        .rsplit_once('@')
        .ok_or_else(|| ConfigError::Import("ss:// missing host".into()))?;
    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| ConfigError::Import("ss:// missing method:password".into()))?;
    let (host, port) = split_host_port(hostport, 8388)?;
    let name = fragment.unwrap_or_else(|| format!("ss {host}"));
    let cfg = ConnectionConfig::new_shadowsocks(name, host, port, method);
    crate::validate_connection(&cfg).map_err(|e| ConfigError::Import(e.to_string()))?;
    Ok(ParsedImport {
        config: cfg,
        password: Some(password.to_string()),
    })
}

fn parse_vless(raw: &str) -> Result<ParsedImport> {
    let url = url::Url::parse(raw).map_err(|e| ConfigError::Import(e.to_string()))?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err(ConfigError::Import("vless:// missing uuid".into()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::Import("vless:// missing host".into()))?
        .to_string();
    let port = url.port().unwrap_or(443);
    let name = url
        .fragment()
        .map(percent_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("vless {host}"));
    let mut cfg = ConnectionConfig::new_vless(name, host, port, uuid);
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    for (k, v) in &pairs {
        match k.to_ascii_lowercase().as_str() {
            "encryption" => {
                if let ProtocolSettings::Vless { encryption, .. } = &mut cfg.settings {
                    *encryption = v.clone();
                }
            }
            "flow" => {
                if let ProtocolSettings::Vless { flow, .. } = &mut cfg.settings {
                    *flow = v.clone();
                }
            }
            "path" => {
                cfg.tls.path = Some(v.clone());
                if let ProtocolSettings::Vless { path, .. } = &mut cfg.settings {
                    *path = Some(v.clone());
                }
            }
            "host" => {
                cfg.tls.host = Some(v.clone());
                if let ProtocolSettings::Vless { host, .. } = &mut cfg.settings {
                    *host = Some(v.clone());
                }
            }
            "sni" => cfg.tls.sni = Some(v.clone()),
            "fp" | "fingerprint" => {
                cfg.tls.fingerprint = match v.to_ascii_lowercase().as_str() {
                    "chrome" => TlsFingerprintProfile::Chrome,
                    "firefox" => TlsFingerprintProfile::Firefox,
                    "safari" => TlsFingerprintProfile::Safari,
                    "custom" => TlsFingerprintProfile::Custom,
                    _ => TlsFingerprintProfile::Default,
                };
            }
            "security" => {
                if (v.eq_ignore_ascii_case("tls") || v.eq_ignore_ascii_case("reality"))
                    && cfg.transport == Transport::Direct
                {
                    cfg.transport = Transport::Tls;
                }
            }
            "type" | "net" => match v.to_ascii_lowercase().as_str() {
                "ws" | "websocket" => {
                    cfg.transport = if matches!(cfg.transport, Transport::Tls | Transport::Wss) {
                        Transport::Wss
                    } else {
                        Transport::WebSocket
                    };
                }
                "httpupgrade" | "http_upgrade" => cfg.transport = Transport::HttpUpgrade,
                _ => {}
            },
            "alpn" => {
                cfg.tls.alpn = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "allowinsecure" | "insecure" if v == "1" || v.eq_ignore_ascii_case("true") => {
                cfg.tls.verify = false;
            }
            _ => {}
        }
    }
    crate::validate_connection(&cfg)?;
    Ok(ParsedImport {
        config: cfg,
        password: None,
    })
}

fn parse_ssh(raw: &str) -> Result<ParsedImport> {
    let url = url::Url::parse(raw).map_err(|e| ConfigError::Import(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::Import("ssh:// missing host".into()))?
        .to_string();
    let port = url.port().unwrap_or(22);
    let username = url.username();
    if username.is_empty() {
        return Err(ConfigError::Import("ssh:// missing username".into()));
    }
    let password = url.password().map(percent_decode);
    let name = url
        .fragment()
        .map(percent_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ssh {host}"));
    let mut cfg = ConnectionConfig::new_ssh(name, host, port);
    cfg.username = Some(percent_decode(username));
    crate::validate_connection(&cfg)?;
    Ok(ParsedImport {
        config: cfg,
        password,
    })
}

fn split_fragment(s: &str) -> (&str, Option<String>) {
    match s.split_once('#') {
        Some((a, b)) => (a, Some(percent_decode(b))),
        None => (s, None),
    }
}

fn split_host_port(s: &str, default: u16) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, portpart) = rest
            .split_once(']')
            .ok_or_else(|| ConfigError::Import("bad IPv6 host".into()))?;
        let port = portpart
            .strip_prefix(':')
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| ConfigError::Import("bad port".into()))?
            .unwrap_or(default);
        return Ok((host.to_string(), port));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if h.contains(':') {
            return Ok((s.to_string(), default));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| ConfigError::Import("bad port".into()))?;
        return Ok((h.to_string(), port));
    }
    Ok((s.to_string(), default))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_base64(s: &str) -> std::result::Result<Vec<u8>, String> {
    use base64::Engine;
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = match cleaned.len() % 4 {
        2 => format!("{cleaned}=="),
        3 => format!("{cleaned}="),
        _ => cleaned,
    };
    base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded))
        .map_err(|e| format!("ss:// base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_userinfo() {
        let p = parse_import("ss://aes-256-gcm:secret@192.0.2.1:8388#lab").unwrap();
        assert_eq!(p.config.host, "192.0.2.1");
        assert_eq!(p.config.port, 8388);
        assert_eq!(p.password.as_deref(), Some("secret"));
        assert_eq!(p.config.name, "lab");
    }

    #[test]
    fn vless_tls() {
        let p = parse_import(
            "vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&security=tls&sni=example.com#n",
        )
        .unwrap();
        assert_eq!(p.config.transport, Transport::Tls);
        assert_eq!(p.config.tls.sni.as_deref(), Some("example.com"));
        assert_eq!(p.config.name, "n");
    }

    #[test]
    fn ssh_uri() {
        let p = parse_import("ssh://alice:pw@192.0.2.8:22#home").unwrap();
        assert_eq!(p.config.username.as_deref(), Some("alice"));
        assert_eq!(p.password.as_deref(), Some("pw"));
    }
}
