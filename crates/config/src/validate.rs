use crate::model::*;
use crate::{ConfigError, Result};

pub fn validate_connection(cfg: &ConnectionConfig) -> Result<()> {
    if cfg.name.trim().is_empty() {
        return Err(ConfigError::Validation("name is required".into()));
    }
    if cfg.name.len() > 128 || cfg.name.chars().any(char::is_control) {
        return Err(ConfigError::Validation(
            "name must be at most 128 characters and contain no control characters".into(),
        ));
    }
    if cfg.host.trim().is_empty() {
        return Err(ConfigError::Validation("host is required".into()));
    }
    if cfg.host.len() > 255
        || cfg
            .host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        || cfg.host.contains('/')
    {
        return Err(ConfigError::Validation(
            "host must be at most 255 characters and contain no whitespace, control characters, or path separators"
                .into(),
        ));
    }
    if cfg.port == 0 {
        return Err(ConfigError::Validation("port must be 1–65535".into()));
    }
    if let Some(mtu) = cfg.mtu {
        if !(576..=9000).contains(&mtu) {
            return Err(ConfigError::Validation(
                "MTU must be between 576 and 9000".into(),
            ));
        }
    }
    if cfg.proxy.socks_port == 0 || cfg.proxy.http_proxy_port == 0 {
        return Err(ConfigError::Validation(
            "proxy ports must be non-zero".into(),
        ));
    }
    if cfg.proxy.socks_port == cfg.proxy.http_proxy_port {
        return Err(ConfigError::Validation(
            "SOCKS and HTTP proxy ports must be different".into(),
        ));
    }
    if cfg.proxy.listen != "127.0.0.1"
        && cfg.proxy.listen != "0.0.0.0"
        && cfg.proxy.listen != "::1"
        && cfg.proxy.listen != "::"
        && cfg.proxy.listen != "LAN"
    {
        // Allow IPv4/IPv6 literals — basic check
        if cfg.proxy.listen.parse::<std::net::IpAddr>().is_err() {
            return Err(ConfigError::Validation(format!(
                "invalid listen address: {}",
                cfg.proxy.listen
            )));
        }
    }

    match (&cfg.protocol, &cfg.settings) {
        (Protocol::Ssh, ProtocolSettings::Ssh { .. }) => {
            if cfg
                .username
                .as_ref()
                .map(|u| u.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(ConfigError::Validation("SSH username is required".into()));
            }
            if cfg
                .username
                .as_ref()
                .is_some_and(|u| u.len() > 255 || u.chars().any(char::is_control))
            {
                return Err(ConfigError::Validation(
                    "SSH username is too long or contains control characters".into(),
                ));
            }
        }
        (Protocol::Shadowsocks, ProtocolSettings::Shadowsocks { method }) => {
            if method.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "Shadowsocks method is required".into(),
                ));
            }
            let m = method.to_ascii_lowercase();
            if !matches!(m.as_str(), "aes-128-gcm" | "aes-256-gcm") {
                return Err(ConfigError::Validation(format!(
                    "unsupported Shadowsocks method `{method}`. Supported: aes-128-gcm, aes-256-gcm. SS2022 is not implemented in this phase."
                )));
            }
        }
        (Protocol::Vless, ProtocolSettings::Vless(settings)) => {
            let VlessSettings {
                uuid,
                encryption,
                flow,
                network,
                security,
                reality_public_key,
                reality_short_id,
                ..
            } = settings.as_ref();
            if Uuid::parse_str(uuid).is_err() {
                return Err(ConfigError::Validation(
                    "VLESS uuid must be a valid UUID".into(),
                ));
            }
            if !encryption.is_empty() && !encryption.eq_ignore_ascii_case("none") {
                return Err(ConfigError::Validation(
                    "VLESS encryption must be `none` for Xray/sing-box compatibility".into(),
                ));
            }
            let flow = flow.to_ascii_lowercase();
            if !matches!(
                flow.as_str(),
                "" | "none" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
            ) {
                return Err(ConfigError::Validation(format!(
                    "unsupported VLESS flow `{flow}`"
                )));
            }
            let network = network.to_ascii_lowercase();
            if !matches!(
                network.as_str(),
                "tcp" | "raw" | "ws" | "websocket" | "grpc" | "httpupgrade" | "xhttp"
            ) {
                return Err(ConfigError::Validation(format!(
                    "unsupported VLESS network `{network}`"
                )));
            }
            let security = security.to_ascii_lowercase();
            if !matches!(security.as_str(), "none" | "" | "tls" | "reality") {
                return Err(ConfigError::Validation(format!(
                    "unsupported VLESS security `{security}`"
                )));
            }
            if matches!(
                flow.as_str(),
                "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
            ) && (!matches!(network.as_str(), "tcp" | "raw")
                || !matches!(security.as_str(), "tls" | "reality"))
            {
                return Err(ConfigError::Validation(
                    "VLESS Vision requires tcp with tls or reality".into(),
                ));
            }
            if security == "reality" {
                if reality_public_key
                    .as_deref()
                    .map_or(true, |key| key.trim().is_empty())
                {
                    return Err(ConfigError::Validation(
                        "VLESS Reality requires a public key (`pbk`)".into(),
                    ));
                }
                if cfg
                    .tls
                    .sni
                    .as_deref()
                    .map_or(true, |sni| sni.trim().is_empty())
                {
                    return Err(ConfigError::Validation(
                        "VLESS Reality requires a server name (`sni`)".into(),
                    ));
                }
                if !matches!(network.as_str(), "tcp" | "raw" | "grpc" | "xhttp") {
                    return Err(ConfigError::Validation(
                        "VLESS Reality supports tcp, grpc, or xhttp transport".into(),
                    ));
                }
                if let Some(short_id) = reality_short_id {
                    if short_id.len() > 16
                        || short_id.len() % 2 != 0
                        || !short_id.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        return Err(ConfigError::Validation(
                            "VLESS Reality short ID must be an even-length hexadecimal string of at most 16 characters"
                                .into(),
                        ));
                    }
                }
            }
        }
        (Protocol::Socks, ProtocolSettings::Socks { .. }) => {}
        (p, _) => {
            return Err(ConfigError::Validation(format!(
                "protocol/settings mismatch for {p:?}"
            )));
        }
    }

    if cfg.udpgw.enabled && cfg.protocol != Protocol::Ssh {
        return Err(ConfigError::Validation(
            "UDPGW is supported only for SSH profiles".into(),
        ));
    }

    if let Some(sni) = cfg.tls.sni.as_deref() {
        if sni.len() > 255 || sni.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(ConfigError::Validation(
                "TLS SNI is too long or contains whitespace/control characters".into(),
            ));
        }
    }
    if let Some(host) = cfg.tls.host.as_deref() {
        if host.len() > 255 || host.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(ConfigError::Validation(
                "transport Host header is too long or contains forbidden characters".into(),
            ));
        }
    }
    if let Some(path) = cfg.tls.path.as_deref() {
        if !path.starts_with('/')
            || path.len() > 2048
            || path.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
        {
            return Err(ConfigError::Validation(
                "WebSocket/HTTP Upgrade path must start with `/`, be at most 2048 bytes, and contain no control line breaks"
                    .into(),
            ));
        }
    }
    for alpn in &cfg.tls.alpn {
        if alpn.is_empty()
            || alpn.len() > 255
            || alpn.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(ConfigError::Validation(format!(
                "invalid TLS ALPN protocol: {alpn:?}"
            )));
        }
    }

    if matches!(
        cfg.transport,
        Transport::Tls | Transport::Wss | Transport::HttpUpgrade
    ) && !cfg.tls.verify
    {
        tracing::warn!(
            profile = %cfg.name,
            "TLS certificate verification is disabled — not recommended"
        );
    }

    for server in &cfg.dns.servers {
        if server.parse::<std::net::IpAddr>().is_err() {
            return Err(ConfigError::Validation(format!(
                "invalid DNS server address: {server}"
            )));
        }
    }

    for cidr in &cfg.split_bypass_cidrs {
        if cidr.parse::<ipnet::IpNet>().is_err() {
            return Err(ConfigError::Validation(format!(
                "invalid split-bypass CIDR: {cidr}"
            )));
        }
    }
    for domain in &cfg.split_bypass_domains {
        if domain.trim().is_empty() || domain.contains(' ') {
            return Err(ConfigError::Validation(format!(
                "invalid split-bypass domain: {domain}"
            )));
        }
    }

    Ok(())
}

use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_host() {
        let mut cfg = ConnectionConfig::new_ssh("t", "example.com", 22);
        cfg.username = Some("user".into());
        cfg.host = String::new();
        assert!(validate_connection(&cfg).is_err());
    }

    #[test]
    fn accepts_minimal_ssh() {
        let mut cfg = ConnectionConfig::new_ssh("Home", "192.0.2.1", 22);
        cfg.username = Some("alice".into());
        assert!(validate_connection(&cfg).is_ok());
    }

    #[test]
    fn accepts_shadowsocks_aead() {
        let cfg = ConnectionConfig::new_shadowsocks("ss", "192.0.2.1", 8388, "aes-256-gcm");
        assert!(validate_connection(&cfg).is_ok());
    }

    #[test]
    fn rejects_ss2022() {
        let cfg =
            ConnectionConfig::new_shadowsocks("ss", "192.0.2.1", 8388, "2022-blake3-aes-256-gcm");
        assert!(validate_connection(&cfg).is_err());
    }

    #[test]
    fn accepts_vless_none() {
        let cfg = ConnectionConfig::new_vless(
            "v",
            "192.0.2.1",
            443,
            "00000000-0000-0000-0000-000000000000",
        );
        assert!(validate_connection(&cfg).is_ok());
    }

    #[test]
    fn accepts_vless_vision() {
        let mut cfg = ConnectionConfig::new_vless(
            "v",
            "192.0.2.1",
            443,
            "00000000-0000-0000-0000-000000000000",
        );
        if let ProtocolSettings::Vless(settings) = &mut cfg.settings {
            let crate::VlessSettings { flow, security, .. } = settings.as_mut();
            *flow = "xtls-rprx-vision".into();
            *security = "tls".into();
        }
        assert!(validate_connection(&cfg).is_ok());
    }

    #[test]
    fn rejects_any_unsupported_vless_flow() {
        let mut cfg = ConnectionConfig::new_vless(
            "v",
            "192.0.2.1",
            443,
            "00000000-0000-0000-0000-000000000000",
        );
        if let ProtocolSettings::Vless(settings) = &mut cfg.settings {
            let crate::VlessSettings { flow, .. } = settings.as_mut();
            *flow = "some-future-flow".into();
        }
        assert!(validate_connection(&cfg).is_err());
    }

    #[test]
    fn rejects_http_header_injection_fields() {
        let mut cfg = ConnectionConfig::new_vless(
            "v",
            "example.com",
            443,
            "00000000-0000-0000-0000-000000000000",
        );
        cfg.transport = Transport::Wss;
        cfg.tls.host = Some("example.com\r\nX-Injected: yes".into());
        assert!(validate_connection(&cfg).is_err());

        cfg.tls.host = Some("example.com".into());
        cfg.tls.path = Some("/ok\r\nX-Injected: yes".into());
        assert!(validate_connection(&cfg).is_err());
    }
}
