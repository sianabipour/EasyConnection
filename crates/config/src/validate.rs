use crate::model::*;
use crate::{ConfigError, Result};

pub fn validate_connection(cfg: &ConnectionConfig) -> Result<()> {
    if cfg.name.trim().is_empty() {
        return Err(ConfigError::Validation("name is required".into()));
    }
    if cfg.host.trim().is_empty() {
        return Err(ConfigError::Validation("host is required".into()));
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
            if cfg.username.as_ref().map(|u| u.is_empty()).unwrap_or(true) {
                return Err(ConfigError::Validation("SSH username is required".into()));
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
        (
            Protocol::Vless,
            ProtocolSettings::Vless {
                uuid,
                encryption,
                flow,
                ..
            },
        ) => {
            if Uuid::parse_str(uuid).is_err() {
                return Err(ConfigError::Validation(
                    "VLESS uuid must be a valid UUID".into(),
                ));
            }
            if !encryption.is_empty() && !encryption.eq_ignore_ascii_case("none") {
                return Err(ConfigError::Validation(
                    "VLESS encryption must be `none` (Vision/XTLS is not implemented)".into(),
                ));
            }
            if !flow.is_empty()
                && !flow.eq_ignore_ascii_case("none")
                && flow.to_ascii_lowercase().contains("vision")
            {
                return Err(ConfigError::Validation(
                    "VLESS flow `xtls-rprx-vision` is not implemented (no public XTLS wire)".into(),
                ));
            }
        }
        (Protocol::Socks, ProtocolSettings::Socks { .. }) => {}
        (p, _) => {
            return Err(ConfigError::Validation(format!(
                "protocol/settings mismatch for {p:?}"
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
    fn rejects_vless_vision() {
        let mut cfg = ConnectionConfig::new_vless(
            "v",
            "192.0.2.1",
            443,
            "00000000-0000-0000-0000-000000000000",
        );
        if let ProtocolSettings::Vless { flow, .. } = &mut cfg.settings {
            *flow = "xtls-rprx-vision".into();
        }
        assert!(validate_connection(&cfg).is_err());
    }
}
