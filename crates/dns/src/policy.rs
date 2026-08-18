//! Which DNS servers to use and whether the helper should touch systemd-resolved.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicy {
    System,
    Tunnel,
    Custom,
    Remote,
}

impl DnsPolicy {
    pub fn parse(mode: &str) -> Self {
        match mode {
            "custom" => Self::Custom,
            "remote" => Self::Remote,
            "system" => Self::System,
            _ => Self::Tunnel,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Tunnel => "tunnel",
            Self::Custom => "custom",
            Self::Remote => "remote",
        }
    }
}

/// Full/split tunnel with "system" DNS would leak via the LAN resolver.
/// Upgrade that combination to tunnel DNS.
pub fn effective_policy(routing_is_tunnel: bool, configured: DnsPolicy) -> DnsPolicy {
    if routing_is_tunnel && configured == DnsPolicy::System {
        DnsPolicy::Tunnel
    } else {
        configured
    }
}

pub fn resolve_servers(policy: DnsPolicy, configured: &[String]) -> Vec<String> {
    match policy {
        DnsPolicy::System => Vec::new(),
        DnsPolicy::Custom if !configured.is_empty() => configured.to_vec(),
        _ if !configured.is_empty() => configured.to_vec(),
        _ => crate::default_dns_servers()
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }
}

pub fn should_configure_resolved(policy: DnsPolicy) -> bool {
    !matches!(policy, DnsPolicy::System)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_upgrades_system_to_tunnel() {
        assert_eq!(effective_policy(true, DnsPolicy::System), DnsPolicy::Tunnel);
        assert_eq!(
            effective_policy(false, DnsPolicy::System),
            DnsPolicy::System
        );
        assert_eq!(effective_policy(true, DnsPolicy::Custom), DnsPolicy::Custom);
    }

    #[test]
    fn custom_keeps_user_servers() {
        let s = resolve_servers(DnsPolicy::Custom, &["9.9.9.9".into()]);
        assert_eq!(s, vec!["9.9.9.9"]);
    }
}
