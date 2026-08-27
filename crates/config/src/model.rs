use chrono::{DateTime, Utc};
use rt_secrets::SecretRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// On-disk / export schema version.
pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Ssh,
    Socks,
    Shadowsocks,
    Vless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Direct,
    Tls,
    WebSocket,
    Wss,
    HttpUpgrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    System,
    Tunnel,
    Custom,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RoutingMode {
    #[default]
    ProxyOnly,
    FullTunnel,
    SplitTunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DnsOverTcp {
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum TlsFingerprintProfile {
    #[default]
    Default,
    Chrome,
    Firefox,
    Safari,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HostKeyPolicy {
    /// Reject unknown / mismatched keys (default).
    #[default]
    Strict,
    /// Prompt the user via UI before accepting.
    Ask,
    /// Trust on first use; still reject mismatches.
    Tofu,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[derive(Default)]
pub enum AuthMethod {
    Password {
        #[serde(default)]
        secret: Option<SecretRef>,
    },
    PrivateKey {
        path: Option<String>,
        #[serde(default)]
        passphrase: Option<SecretRef>,
        #[serde(default)]
        key_material: Option<SecretRef>,
    },
    Agent,
    #[default]
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolSettings {
    Ssh {
        #[serde(default = "default_keepalive")]
        keepalive_secs: u64,
        #[serde(default = "default_timeout")]
        connect_timeout_secs: u64,
        #[serde(default)]
        host_key_policy: HostKeyPolicy,
    },
    Socks {},
    Shadowsocks {
        method: String,
    },
    Vless {
        uuid: String,
        #[serde(default)]
        encryption: String,
        #[serde(default)]
        flow: String,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        path: Option<String>,
    },
}

fn default_keepalive() -> u64 {
    30
}

fn default_timeout() -> u64 {
    15
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsSettings {
    pub mode: DnsMode,
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub dns_over_tcp: DnsOverTcp,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            mode: DnsMode::System,
            servers: Vec::new(),
            dns_over_tcp: DnsOverTcp::Auto,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpgwSettings {
    pub enabled: bool,
    #[serde(default = "default_udpgw_host")]
    pub host: String,
    #[serde(default = "default_udpgw_port")]
    pub port: u16,
    #[serde(default)]
    pub transparent_dns: bool,
}

fn default_udpgw_host() -> String {
    "127.0.0.1".into()
}

fn default_udpgw_port() -> u16 {
    7300
}

impl Default for UdpgwSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_udpgw_host(),
            port: default_udpgw_port(),
            transparent_dns: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(default)]
    pub fingerprint: TlsFingerprintProfile,
    /// WS / HTTP Upgrade path (default `/`).
    #[serde(default)]
    pub path: Option<String>,
    /// Host header for WS / HTTP Upgrade (falls back to SNI, then server host).
    #[serde(default)]
    pub host: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            sni: None,
            alpn: Vec::new(),
            verify: true,
            fingerprint: TlsFingerprintProfile::Default,
            path: None,
            host: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyShareSettings {
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_http_port")]
    pub http_proxy_port: u16,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub require_auth: bool,
    #[serde(default)]
    pub auth_secret: Option<SecretRef>,
}

fn default_socks_port() -> u16 {
    1080
}
fn default_http_port() -> u16 {
    8080
}
fn default_listen() -> String {
    "127.0.0.1".into()
}

impl Default for ProxyShareSettings {
    fn default() -> Self {
        Self {
            socks_port: default_socks_port(),
            http_proxy_port: default_http_port(),
            listen: default_listen(),
            require_auth: false,
            auth_secret: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub id: Uuid,
    pub name: String,
    pub protocol: Protocol,
    pub transport: Transport,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub authentication: AuthMethod,
    #[serde(default)]
    pub dns: DnsSettings,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub mss: Option<u16>,
    #[serde(default)]
    pub routing_mode: RoutingMode,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    #[serde(default)]
    pub udpgw: UdpgwSettings,
    #[serde(default)]
    pub tls: TlsSettings,
    #[serde(default)]
    pub proxy: ProxyShareSettings,
    pub settings: ProtocolSettings,
    #[serde(default)]
    pub bypass_private_networks: bool,
    #[serde(default)]
    pub kill_switch: bool,
    /// Extra CIDRs that skip the nft redirect (split tunnel).
    #[serde(default)]
    pub split_bypass_cidrs: Vec<String>,
    /// Domains resolved at connect time and added to split bypass.
    #[serde(default)]
    pub split_bypass_domains: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ConnectionConfig {
    pub fn new_ssh(name: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            protocol: Protocol::Ssh,
            transport: Transport::Direct,
            host: host.into(),
            port,
            username: None,
            authentication: AuthMethod::Password { secret: None },
            dns: DnsSettings::default(),
            ipv6: false,
            mtu: None,
            mss: None,
            routing_mode: RoutingMode::ProxyOnly,
            auto_reconnect: true,
            udpgw: UdpgwSettings::default(),
            tls: TlsSettings::default(),
            proxy: ProxyShareSettings::default(),
            settings: ProtocolSettings::Ssh {
                keepalive_secs: default_keepalive(),
                connect_timeout_secs: default_timeout(),
                host_key_policy: HostKeyPolicy::Strict,
            },
            bypass_private_networks: true,
            kill_switch: false,
            split_bypass_cidrs: Vec::new(),
            split_bypass_domains: Vec::new(),
            notes: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_shadowsocks(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        method: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            protocol: Protocol::Shadowsocks,
            transport: Transport::Direct,
            host: host.into(),
            port,
            username: None,
            authentication: AuthMethod::Password { secret: None },
            dns: DnsSettings::default(),
            ipv6: false,
            mtu: None,
            mss: None,
            routing_mode: RoutingMode::ProxyOnly,
            auto_reconnect: true,
            udpgw: UdpgwSettings::default(),
            tls: TlsSettings::default(),
            proxy: ProxyShareSettings::default(),
            settings: ProtocolSettings::Shadowsocks {
                method: method.into(),
            },
            bypass_private_networks: true,
            kill_switch: false,
            split_bypass_cidrs: Vec::new(),
            split_bypass_domains: Vec::new(),
            notes: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_vless(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        uuid: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            protocol: Protocol::Vless,
            transport: Transport::Direct,
            host: host.into(),
            port,
            username: None,
            authentication: AuthMethod::None,
            dns: DnsSettings::default(),
            ipv6: false,
            mtu: None,
            mss: None,
            routing_mode: RoutingMode::ProxyOnly,
            auto_reconnect: true,
            udpgw: UdpgwSettings::default(),
            tls: TlsSettings::default(),
            proxy: ProxyShareSettings::default(),
            settings: ProtocolSettings::Vless {
                uuid: uuid.into(),
                encryption: "none".into(),
                flow: String::new(),
                host: None,
                path: None,
            },
            bypass_private_networks: true,
            kill_switch: false,
            split_bypass_cidrs: Vec::new(),
            split_bypass_domains: Vec::new(),
            notes: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Exportable JSON without secret material (refs stripped to type-only).
    pub fn export_safe(&self) -> ExportDocument {
        let mut cfg = self.clone();
        match &mut cfg.authentication {
            AuthMethod::Password { secret } => *secret = None,
            AuthMethod::PrivateKey {
                passphrase,
                key_material,
                ..
            } => {
                *passphrase = None;
                *key_material = None;
            }
            _ => {}
        }
        cfg.proxy.auth_secret = None;
        ExportDocument {
            version: CONFIG_VERSION,
            profile: cfg,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDocument {
    pub version: u32,
    pub profile: ConnectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: String,
    pub start_minimized: bool,
    pub reconnect_base_delay_ms: u64,
    pub reconnect_max_delay_ms: u64,
    pub log_level: String,
    /// Session routing mode chosen on the dashboard (not stored per profile).
    #[serde(default = "default_preferred_routing_mode")]
    pub preferred_routing_mode: String,
}

fn default_preferred_routing_mode() -> String {
    "proxy_only".into()
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            start_minimized: false,
            reconnect_base_delay_ms: 1_000,
            reconnect_max_delay_ms: 60_000,
            log_level: "info".into(),
            preferred_routing_mode: default_preferred_routing_mode(),
        }
    }
}
