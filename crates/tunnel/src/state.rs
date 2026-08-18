use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    EstablishingTunnel,
    Connected,
    Degraded,
    Reconnecting,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Idle,
    ResolvingServer,
    EstablishingTcp,
    NegotiatingTransport,
    Authenticating,
    EstablishingTunnel,
    ConfiguringRoutes,
    ConfiguringDns,
    Ready,
    Reconnecting { attempt: u32 },
    Failed { message: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub rate_down_bps: u64,
    pub rate_up_bps: u64,
    pub active_flows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub state: ConnectionState,
    pub phase: ConnectionPhase,
    pub profile_id: Option<Uuid>,
    pub profile_name: Option<String>,
    pub socks_endpoint: Option<String>,
    pub http_endpoint: Option<String>,
    pub connected_since: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_error_detail: Option<String>,
    pub stats: TrafficStats,
    pub ipv6: bool,
    pub routing_mode: String,
    pub dns_status: String,
    pub udpgw_status: String,
    pub server_label: Option<String>,
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub tun_name: Option<String>,
    #[serde(default)]
    pub helper_ok: bool,
    #[serde(default)]
    pub udp_note: Option<String>,
    #[serde(default)]
    pub kill_switch: bool,
}

impl Default for ConnectionSnapshot {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            phase: ConnectionPhase::Idle,
            profile_id: None,
            profile_name: None,
            socks_endpoint: None,
            http_endpoint: None,
            connected_since: None,
            last_error: None,
            last_error_detail: None,
            stats: TrafficStats::default(),
            ipv6: false,
            routing_mode: "proxy_only".into(),
            dns_status: "system".into(),
            udpgw_status: "disabled".into(),
            server_label: None,
            latency_ms: None,
            tun_name: None,
            helper_ok: false,
            udp_note: None,
            kill_switch: false,
        }
    }
}
