use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const IPC_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelperRequest {
    Ping { version: u32 },
    Cleanup,
    Apply { spec: ApplySpec },
    Teardown,
    EmergencyRestore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperResponse {
    Pong {
        version: u32,
        uid: u32,
    },
    Ok {
        message: String,
        tun_name: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplySpec {
    pub session_id: Uuid,
    pub tun_name: String,
    pub tun_addr: Ipv4Addr,
    pub tun_prefix: u8,
    pub mtu: u16,
    pub server_ips: Vec<IpAddr>,
    pub bypass_private: bool,
    #[serde(default)]
    pub extra_bypass: Vec<IpNet>,
    pub ipv6: bool,
    pub kill_switch: bool,
    #[serde(default = "default_transproxy_port")]
    pub transproxy_port: u16,
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
    /// system | tunnel | custom | remote
    #[serde(default)]
    pub dns_mode: String,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// When non-zero, leftover UDP is redirected here instead of rejected.
    #[serde(default)]
    pub udp_port: u16,
}

fn default_transproxy_port() -> u16 {
    crate::TRANSPROXY_PORT
}
fn default_dns_port() -> u16 {
    crate::DNS_PROXY_PORT
}

impl ApplySpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.tun_name != crate::TUN_NAME {
            return Err(format!(
                "refusing TUN name `{}` (only {} is allowed)",
                self.tun_name,
                crate::TUN_NAME
            ));
        }
        if !(576..=9000).contains(&self.mtu) {
            return Err("MTU must be between 576 and 9000".into());
        }
        if self.tun_prefix > 32 {
            return Err("invalid TUN prefix".into());
        }
        if self.server_ips.is_empty() {
            return Err("server_ips must contain the resolved SSH endpoint".into());
        }
        if self.transproxy_port == 0 || self.dns_port == 0 {
            return Err("intercept ports must be non-zero".into());
        }
        Ok(())
    }
}

pub fn socket_path_from_env() -> PathBuf {
    if let Ok(p) = std::env::var("EASY_HELPER_SOCKET") {
        return PathBuf::from(p);
    }
    PathBuf::from(crate::DEFAULT_SOCKET)
}
