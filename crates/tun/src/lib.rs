//! Linux TUN helpers and authenticated Unix-socket IPC for the privileged helper.

pub mod client;
mod device;
pub mod elevate;
mod error;
mod frame;
pub mod ipc;

pub use client::HelperClient;
pub use device::{create_named_tun, TunIo};
pub use elevate::{ensure_helper_or_tun_error, ensure_helper_running, helper_reachable};
pub use error::TunError;
pub use frame::{recv_frame, send_frame, RecvFrame};
pub use ipc::{ApplySpec, HelperRequest, HelperResponse};

use std::net::{Ipv4Addr, Ipv6Addr};

pub type Result<T> = std::result::Result<T, TunError>;

pub const TUN_NAME: &str = "easy0";
pub const NFT_TABLE: &str = "easy";
pub const DEFAULT_SOCKET: &str = "/run/easy/helper.sock";
pub const RUN_DIR: &str = "/run/easy";
pub const SESSION_JOURNAL: &str = "/run/easy/session.json";
pub const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 2);
pub const TUN_PEER: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
pub const TUN_PREFIX: u8 = 24;
/// Unique-local IPv6 on the TUN when the profile enables IPv6.
pub const TUN_ADDR_V6: Ipv6Addr = Ipv6Addr::new(0xfd72, 0x6f63, 0x6b65, 0, 0, 0, 0, 2);
pub const TUN_PREFIX_V6: u8 = 64;
pub const DEFAULT_MTU: u16 = 1280;
/// Local TCP intercept target used by nftables `redirect` (kernel TCP, SSH forward).
pub const TRANSPROXY_PORT: u16 = 13450;
/// Local UDP/53 intercept target; queries are answered via DNS-over-TCP or UDPGW.
pub const DNS_PROXY_PORT: u16 = 13453;
/// Local UDP intercept for general datagrams when UDPGW is connected.
pub const UDP_PROXY_PORT: u16 = 13451;
