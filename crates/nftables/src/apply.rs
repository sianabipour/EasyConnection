use std::net::IpAddr;
use std::process::Stdio;

use ipnet::IpNet;
use tokio::process::Command;
use tracing::{debug, warn};

use rt_tun::{NFT_TABLE, TUN_NAME};

use crate::{NftError, Result};

pub fn nft_bin() -> &'static str {
    for p in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"] {
        if std::path::Path::new(p).exists() {
            return p;
        }
    }
    "nft"
}

/// Isolated `table inet easy`.
/// TCP (and UDP/53) from this machine are redirected to local intercept ports.
/// Only parsed `IpAddr`/`IpNet` values and numeric ports are interpolated.
pub fn render_table(
    server_ips: &[IpAddr],
    bypass: &[IpNet],
    kill_switch: bool,
    transproxy_port: u16,
    dns_port: u16,
    ipv6: bool,
    udp_port: u16,
) -> String {
    let mut nat = String::new();
    nat.push_str("    oifname \"lo\" return\n");
    nat.push_str(&format!("    oifname \"{TUN_NAME}\" return\n"));
    nat.push_str("    ip daddr 127.0.0.0/8 return\n");
    nat.push_str("    ip6 daddr ::1 return\n");
    for ip in server_ips {
        match ip {
            IpAddr::V4(v) => nat.push_str(&format!("    ip daddr {v} return\n")),
            IpAddr::V6(v) => nat.push_str(&format!("    ip6 daddr {v} return\n")),
        }
    }
    for net in bypass {
        match net.addr() {
            IpAddr::V4(_) => nat.push_str(&format!("    ip daddr {net} return\n")),
            IpAddr::V6(_) => nat.push_str(&format!("    ip6 daddr {net} return\n")),
        }
    }
    if ipv6 {
        nat.push_str(&format!(
            "    meta l4proto udp udp dport 53 redirect to :{dns_port}\n"
        ));
        nat.push_str(&format!(
            "    meta l4proto tcp redirect to :{transproxy_port}\n"
        ));
        if udp_port != 0 {
            nat.push_str(&format!("    meta l4proto udp redirect to :{udp_port}\n"));
        }
    } else {
        // IPv4-only intercept. Dual-stack `meta l4proto tcp redirect` sends IPv6
        // to [::1]:port, where the engine does not listen — browsers/curl then fail.
        nat.push_str(&format!(
            "    ip protocol udp udp dport 53 redirect to :{dns_port}\n"
        ));
        nat.push_str(&format!(
            "    ip protocol tcp redirect to :{transproxy_port}\n"
        ));
        if udp_port != 0 {
            nat.push_str(&format!("    ip protocol udp redirect to :{udp_port}\n"));
        }
    }

    let mut filter = String::new();
    filter.push_str("    ct state established,related accept\n");
    filter.push_str("    oifname \"lo\" accept\n");
    filter.push_str(&format!("    oifname \"{TUN_NAME}\" accept\n"));
    filter.push_str("    ip daddr 127.0.0.0/8 accept\n");
    filter.push_str("    ip6 daddr ::1 accept\n");
    for ip in server_ips {
        match ip {
            IpAddr::V4(v) => filter.push_str(&format!("    ip daddr {v} accept\n")),
            IpAddr::V6(v) => filter.push_str(&format!("    ip6 daddr {v} accept\n")),
        }
    }
    for net in bypass {
        match net.addr() {
            IpAddr::V4(_) => filter.push_str(&format!("    ip daddr {net} accept\n")),
            IpAddr::V6(_) => filter.push_str(&format!("    ip6 daddr {net} accept\n")),
        }
    }
    if !ipv6 {
        filter.push_str("    meta nfproto ipv6 reject with icmpx type admin-prohibited\n");
    }
    if udp_port == 0 {
        // QUIC/HTTP3 and other UDP skip the TCP intercept. Reject so apps fall back to TCP.
        filter.push_str("    meta l4proto udp reject with icmpx type admin-prohibited\n");
    }
    if kill_switch {
        filter.push_str("    reject with icmpx type admin-prohibited\n");
    }

    format!(
        "table inet {NFT_TABLE} {{\n\
         \n  chain output_nat {{\n    type nat hook output priority -100; policy accept;\n{nat}  }}\n\
         \n  chain output_filter {{\n    type filter hook output priority 0; policy accept;\n{filter}  }}\n\
         }}\n"
    )
}

pub async fn flush_table() -> Result<()> {
    flush_named(NFT_TABLE).await
}

async fn flush_named(table: &str) -> Result<()> {
    let out = Command::new(nft_bin())
        .args(["delete", "table", "inet", table])
        .stdin(Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.contains("No such file") && !err.contains("does not exist") {
            debug!(error = %err.trim(), table, "nft delete table (ignored if missing)");
        }
    }
    Ok(())
}

pub async fn apply_table(script: &str) -> Result<()> {
    flush_table().await?;
    debug!(bytes = script.len(), "applying nftables table");
    let mut child = Command::new(nft_bin())
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(script.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        return Err(NftError::Other(format!(
            "nft apply failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

pub async fn restore() -> Result<()> {
    if let Err(e) = flush_table().await {
        warn!(error = %e, "nft flush failed");
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn script_contains_owned_table_redirect_and_server() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let script = render_table(&[ip], &[], true, 13450, 13453, false, 0);
        assert!(script.contains("table inet easy"));
        assert!(script.contains("203.0.113.9"));
        assert!(script.contains("easy0"));
        assert!(script.contains("ip protocol tcp redirect to :13450"));
        assert!(script.contains("udp dport 53"));
        assert!(script.contains("reject"));
        assert!(!script.contains("bash"));
    }

    #[test]
    fn ipv4_only_does_not_redirect_ipv6_tcp() {
        let script = render_table(&[], &[], false, 13450, 13453, false, 0);
        assert!(script.contains("ip protocol tcp redirect"));
        assert!(!script.contains("meta l4proto tcp redirect"));
        assert!(script.contains("meta nfproto ipv6 reject"));
        assert!(script.contains("meta l4proto udp reject"));
    }

    #[test]
    fn ipv6_enabled_uses_dual_stack_redirect() {
        let script = render_table(&[], &[], false, 13450, 13453, true, 0);
        assert!(script.contains("meta l4proto tcp redirect"));
        assert!(!script.contains("meta nfproto ipv6 reject"));
    }

    #[test]
    fn kill_switch_off_has_no_generic_reject() {
        let script = render_table(&[], &[], false, 13450, 13453, true, 0);
        assert!(script.contains("meta l4proto udp reject"));
        assert!(!script.contains("reject with icmpx type admin-prohibited\n    reject"));
    }

    #[test]
    fn udpgw_redirects_leftover_udp() {
        let script = render_table(&[], &[], false, 13450, 13453, false, 13451);
        assert!(script.contains("ip protocol udp redirect to :13451"));
        assert!(!script.contains("meta l4proto udp reject"));
    }
}
