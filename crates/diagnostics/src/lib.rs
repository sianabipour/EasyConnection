//! Leak, DNS, TCP, and traceroute diagnostics for a live tunnel session.

use rt_tun::{NFT_TABLE, TUN_NAME};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct DiagError(pub String);

pub type Result<T> = std::result::Result<T, DiagError>;

#[derive(Debug, Clone, Serialize)]
pub struct LeakReport {
    pub tun_present: bool,
    pub nft_table_present: bool,
    pub resolved_link_dns: Vec<String>,
    pub using_tunnel_dns: bool,
    pub ipv6_enabled_on_tun: bool,
    pub ipv6_global_addrs: Vec<String>,
    pub udp_redirected: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub kind: String,
    pub target: String,
    pub latency_ms: Option<u64>,
    pub output: String,
    pub note: Option<String>,
}

pub async fn leak_report(ipv6_expected: bool) -> LeakReport {
    let tun_present = std::path::Path::new(&format!("/sys/class/net/{TUN_NAME}")).exists();
    let nft_table_present = nft_table_exists().await;
    let link = TUN_NAME;
    let resolved_link_dns = resolvectl_dns(link).await;
    let using_tunnel_dns = !resolved_link_dns.is_empty();
    let ipv6_enabled_on_tun = tun_has_ula(link).await;
    let ipv6_global_addrs = global_ipv6_addrs().await;
    let udp_redirected = nft_has_udp_redirect().await;

    let mut notes = Vec::new();
    if !tun_present {
        notes.push(format!(
            "No {TUN_NAME} — connect a full-tunnel profile first."
        ));
    }
    if tun_present && !using_tunnel_dns {
        notes.push(format!(
            "systemd-resolved has no DNS on {link} — queries may use the LAN resolver."
        ));
    }
    if using_tunnel_dns {
        notes.push(format!(
            "Link DNS is set on {link}; UDP/53 is intercepted (DNS-over-TCP and/or UDPGW)."
        ));
    }
    if tun_present && udp_redirected {
        notes.push(
            "General UDP is redirected to the UDPGW intercept. Compatibility depends on the remote badvpn-udpgw."
                .into(),
        );
    } else if tun_present {
        notes.push(
            "General UDP is rejected (no UDPGW intercept). Apps should fall back to TCP.".into(),
        );
    }
    if !ipv6_expected && !ipv6_global_addrs.is_empty() {
        notes.push(
            "This profile has IPv6 off. Public IPv6 should be rejected by nftables so apps fall back to IPv4."
                .into(),
        );
    }
    if ipv6_expected && tun_present && !ipv6_enabled_on_tun {
        notes.push("IPv6 is enabled on the profile but the TUN has no ULA address.".into());
    }
    if !nft_table_present && tun_present {
        notes.push(format!("TUN is up but table inet {NFT_TABLE} is missing."));
    }
    if tun_present && notes.is_empty() {
        notes.push("No obvious DNS/IPv6 leak from local checks.".into());
    }

    LeakReport {
        tun_present,
        nft_table_present,
        resolved_link_dns,
        using_tunnel_dns,
        ipv6_enabled_on_tun,
        ipv6_global_addrs,
        udp_redirected,
        notes,
    }
}

/// ICMP ping is not available on the TCP intercept path. This is a TCP connect probe.
pub async fn tcp_connect_probe(host: &str, port: u16) -> ProbeResult {
    let target = format!("{host}:{port}");
    let start = std::time::Instant::now();
    let note = Some(
        "ICMP ping is not carried on the TCP intercept path. This is a TCP connect timing probe."
            .into(),
    );
    match tokio::time::timeout(
        std::time::Duration::from_secs(8),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(_stream)) => ProbeResult {
            ok: true,
            kind: "tcp".into(),
            target,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            output: "connected".into(),
            note,
        },
        Ok(Err(e)) => ProbeResult {
            ok: false,
            kind: "tcp".into(),
            target,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            output: e.to_string(),
            note,
        },
        Err(_) => ProbeResult {
            ok: false,
            kind: "tcp".into(),
            target,
            latency_ms: None,
            output: "timed out".into(),
            note,
        },
    }
}

pub async fn traceroute_tcp(host: &str) -> ProbeResult {
    let note = Some(
        "Uses traceroute -T (TCP SYN) when installed. ICMP traceroute usually fails on this path."
            .into(),
    );
    let bin = ["traceroute", "tracepath"]
        .into_iter()
        .find(|b| which(b))
        .unwrap_or("traceroute");
    let mut cmd = tokio::process::Command::new(bin);
    if bin == "traceroute" {
        cmd.args(["-n", "-T", "-w", "1", "-q", "1", "-m", "12", host]);
    } else {
        cmd.args(["-n", host]);
    }
    match tokio::time::timeout(std::time::Duration::from_secs(20), cmd.output()).await {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let output = if stdout.is_empty() { stderr } else { stdout };
            ProbeResult {
                ok: out.status.success() || !output.is_empty(),
                kind: "traceroute".into(),
                target: host.into(),
                latency_ms: None,
                output: if output.is_empty() {
                    format!("{bin} produced no output (install traceroute?)")
                } else {
                    output
                },
                note,
            }
        }
        Ok(Err(e)) => ProbeResult {
            ok: false,
            kind: "traceroute".into(),
            target: host.into(),
            latency_ms: None,
            output: format!("failed to spawn {bin}: {e}"),
            note,
        },
        Err(_) => ProbeResult {
            ok: false,
            kind: "traceroute".into(),
            target: host.into(),
            latency_ms: None,
            output: "timed out".into(),
            note,
        },
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

async fn nft_has_udp_redirect() -> bool {
    let out = tokio::process::Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .output()
        .await;
    matches!(out, Ok(o) if o.status.success() && String::from_utf8_lossy(&o.stdout).contains(":13451"))
}

async fn nft_table_exists() -> bool {
    let out = tokio::process::Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .output()
        .await;
    matches!(out, Ok(o) if o.status.success())
}

async fn resolvectl_dns(link: &str) -> Vec<String> {
    let Ok(out) = tokio::process::Command::new("resolvectl")
        .args(["dns", link])
        .output()
        .await
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .filter(|t| t.parse::<std::net::IpAddr>().is_ok())
        .map(|s| s.to_string())
        .collect()
}

async fn tun_has_ula(link: &str) -> bool {
    let Ok(out) = tokio::process::Command::new("ip")
        .args(["-6", "-o", "addr", "show", "dev", link])
        .output()
        .await
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).contains("fd72:6f63:6b65")
}

async fn global_ipv6_addrs() -> Vec<String> {
    let Ok(out) = tokio::process::Command::new("ip")
        .args(["-6", "-o", "addr", "show", "scope", "global"])
        .output()
        .await
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _if = parts.next()?;
            let _ = parts.next()?;
            parts.next().map(|s| s.to_string())
        })
        .collect()
}
