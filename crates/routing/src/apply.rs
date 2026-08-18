use std::net::IpAddr;
use std::process::Stdio;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, warn};

use crate::cidrs::{private_cidrs, split_default_v4, split_default_v6};
use crate::{Result, RoutingError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefaultRoute {
    pub gateway: Option<IpAddr>,
    pub dev: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddedRoute {
    pub dest: String,
    pub via: Option<IpAddr>,
    pub dev: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteJournal {
    pub added: Vec<AddedRoute>,
    pub original_default: Option<DefaultRoute>,
}

pub fn ip_bin() -> &'static str {
    for p in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"] {
        if std::path::Path::new(p).exists() {
            return p;
        }
    }
    "ip"
}

pub async fn run_ip(args: &[&str]) -> Result<String> {
    debug!(bin = ip_bin(), ?args, "ip");
    let out = Command::new(ip_bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        return Err(RoutingError::Other(format!(
            "ip {} failed: {stderr} {stdout}",
            args.join(" ")
        )));
    }
    Ok(stdout)
}

pub async fn run_ip_ignore_exists(args: &[&str]) -> Result<bool> {
    match run_ip(args).await {
        Ok(_) => Ok(true),
        Err(RoutingError::Other(msg)) if msg.contains("File exists") || msg.contains("exists") => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, Deserialize)]
struct IpRouteJson {
    #[allow(dead_code)]
    dst: Option<String>,
    gateway: Option<String>,
    dev: Option<String>,
    metric: Option<u32>,
}

pub async fn detect_default_route() -> Result<DefaultRoute> {
    if let Ok(raw) = run_ip(&["-json", "route", "show", "default"]).await {
        if let Ok(rows) = serde_json::from_str::<Vec<IpRouteJson>>(&raw) {
            let mut best: Option<(u32, DefaultRoute)> = None;
            for row in rows {
                let Some(dev) = row.dev else { continue };
                let metric = row.metric.unwrap_or(0);
                let gateway = row
                    .gateway
                    .as_deref()
                    .and_then(|g| g.parse::<IpAddr>().ok());
                let cand = DefaultRoute {
                    gateway,
                    dev,
                    metric: row.metric,
                };
                match &best {
                    None => best = Some((metric, cand)),
                    Some((m, _)) if metric < *m => best = Some((metric, cand)),
                    _ => {}
                }
            }
            if let Some((_, r)) = best {
                return Ok(r);
            }
        }
    }

    let text = run_ip(&["route", "show", "default"]).await?;
    parse_default_route_text(&text).ok_or(RoutingError::NoDefaultRoute)
}

pub fn parse_default_route_text(text: &str) -> Option<DefaultRoute> {
    let line = text.lines().next()?.trim();
    if !line.starts_with("default") {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let mut gateway = None;
    let mut dev = None;
    let mut metric = None;
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "via" if i + 1 < parts.len() => {
                gateway = parts[i + 1].parse().ok();
                i += 2;
            }
            "dev" if i + 1 < parts.len() => {
                dev = Some(parts[i + 1].to_string());
                i += 2;
            }
            "metric" if i + 1 < parts.len() => {
                metric = parts[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }
    Some(DefaultRoute {
        gateway,
        dev: dev?,
        metric,
    })
}

pub struct RoutePlan {
    pub journal: RouteJournal,
}

pub fn build_plan(
    default: &DefaultRoute,
    tun_name: &str,
    server_ips: &[IpAddr],
    bypass_private: bool,
    extra_bypass: &[IpNet],
    ipv6: bool,
) -> RoutePlan {
    let mut added = Vec::new();

    for ip in server_ips {
        added.push(AddedRoute {
            dest: ip.to_string(),
            via: default.gateway,
            dev: default.dev.clone(),
        });
    }

    if bypass_private {
        for cidr in private_cidrs()
            .into_iter()
            .chain(extra_bypass.iter().copied())
        {
            if cidr.addr().is_ipv4() {
                added.push(AddedRoute {
                    dest: cidr.to_string(),
                    via: default.gateway,
                    dev: default.dev.clone(),
                });
            } else if ipv6 {
                added.push(AddedRoute {
                    dest: cidr.to_string(),
                    via: default.gateway.filter(|g| g.is_ipv6()),
                    dev: default.dev.clone(),
                });
            }
        }
    }

    for net in split_default_v4() {
        added.push(AddedRoute {
            dest: net.to_string(),
            via: None,
            dev: tun_name.to_string(),
        });
    }
    if ipv6 {
        for net in split_default_v6() {
            added.push(AddedRoute {
                dest: net.to_string(),
                via: None,
                dev: tun_name.to_string(),
            });
        }
    }

    RoutePlan {
        journal: RouteJournal {
            added,
            original_default: Some(default.clone()),
        },
    }
}

pub async fn apply_journal(journal: &RouteJournal) -> Result<Vec<AddedRoute>> {
    let mut actually_added = Vec::new();
    for r in &journal.added {
        let mut args = vec!["route", "add", r.dest.as_str()];
        let via;
        if let Some(gw) = r.via {
            via = gw.to_string();
            args.push("via");
            args.push(via.as_str());
        }
        args.push("dev");
        args.push(r.dev.as_str());
        match run_ip_ignore_exists(&args).await {
            Ok(true) => actually_added.push(r.clone()),
            Ok(false) => {
                debug!(dest = %r.dest, "route already present; not tracking for delete");
            }
            Err(e) => {
                warn!(error = %e, dest = %r.dest, "failed to add route; rolling back");
                let _ = restore_added(&actually_added).await;
                return Err(e);
            }
        }
    }
    Ok(actually_added)
}

pub async fn restore_added(added: &[AddedRoute]) -> Result<()> {
    for r in added.iter().rev() {
        let mut args = vec!["route", "del", r.dest.as_str()];
        let via;
        if let Some(gw) = r.via {
            via = gw.to_string();
            args.push("via");
            args.push(via.as_str());
        }
        args.push("dev");
        args.push(r.dev.as_str());
        if let Err(e) = run_ip(&args).await {
            warn!(error = %e, dest = %r.dest, "route delete failed (continuing)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_classic_default_line() {
        let r =
            parse_default_route_text("default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600")
                .unwrap();
        assert_eq!(r.dev, "wlp2s0");
        assert_eq!(r.gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(r.metric, Some(600));
    }

    #[test]
    fn plan_protects_server_and_splits_default() {
        let def = DefaultRoute {
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dev: "eth0".into(),
            metric: Some(100),
        };
        let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let plan = build_plan(&def, "easy0", &[server], true, &[], false);
        let dests: Vec<_> = plan.journal.added.iter().map(|r| r.dest.as_str()).collect();
        assert!(dests.contains(&"203.0.113.10"));
        assert!(dests.contains(&"0.0.0.0/1"));
        assert!(dests.contains(&"128.0.0.0/1"));
        assert!(dests.contains(&"10.0.0.0/8"));
        assert!(!dests.iter().any(|d| d.contains("::/1")));
    }
}
