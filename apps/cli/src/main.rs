use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use rt_config::{
    AuthMethod, ConnectionConfig, HostKeyPolicy, ProtocolSettings, TlsFingerprintProfile, Transport,
};
use rt_core::{init_logging, AppController};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "easy", about = "Easy Connection Linux CLI")]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Debug)]
struct SharedProfileArgs {
    #[arg(long, default_value_t = 1080)]
    socks_port: u16,
    #[arg(long, default_value_t = 8080)]
    http_port: u16,
    /// proxy_only | full_tunnel | split_tunnel
    #[arg(long, default_value = "proxy_only")]
    routing_mode: String,
    #[arg(long, default_value_t = false)]
    kill_switch: bool,
    #[arg(long, default_value_t = true)]
    bypass_private: bool,
    #[arg(long, default_value_t = false)]
    ipv6: bool,
    /// system | tunnel | custom | remote
    #[arg(long, default_value = "system")]
    dns_mode: String,
    /// Comma-separated DNS IPs (used with --dns-mode custom/tunnel)
    #[arg(long)]
    dns_servers: Option<String>,
    /// direct | tls | websocket | wss | http_upgrade
    #[arg(long, default_value = "direct")]
    transport: String,
    #[arg(long)]
    sni: Option<String>,
    /// Comma-separated ALPN (empty keeps SSH-over-TLS without h2)
    #[arg(long)]
    alpn: Option<String>,
    /// default | chrome | firefox | safari | custom (ALPN hint only, not JA3)
    #[arg(long, default_value = "default")]
    fingerprint: String,
    /// Disable TLS certificate verification (not recommended)
    #[arg(long, default_value_t = false)]
    insecure: bool,
    /// WebSocket / HTTP Upgrade path
    #[arg(long)]
    ws_path: Option<String>,
    /// Host header for WS / HTTP Upgrade
    #[arg(long)]
    ws_host: Option<String>,
    /// 127.0.0.1 (default) or 0.0.0.0 / LAN to share the local proxy
    #[arg(long, default_value = "127.0.0.1")]
    listen: String,
    /// Extra CIDR to skip nft redirect (repeatable)
    #[arg(long = "split-cidr")]
    split_cidr: Vec<String>,
    /// Domain resolved at connect time and skipped in nft redirect (repeatable)
    #[arg(long = "split-domain")]
    split_domain: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List saved profiles
    List,
    /// Add an SSH profile (password auth)
    AddSsh {
        #[arg(long)]
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[command(flatten)]
        shared: SharedProfileArgs,
        /// Enable BadVPN UDPGW (remote must run badvpn-udpgw)
        #[arg(long, default_value_t = false)]
        udpgw: bool,
        #[arg(long, default_value = "127.0.0.1")]
        udpgw_host: String,
        #[arg(long, default_value_t = 7300)]
        udpgw_port: u16,
        /// Send intercepted DNS via UDPGW (falls back to DNS-over-TCP)
        #[arg(long, default_value_t = false)]
        udpgw_dns: bool,
        /// Use strict known_hosts (default is trust-on-first-use)
        #[arg(long, default_value_t = false)]
        strict_host_key: bool,
    },
    /// Add a Shadowsocks AEAD profile (aes-128-gcm / aes-256-gcm)
    AddSs {
        #[arg(long)]
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 8388)]
        port: u16,
        #[arg(long, default_value = "aes-256-gcm")]
        method: String,
        #[arg(long)]
        password: String,
        #[command(flatten)]
        shared: SharedProfileArgs,
    },
    /// Add a VLESS profile (encryption=none; Vision/XTLS rejected)
    AddVless {
        #[arg(long)]
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long)]
        uuid: String,
        #[arg(long, default_value = "none")]
        encryption: String,
        #[arg(long, default_value = "")]
        flow: String,
        #[command(flatten)]
        shared: SharedProfileArgs,
    },
    /// Connect a profile and keep proxies running until Ctrl-C
    Connect { id: Uuid },
    /// Show connection snapshot JSON
    Status,
    /// DNS / IPv6 leak report (needs a live tunnel for full results)
    DnsStatus,
    /// Export a profile (secrets stripped)
    Export { id: Uuid },
    /// Delete a profile
    Delete { id: Uuid },
    /// Import JSON export or ss:// / vless:// / ssh:// URI (file path or text)
    Import { source: String },
    /// TCP connect probe (ICMP ping is not available on the TCP intercept path)
    Ping {
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
    },
    /// TCP traceroute (needs traceroute -T)
    Traceroute { host: String },
    /// Remove leftover TUN/nftables/routes via the privileged helper
    EmergencyRestore,
}

fn parse_transport(s: &str) -> Result<Transport> {
    match s.to_ascii_lowercase().as_str() {
        "direct" => Ok(Transport::Direct),
        "tls" => Ok(Transport::Tls),
        "websocket" | "ws" => Ok(Transport::WebSocket),
        "wss" => Ok(Transport::Wss),
        "http_upgrade" | "http-upgrade" | "upgrade" => Ok(Transport::HttpUpgrade),
        other => anyhow::bail!(
            "unknown --transport {other}. Use direct, tls, websocket, wss, or http_upgrade"
        ),
    }
}

fn parse_fingerprint(s: &str) -> Result<TlsFingerprintProfile> {
    match s.to_ascii_lowercase().as_str() {
        "default" => Ok(TlsFingerprintProfile::Default),
        "chrome" => Ok(TlsFingerprintProfile::Chrome),
        "firefox" => Ok(TlsFingerprintProfile::Firefox),
        "safari" => Ok(TlsFingerprintProfile::Safari),
        "custom" => Ok(TlsFingerprintProfile::Custom),
        other => anyhow::bail!(
            "unknown --fingerprint {other}. Use default, chrome, firefox, safari, or custom"
        ),
    }
}

fn apply_shared(cfg: &mut ConnectionConfig, shared: &SharedProfileArgs) -> Result<()> {
    cfg.proxy.socks_port = shared.socks_port;
    cfg.proxy.http_proxy_port = shared.http_port;
    cfg.kill_switch = shared.kill_switch;
    cfg.bypass_private_networks = shared.bypass_private;
    cfg.ipv6 = shared.ipv6;
    cfg.dns.mode = match shared.dns_mode.as_str() {
        "system" => rt_config::DnsMode::System,
        "tunnel" => rt_config::DnsMode::Tunnel,
        "custom" => rt_config::DnsMode::Custom,
        "remote" => rt_config::DnsMode::Remote,
        other => anyhow::bail!("unknown --dns-mode {other}"),
    };
    if let Some(servers) = &shared.dns_servers {
        cfg.dns.servers = servers
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
    }
    cfg.routing_mode = match shared.routing_mode.as_str() {
        "proxy_only" | "proxy" => rt_config::RoutingMode::ProxyOnly,
        "full_tunnel" | "vpn" | "full" => rt_config::RoutingMode::FullTunnel,
        "split_tunnel" | "split" => rt_config::RoutingMode::SplitTunnel,
        other => anyhow::bail!("unknown --routing-mode {other}"),
    };
    if matches!(
        cfg.routing_mode,
        rt_config::RoutingMode::FullTunnel | rt_config::RoutingMode::SplitTunnel
    ) && cfg.dns.mode == rt_config::DnsMode::System
    {
        cfg.dns.mode = rt_config::DnsMode::Tunnel;
    }
    cfg.transport = parse_transport(&shared.transport)?;
    cfg.tls.sni = shared
        .sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    cfg.tls.alpn = shared
        .alpn
        .as_deref()
        .map(|s| {
            s.split([',', ' '])
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string())
                .collect()
        })
        .unwrap_or_default();
    cfg.tls.fingerprint = parse_fingerprint(&shared.fingerprint)?;
    cfg.tls.verify = !shared.insecure;
    cfg.tls.path = shared
        .ws_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    cfg.tls.host = shared
        .ws_host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    cfg.proxy.listen = if shared.listen.eq_ignore_ascii_case("lan") {
        "0.0.0.0".into()
    } else {
        shared.listen.clone()
    };
    cfg.split_bypass_cidrs = shared.split_cidr.clone();
    cfg.split_bypass_domains = shared.split_domain.clone();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging("info");
    let cli = Cli::parse();
    let controller = if let Some(dir) = &cli.data_dir {
        std::fs::create_dir_all(dir)?;
        AppController::bootstrap_at(dir.join("state.db"), dir.join("secrets.bin"))?
    } else {
        AppController::bootstrap()?
    };

    match cli.command {
        Commands::List => {
            for p in controller.list_profiles()? {
                println!(
                    "{}  {}  {}+{}://{}:{}  socks={} http={}",
                    p.id,
                    p.name,
                    format!("{:?}", p.protocol).to_lowercase(),
                    format!("{:?}", p.transport).to_lowercase(),
                    p.host,
                    p.port,
                    p.proxy.socks_port,
                    p.proxy.http_proxy_port
                );
            }
        }
        Commands::AddSsh {
            name,
            host,
            port,
            username,
            password,
            shared,
            udpgw,
            udpgw_host,
            udpgw_port,
            udpgw_dns,
            strict_host_key,
        } => {
            let mut cfg = ConnectionConfig::new_ssh(name, host, port);
            cfg.username = Some(username);
            apply_shared(&mut cfg, &shared)?;
            cfg.udpgw.enabled = udpgw;
            cfg.udpgw.host = udpgw_host;
            cfg.udpgw.port = udpgw_port;
            cfg.udpgw.transparent_dns = udpgw_dns;
            let secret = controller.put_secret(&password)?;
            cfg.authentication = AuthMethod::Password {
                secret: Some(secret),
            };
            if let ProtocolSettings::Ssh {
                host_key_policy, ..
            } = &mut cfg.settings
            {
                *host_key_policy = if strict_host_key {
                    HostKeyPolicy::Strict
                } else {
                    HostKeyPolicy::Tofu
                };
            }
            let saved = controller.save_profile(cfg)?;
            println!("{}", saved.id);
        }
        Commands::AddSs {
            name,
            host,
            port,
            method,
            password,
            shared,
        } => {
            let mut cfg = ConnectionConfig::new_shadowsocks(name, host, port, method);
            apply_shared(&mut cfg, &shared)?;
            let secret = controller.put_secret(&password)?;
            cfg.authentication = AuthMethod::Password {
                secret: Some(secret),
            };
            let saved = controller.save_profile(cfg)?;
            println!("{}", saved.id);
        }
        Commands::AddVless {
            name,
            host,
            port,
            uuid,
            encryption,
            flow,
            shared,
        } => {
            let mut cfg = ConnectionConfig::new_vless(name, host, port, uuid);
            apply_shared(&mut cfg, &shared)?;
            if let ProtocolSettings::Vless {
                encryption: enc,
                flow: fl,
                host: vhost,
                path,
                ..
            } = &mut cfg.settings
            {
                *enc = encryption;
                *fl = flow;
                *vhost = cfg.tls.host.clone();
                *path = cfg.tls.path.clone();
            }
            let saved = controller.save_profile(cfg)?;
            println!("{}", saved.id);
        }
        Commands::Connect { id } => {
            let snap = controller
                .connect(id)
                .await
                .with_context(|| "connect failed")?;
            println!("{}", serde_json::to_string_pretty(&snap)?);
            println!("Press Ctrl-C to disconnect…");
            tokio::signal::ctrl_c().await?;
            let _ = controller.disconnect().await?;
        }
        Commands::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&controller.connection_snapshot())?
            );
        }
        Commands::DnsStatus => {
            println!(
                "{}",
                serde_json::to_string_pretty(&controller.leak_report().await)?
            );
        }
        Commands::Export { id } => {
            let doc = controller.export_profile(id)?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        Commands::Delete { id } => {
            controller.delete_profile(id)?;
            println!("deleted {id}");
        }
        Commands::Import { source } => {
            let text = if std::path::Path::new(&source).is_file() {
                std::fs::read_to_string(&source)?
            } else {
                source
            };
            let saved = controller.import_profile_text(&text)?;
            println!("{}", saved.id);
        }
        Commands::Ping { host, port } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&controller.tcp_probe(&host, port).await)?
            );
        }
        Commands::Traceroute { host } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&controller.traceroute(&host).await)?
            );
        }
        Commands::EmergencyRestore => {
            let msg = rt_tun::client::HelperClient::connect_default()
                .await?
                .emergency_restore()
                .await?;
            println!("{msg}");
        }
    }

    Ok(())
}
