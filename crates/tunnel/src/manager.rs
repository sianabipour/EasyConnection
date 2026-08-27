use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::RwLock;
use rt_config::{ConnectionConfig, DnsOverTcp, Protocol, RoutingMode, Transport};
use rt_secrets::SecretsStore;
use rt_shadowsocks::ShadowsocksConnector;
use rt_socks::{ProxyHandles, ProxyServer, Socks5Auth};
use rt_ssh::{SshConnectOptions, SshSession};
use rt_tls::{dial, DialRequest};
use rt_tun::ipc::ApplySpec;
use rt_tun::{
    HelperClient, TunIo, DEFAULT_MTU, DNS_PROXY_PORT, TRANSPROXY_PORT, TUN_ADDR, TUN_NAME,
    TUN_PREFIX, UDP_PROXY_PORT,
};
use rt_udpgw::UdpgwHandle;
use rt_vless::VlessConnector;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::state::{ConnectionPhase, ConnectionSnapshot, ConnectionState};
use crate::transproxy::{
    bind_udp_origdst, drain_tun, pump_udpgw_replies, run_dns_intercept, run_transproxy,
    run_udp_intercept,
};
use crate::{Result, TunnelError};

struct ActiveSession {
    ssh: Option<Arc<SshSession>>,
    proxies: ProxyHandles,
    helper: Option<HelperClient>,
    tun_stop: Option<CancellationToken>,
    tun_task: Option<tokio::task::JoinHandle<()>>,
}

pub struct ConnectionManager {
    secrets: Arc<SecretsStore>,
    snapshot: Arc<RwLock<ConnectionSnapshot>>,
    tx: watch::Sender<ConnectionSnapshot>,
    rx: watch::Receiver<ConnectionSnapshot>,
    active: tokio::sync::Mutex<Option<ActiveSession>>,
    known_hosts_path: Option<std::path::PathBuf>,
}

impl ConnectionManager {
    pub fn new(secrets: Arc<SecretsStore>) -> Self {
        Self::with_known_hosts(secrets, None)
    }

    pub fn with_known_hosts(
        secrets: Arc<SecretsStore>,
        known_hosts_path: Option<std::path::PathBuf>,
    ) -> Self {
        let snapshot = ConnectionSnapshot::default();
        let (tx, rx) = watch::channel(snapshot.clone());
        Self {
            secrets,
            snapshot: Arc::new(RwLock::new(snapshot)),
            tx,
            rx,
            active: tokio::sync::Mutex::new(None),
            known_hosts_path,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<ConnectionSnapshot> {
        self.rx.clone()
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.snapshot.read().clone()
    }

    fn publish(&self, next: ConnectionSnapshot) {
        *self.snapshot.write() = next.clone();
        let _ = self.tx.send(next);
    }

    fn set_phase(&self, state: ConnectionState, phase: ConnectionPhase) {
        let mut snap = self.snapshot();
        snap.state = state;
        snap.phase = phase;
        self.publish(snap);
    }

    pub async fn connect(&self, profile: ConnectionConfig) -> Result<ConnectionSnapshot> {
        {
            let guard = self.active.lock().await;
            if guard.is_some() {
                return Err(TunnelError::AlreadyConnected);
            }
        }

        if matches!(profile.protocol, Protocol::Socks) {
            return Err(TunnelError::UnsupportedProtocol(
                "inbound SOCKS profiles are not a tunnel protocol — use SSH, Shadowsocks, or VLESS"
                    .into(),
            ));
        }

        let wants_tun = !matches!(profile.routing_mode, RoutingMode::ProxyOnly);
        if profile.routing_mode == RoutingMode::SplitTunnel {
            warn!(
                "split tunnel domain/process rules are not in this phase; applying full-tunnel TCP with private-network bypass"
            );
        }

        let mut snap = ConnectionSnapshot {
            state: ConnectionState::Connecting,
            phase: ConnectionPhase::ResolvingServer,
            profile_id: Some(profile.id),
            profile_name: Some(profile.name.clone()),
            server_label: Some(format!("{}:{}", profile.host, profile.port)),
            ipv6: profile.ipv6,
            routing_mode: match profile.routing_mode {
                RoutingMode::ProxyOnly => "proxy_only".into(),
                RoutingMode::FullTunnel => "full_tunnel".into(),
                RoutingMode::SplitTunnel => "split_tunnel".into(),
            },
            dns_status: format!("{:?}", profile.dns.mode).to_lowercase(),
            udpgw_status: if profile.udpgw.enabled {
                "connecting".into()
            } else {
                "disabled".into()
            },
            kill_switch: profile.kill_switch,
            udp_note: if wants_tun {
                Some(
                    "TCP is intercepted. UDP needs a remote badvpn-udpgw (enable it on the profile)."
                        .into(),
                )
            } else {
                None
            },
            ..ConnectionSnapshot::default()
        };
        self.publish(snap.clone());

        self.set_phase(
            ConnectionState::Connecting,
            ConnectionPhase::EstablishingTcp,
        );

        self.set_phase(
            ConnectionState::Authenticating,
            ConnectionPhase::Authenticating,
        );

        let (ssh, upstream) = match open_upstream(
            &profile,
            self.secrets.as_ref(),
            self.known_hosts_path.clone(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let detail = e.to_string();
                error!(error = %detail, "upstream connect failed");
                snap.state = ConnectionState::Error;
                snap.phase = ConnectionPhase::Failed {
                    message: detail.clone(),
                };
                snap.last_error = Some(short_connect_error(&detail));
                snap.last_error_detail = Some(detail);
                self.publish(snap.clone());
                return Err(e);
            }
        };

        self.set_phase(
            ConnectionState::EstablishingTunnel,
            ConnectionPhase::EstablishingTunnel,
        );
        let auth = Socks5Auth::none();
        let listen = proxy_bind_addr(&profile.proxy.listen);
        if listen != "127.0.0.1" && listen != "::1" {
            warn!(
                listen,
                "proxy is listening off-loopback — anyone who can reach this address can use the tunnel"
            );
        }
        let proxies = match ProxyServer::start(
            listen,
            profile.proxy.socks_port,
            profile.proxy.http_proxy_port,
            Arc::clone(&upstream),
            auth,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                if let Some(s) = &ssh {
                    let _ = s.disconnect().await;
                }
                return Err(e.into());
            }
        };

        let mut helper = None;
        let mut tun_stop = None;
        let mut tun_task = None;
        let mut tun_name = None;
        let mut helper_ok = false;
        let mut dns_status = snap.dns_status.clone();
        let mut udpgw_status = snap.udpgw_status.clone();
        let mut udp_note = snap.udp_note.clone();
        let mut udpgw_ok = false;

        if wants_tun {
            self.set_phase(
                ConnectionState::EstablishingTunnel,
                ConnectionPhase::ConfiguringRoutes,
            );
            match start_full_tunnel(&profile, Arc::clone(&upstream)).await {
                Ok(tun) => {
                    helper_ok = true;
                    tun_name = Some(TUN_NAME.to_string());
                    dns_status = tun.dns_status;
                    udpgw_status = tun.udpgw_status;
                    udp_note = Some(tun.udp_note);
                    udpgw_ok = tun.udpgw_ok;
                    helper = Some(tun.helper);
                    tun_stop = Some(tun.stop.clone());
                    tun_task = Some(tun.task);
                }
                Err(e) => {
                    error!(error = %e, "full tunnel failed; rolling back");
                    proxies.stop().await;
                    if let Some(s) = &ssh {
                        let _ = s.disconnect().await;
                    }
                    let detail = e.to_string();
                    snap.state = ConnectionState::Error;
                    snap.phase = ConnectionPhase::Failed {
                        message: detail.clone(),
                    };
                    snap.last_error = Some("Failed to configure system-wide routing".into());
                    snap.last_error_detail = Some(full_tunnel_error(&detail));
                    self.publish(snap.clone());
                    return Err(e);
                }
            }
        }

        if !wants_tun && profile.udpgw.enabled && ssh.is_some() {
            let stop = CancellationToken::new();
            let started = start_udpgw_client(&profile, upstream.as_ref(), &stop).await;
            udpgw_status = started.status;
            udpgw_ok = started.handle.is_some();
            udp_note = Some(
                "Proxy-only does not intercept system UDP. UDPGW is connected for diagnostics only; use VPN mode for transparent UDP."
                    .into(),
            );
            tun_stop = Some(stop);
        }

        let now = chrono::Utc::now();
        snap.state = if profile.udpgw.enabled && !udpgw_ok {
            ConnectionState::Degraded
        } else {
            ConnectionState::Connected
        };
        snap.phase = ConnectionPhase::Ready;
        snap.socks_endpoint = Some(format!("socks5://{}", proxies.socks_endpoint()));
        snap.http_endpoint = Some(format!("http://{}", proxies.http_endpoint()));
        snap.connected_since = Some(now);
        snap.last_error = None;
        snap.last_error_detail = None;
        snap.tun_name = tun_name;
        snap.helper_ok = helper_ok;
        snap.dns_status = dns_status;
        snap.udpgw_status = udpgw_status;
        snap.kill_switch = profile.kill_switch;
        snap.udp_note = udp_note;
        self.publish(snap.clone());

        info!(
            profile = %profile.name,
            socks = %proxies.socks_endpoint(),
            http = %proxies.http_endpoint(),
            vpn = wants_tun,
            "tunnel ready"
        );

        *self.active.lock().await = Some(ActiveSession {
            ssh,
            proxies,
            helper,
            tun_stop,
            tun_task,
        });

        Ok(snap)
    }

    pub async fn disconnect(&self) -> Result<ConnectionSnapshot> {
        self.set_phase(ConnectionState::Disconnecting, ConnectionPhase::Idle);

        let active = self.active.lock().await.take();
        if let Some(session) = active {
            if let Some(stop) = session.tun_stop {
                stop.cancel();
            }
            if let Some(task) = session.tun_task {
                task.abort();
            }
            if let Some(helper) = session.helper {
                if let Err(e) = helper.teardown().await {
                    warn!(error = %e, "helper teardown reported an error");
                }
            }
            session.proxies.stop().await;
            if let Some(ssh) = session.ssh {
                if let Err(e) = ssh.disconnect().await {
                    warn!(error = %e, "SSH disconnect reported error");
                }
            }
        }

        let snap = ConnectionSnapshot::default();
        self.publish(snap.clone());
        info!("disconnected");
        Ok(snap)
    }
}

async fn open_upstream(
    profile: &ConnectionConfig,
    secrets: &SecretsStore,
    known_hosts: Option<std::path::PathBuf>,
) -> Result<(
    Option<Arc<SshSession>>,
    Arc<dyn rt_socks::UpstreamConnector>,
)> {
    match profile.protocol {
        Protocol::Ssh => {
            let mut opts = SshConnectOptions::from_config(profile)?;
            if opts.known_hosts_path.is_none() {
                opts.known_hosts_path = known_hosts;
            }
            let ssh = if profile.transport == Transport::Direct {
                SshSession::connect(opts, secrets).await?
            } else {
                let req = DialRequest::from_profile(
                    &profile.host,
                    profile.port,
                    profile.transport,
                    profile.tls.clone(),
                );
                let stream = dial(&req)
                    .await
                    .map_err(|e| TunnelError::Other(format!("SSH transport: {e}")))?;
                SshSession::connect_over_transport(opts, secrets, stream).await?
            };
            let ssh = Arc::new(ssh);
            let upstream = Arc::new(ssh.upstream());
            Ok((Some(ssh), upstream))
        }
        Protocol::Shadowsocks => {
            let c = ShadowsocksConnector::from_profile(profile, secrets)
                .map_err(|e| TunnelError::Other(e.to_string()))?;
            Ok((None, Arc::new(c)))
        }
        Protocol::Vless => {
            let c = VlessConnector::from_profile(profile)
                .map_err(|e| TunnelError::Other(e.to_string()))?;
            Ok((None, Arc::new(c)))
        }
        Protocol::Socks => Err(TunnelError::UnsupportedProtocol(
            "SOCKS is a local listener, not a remote protocol".into(),
        )),
    }
}

fn short_connect_error(detail: &str) -> String {
    detail.lines().next().unwrap_or("connect failed").into()
}

fn proxy_bind_addr(listen: &str) -> &str {
    match listen {
        "" | "127.0.0.1" | "localhost" => "127.0.0.1",
        "LAN" | "lan" => "0.0.0.0",
        other => other,
    }
}

async fn split_bypass_nets(profile: &ConnectionConfig) -> Vec<ipnet::IpNet> {
    let mut out = Vec::new();
    for cidr in &profile.split_bypass_cidrs {
        match cidr.parse::<ipnet::IpNet>() {
            Ok(n) => out.push(n),
            Err(e) => warn!(cidr, error = %e, "skipping invalid split-bypass CIDR"),
        }
    }
    for domain in &profile.split_bypass_domains {
        let host = domain.trim().trim_end_matches('.');
        if host.is_empty() {
            continue;
        }
        match tokio::net::lookup_host((host, 0)).await {
            Ok(addrs) => {
                for addr in addrs {
                    let net = match addr.ip() {
                        std::net::IpAddr::V4(v) => {
                            ipnet::IpNet::V4(ipnet::Ipv4Net::new(v, 32).expect("v4 /32"))
                        }
                        std::net::IpAddr::V6(v) => {
                            ipnet::IpNet::V6(ipnet::Ipv6Net::new(v, 128).expect("v6 /128"))
                        }
                    };
                    out.push(net);
                }
            }
            Err(e) => warn!(domain, error = %e, "could not resolve split-bypass domain"),
        }
    }
    out
}

struct StartedTun {
    helper: HelperClient,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    dns_status: String,
    udpgw_status: String,
    udp_note: String,
    udpgw_ok: bool,
}

struct StartedUdpgw {
    handle: Option<UdpgwHandle>,
    replies: mpsc::Receiver<(std::net::SocketAddr, Vec<u8>)>,
    status: String,
}

async fn start_udpgw_client(
    profile: &ConnectionConfig,
    upstream: &dyn rt_socks::UpstreamConnector,
    stop: &CancellationToken,
) -> StartedUdpgw {
    let (_tx, empty_rx) = mpsc::channel(1);
    if !profile.udpgw.enabled {
        return StartedUdpgw {
            handle: None,
            replies: empty_rx,
            status: "disabled".into(),
        };
    }
    let host = if profile.udpgw.host.is_empty() {
        rt_udpgw::DEFAULT_HOST
    } else {
        profile.udpgw.host.as_str()
    };
    let port = if profile.udpgw.port == 0 {
        rt_udpgw::DEFAULT_PORT
    } else {
        profile.udpgw.port
    };
    match upstream.connect(host, port).await {
        Ok(stream) => {
            let (tx, rx) = mpsc::channel(256);
            match rt_udpgw::run_udpgw(stream, tx, stop.clone()).await {
                Ok(handle) => {
                    info!(%host, port, "UDPGW client connected");
                    StartedUdpgw {
                        handle: Some(handle),
                        replies: rx,
                        status: format!("connected {host}:{port}"),
                    }
                }
                Err(e) => StartedUdpgw {
                    handle: None,
                    replies: rx,
                    status: format!("failed {host}:{port}: {e}"),
                },
            }
        }
        Err(e) => StartedUdpgw {
            handle: None,
            replies: empty_rx,
            status: format!(
                "unreachable {host}:{port} ({e}). Start badvpn-udpgw on the SSH host (often 127.0.0.1:7300)."
            ),
        },
    }
}

async fn start_full_tunnel(
    profile: &ConnectionConfig,
    upstream: Arc<dyn rt_socks::UpstreamConnector>,
) -> Result<StartedTun> {
    // Auto-elevate via polkit when the helper is not already running (systemd or prior session).
    rt_tun::ensure_helper_or_tun_error().await?;

    let server_ips = resolve_server_ips(&profile.host, profile.port).await?;
    let helper = HelperClient::connect_default().await?;
    let _ = helper.ping().await?;

    let tcp_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, TRANSPROXY_PORT)))
        .await
        .map_err(|e| {
            TunnelError::Other(format!(
                "cannot bind transparent TCP proxy 127.0.0.1:{TRANSPROXY_PORT}: {e}"
            ))
        })?;
    let dns_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, DNS_PROXY_PORT)))
        .await
        .map_err(|e| {
            TunnelError::Other(format!(
                "cannot bind DNS intercept 127.0.0.1:{DNS_PROXY_PORT}: {e}"
            ))
        })?;

    let policy = rt_dns::effective_policy(
        true,
        rt_dns::DnsPolicy::parse(&format!("{:?}", profile.dns.mode).to_lowercase()),
    );
    let dns_servers = rt_dns::resolve_servers(policy, &profile.dns.servers);

    let stop = CancellationToken::new();
    let udpgw = if profile.protocol == Protocol::Ssh {
        start_udpgw_client(profile, upstream.as_ref(), &stop).await
    } else {
        let (_tx, rx) = mpsc::channel(1);
        StartedUdpgw {
            handle: None,
            replies: rx,
            status: "n/a (UDPGW is SSH-only)".into(),
        }
    };
    let udpgw_ok = udpgw.handle.is_some();
    let dns_via_udpgw = profile.udpgw.transparent_dns && udpgw_ok;
    let udp_port = if udpgw_ok { UDP_PROXY_PORT } else { 0 };

    let dns_over_tcp = profile.dns.dns_over_tcp;
    let stop_tcp = stop.clone();
    let stop_dns = stop.clone();
    let up_tcp = Arc::clone(&upstream);
    let up_dns = Arc::clone(&upstream);
    let dns_for_intercept = dns_servers.clone();
    let dns_gw = if dns_via_udpgw {
        udpgw.handle.clone()
    } else {
        None
    };
    tokio::spawn(async move {
        if let Err(e) = run_transproxy(tcp_listener, up_tcp, stop_tcp).await {
            warn!(error = %e, "transproxy exited");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = run_dns_intercept(
            dns_sock,
            up_dns,
            dns_for_intercept,
            dns_gw,
            dns_over_tcp,
            stop_dns,
        )
        .await
        {
            warn!(error = %e, "DNS intercept exited");
        }
    });

    if profile.ipv6 {
        match TcpListener::bind(SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            TRANSPROXY_PORT,
        )))
        .await
        {
            Ok(v6) => {
                let stop_v6 = stop.clone();
                let up_v6 = Arc::clone(&upstream);
                tokio::spawn(async move {
                    if let Err(e) = run_transproxy(v6, up_v6, stop_v6).await {
                        warn!(error = %e, "IPv6 transproxy exited");
                    }
                });
            }
            Err(e) => warn!(error = %e, "could not bind IPv6 transproxy on [::1]"),
        }
        match UdpSocket::bind(SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            DNS_PROXY_PORT,
        )))
        .await
        {
            Ok(v6dns) => {
                let stop_v6d = stop.clone();
                let up_v6d = Arc::clone(&upstream);
                let servers = dns_servers.clone();
                let dns_gw6 = if dns_via_udpgw {
                    udpgw.handle.clone()
                } else {
                    None
                };
                let dns_otc6 = dns_over_tcp;
                tokio::spawn(async move {
                    if let Err(e) =
                        run_dns_intercept(v6dns, up_v6d, servers, dns_gw6, dns_otc6, stop_v6d).await
                    {
                        warn!(error = %e, "IPv6 DNS intercept exited");
                    }
                });
            }
            Err(e) => warn!(error = %e, "could not bind IPv6 DNS intercept on [::1]"),
        }
    }

    if let Some(handle) = udpgw.handle.clone() {
        let mut reply_socks = Vec::new();
        match bind_udp_origdst(SocketAddr::from((Ipv4Addr::LOCALHOST, UDP_PROXY_PORT))) {
            Ok(sock) => {
                let sock = Arc::new(sock);
                reply_socks.push(Arc::clone(&sock));
                let stop_u = stop.clone();
                let gw = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_udp_intercept(sock, gw, stop_u).await {
                        warn!(error = %e, "UDP intercept exited");
                    }
                });
            }
            Err(e) => warn!(error = %e, "could not bind UDP intercept 127.0.0.1:{UDP_PROXY_PORT}"),
        }
        if profile.ipv6 {
            match bind_udp_origdst(SocketAddr::from((
                std::net::Ipv6Addr::LOCALHOST,
                UDP_PROXY_PORT,
            ))) {
                Ok(sock) => {
                    let sock = Arc::new(sock);
                    reply_socks.push(Arc::clone(&sock));
                    let stop_u = stop.clone();
                    let gw = handle.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_udp_intercept(sock, gw, stop_u).await {
                            warn!(error = %e, "IPv6 UDP intercept exited");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "could not bind UDP intercept [::1]:{UDP_PROXY_PORT}"),
            }
        }
        let stop_r = stop.clone();
        tokio::spawn(async move {
            pump_udpgw_replies(reply_socks, udpgw.replies, stop_r).await;
        });
    }

    let mtu = profile.mtu.unwrap_or(DEFAULT_MTU);
    let spec = ApplySpec {
        session_id: profile.id,
        tun_name: TUN_NAME.into(),
        tun_addr: TUN_ADDR,
        tun_prefix: TUN_PREFIX,
        mtu,
        server_ips,
        bypass_private: profile.bypass_private_networks
            || profile.routing_mode == RoutingMode::SplitTunnel,
        extra_bypass: split_bypass_nets(profile).await,
        ipv6: profile.ipv6,
        kill_switch: profile.kill_switch,
        transproxy_port: TRANSPROXY_PORT,
        dns_port: DNS_PROXY_PORT,
        dns_mode: policy.as_str().into(),
        dns_servers: dns_servers.clone(),
        udp_port,
    };

    let (msg, fd) = match helper.apply(spec).await {
        Ok(v) => v,
        Err(e) => {
            stop.cancel();
            return Err(e.into());
        }
    };
    info!(%msg, "helper applied TUN + nftables intercept");

    let tun = TunIo::from_owned_fd(fd)?;
    let stop_tun = stop.clone();
    let task = tokio::spawn(async move {
        drain_tun(tun, stop_tun).await;
    });

    let dns_status = match policy {
        rt_dns::DnsPolicy::System => "system".into(),
        rt_dns::DnsPolicy::Custom if dns_via_udpgw => {
            format!("custom via UDPGW ({})", dns_servers.join(", "))
        }
        rt_dns::DnsPolicy::Custom => match dns_over_tcp {
            DnsOverTcp::Off => format!("custom UDP only ({})", dns_servers.join(", ")),
            _ => format!("custom DNS-over-TCP ({})", dns_servers.join(", ")),
        },
        rt_dns::DnsPolicy::Remote | rt_dns::DnsPolicy::Tunnel if dns_via_udpgw => {
            format!("tunnel UDPGW DNS ({})", dns_servers.join(", "))
        }
        rt_dns::DnsPolicy::Remote | rt_dns::DnsPolicy::Tunnel => match dns_over_tcp {
            DnsOverTcp::Off => "tunnel DNS unavailable (dns_over_tcp=off, no UDPGW)".into(),
            DnsOverTcp::On => format!("tunnel DNS-over-TCP forced ({})", dns_servers.join(", ")),
            DnsOverTcp::Auto => format!(
                "tunnel DNS-over-TCP fallback ({})",
                dns_servers.join(", ")
            ),
        },
    };

    let udp_note = if udpgw_ok {
        format!(
            "UDP is redirected to :{UDP_PROXY_PORT} and carried over SSH via UDPGW ({}). Not every QUIC/game protocol survives this path.",
            udpgw.status
        )
    } else if profile.udpgw.enabled {
        format!(
            "UDPGW is enabled but not connected ({}). Leftover UDP is rejected so apps can fall back to TCP.",
            udpgw.status
        )
    } else {
        "UDPGW is off. Leftover UDP is rejected; DNS uses DNS-over-TCP. Enable UDPGW if the server runs badvpn-udpgw."
            .into()
    };

    Ok(StartedTun {
        helper,
        stop,
        task,
        dns_status,
        udpgw_status: udpgw.status,
        udp_note,
        udpgw_ok,
    })
}

async fn resolve_server_ips(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    let mut ips: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            TunnelError::Other(format!(
                "Could not resolve {host}:{port} before applying routes: {e}"
            ))
        })?
        .map(|a| a.ip())
        .collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(TunnelError::Other(format!(
            "No addresses resolved for {host}"
        )));
    }
    Ok(ips)
}

fn full_tunnel_error(detail: &str) -> String {
    format!(
        "VPN / full-tunnel mode could not be started.\n\n{detail}\n\nPossible causes:\n\
         • polkit elevation was denied or cancelled\n\
         • pkexec / policykit-1 is not installed\n\
         • privileged helper failed to start\n\
         • /dev/net/tun or nftables is unavailable\n\n\
         The desktop app will prompt for authentication via pkexec when needed.\n\
         Manual fallback:\n  sudo easy-helper --allow-uid $(id -u)\n\
         or: sudo scripts/install-helper.sh\n\n\
         Proxy-only mode still works without the helper."
    )
}
