use std::sync::Arc;

use rt_config::{
    AuthMethod, ConnectionConfig, HostKeyPolicy, ProtocolSettings, TlsFingerprintProfile, Transport,
};
use rt_core::AppController;
use rt_tunnel::ConnectionSnapshot;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

#[derive(Serialize)]
pub struct ProfileDto {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub transport: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub ipv6: bool,
    pub routing_mode: String,
    pub kill_switch: bool,
    pub bypass_private_networks: bool,
    pub tofu: bool,
    pub dns_mode: String,
    pub dns_servers: Vec<String>,
    pub udpgw_enabled: bool,
    pub udpgw_host: String,
    pub udpgw_port: u16,
    pub udpgw_transparent_dns: bool,
    pub tls_sni: Option<String>,
    pub tls_alpn: Vec<String>,
    pub tls_verify: bool,
    pub tls_fingerprint: String,
    pub tls_path: Option<String>,
    pub tls_host: Option<String>,
    pub ss_method: Option<String>,
    pub vless_uuid: Option<String>,
    pub vless_encryption: Option<String>,
    pub vless_flow: Option<String>,
    pub split_bypass_cidrs: Vec<String>,
    pub split_bypass_domains: Vec<String>,
    pub proxy: ProxyDto,
}

#[derive(Serialize)]
pub struct ProxyDto {
    pub socks_port: u16,
    pub http_proxy_port: u16,
    pub listen: String,
}

fn to_dto(cfg: &ConnectionConfig) -> ProfileDto {
    let (ss_method, vless_uuid, vless_encryption, vless_flow) = match &cfg.settings {
        ProtocolSettings::Shadowsocks { method } => (Some(method.clone()), None, None, None),
        ProtocolSettings::Vless {
            uuid,
            encryption,
            flow,
            ..
        } => (
            None,
            Some(uuid.clone()),
            Some(encryption.clone()),
            Some(flow.clone()),
        ),
        _ => (None, None, None, None),
    };
    ProfileDto {
        id: cfg.id.to_string(),
        name: cfg.name.clone(),
        protocol: format!("{:?}", cfg.protocol).to_lowercase(),
        transport: format!("{:?}", cfg.transport).to_lowercase(),
        host: cfg.host.clone(),
        port: cfg.port,
        username: cfg.username.clone(),
        ipv6: cfg.ipv6,
        routing_mode: match cfg.routing_mode {
            rt_config::RoutingMode::ProxyOnly => "proxy_only".into(),
            rt_config::RoutingMode::FullTunnel => "full_tunnel".into(),
            rt_config::RoutingMode::SplitTunnel => "split_tunnel".into(),
        },
        kill_switch: cfg.kill_switch,
        bypass_private_networks: cfg.bypass_private_networks,
        tofu: matches!(
            cfg.settings,
            ProtocolSettings::Ssh {
                host_key_policy: HostKeyPolicy::Tofu,
                ..
            }
        ),
        dns_mode: match cfg.dns.mode {
            rt_config::DnsMode::System => "system".into(),
            rt_config::DnsMode::Tunnel => "tunnel".into(),
            rt_config::DnsMode::Custom => "custom".into(),
            rt_config::DnsMode::Remote => "remote".into(),
        },
        dns_servers: cfg.dns.servers.clone(),
        udpgw_enabled: cfg.udpgw.enabled,
        udpgw_host: cfg.udpgw.host.clone(),
        udpgw_port: cfg.udpgw.port,
        udpgw_transparent_dns: cfg.udpgw.transparent_dns,
        tls_sni: cfg.tls.sni.clone(),
        tls_alpn: cfg.tls.alpn.clone(),
        tls_verify: cfg.tls.verify,
        tls_fingerprint: format!("{:?}", cfg.tls.fingerprint).to_lowercase(),
        tls_path: cfg.tls.path.clone(),
        tls_host: cfg.tls.host.clone(),
        ss_method,
        vless_uuid,
        vless_encryption,
        vless_flow,
        split_bypass_cidrs: cfg.split_bypass_cidrs.clone(),
        split_bypass_domains: cfg.split_bypass_domains.clone(),
        proxy: ProxyDto {
            socks_port: cfg.proxy.socks_port,
            http_proxy_port: cfg.proxy.http_proxy_port,
            listen: cfg.proxy.listen.clone(),
        },
    }
}

fn parse_transport(s: &str) -> Result<Transport, String> {
    match s.to_ascii_lowercase().as_str() {
        "direct" => Ok(Transport::Direct),
        "tls" => Ok(Transport::Tls),
        "websocket" | "ws" => Ok(Transport::WebSocket),
        "wss" => Ok(Transport::Wss),
        "http_upgrade" | "http-upgrade" | "upgrade" => Ok(Transport::HttpUpgrade),
        other => Err(format!(
            "Unknown transport `{other}`. Use direct, tls, websocket, wss, or http_upgrade."
        )),
    }
}

fn parse_fingerprint(s: &str) -> Result<TlsFingerprintProfile, String> {
    match s.to_ascii_lowercase().as_str() {
        "default" => Ok(TlsFingerprintProfile::Default),
        "chrome" => Ok(TlsFingerprintProfile::Chrome),
        "firefox" => Ok(TlsFingerprintProfile::Firefox),
        "safari" => Ok(TlsFingerprintProfile::Safari),
        "custom" => Ok(TlsFingerprintProfile::Custom),
        other => Err(format!(
            "Unknown fingerprint `{other}`. Use default, chrome, firefox, safari, or custom."
        )),
    }
}

fn apply_transport_tls(
    cfg: &mut ConnectionConfig,
    transport: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    tls_verify: Option<bool>,
    tls_fingerprint: Option<String>,
    tls_path: Option<String>,
    tls_host: Option<String>,
) -> Result<(), String> {
    if let Some(t) = transport.as_deref() {
        cfg.transport = parse_transport(t)?;
    }
    if let Some(s) = tls_sni {
        cfg.tls.sni = if s.trim().is_empty() { None } else { Some(s) };
    }
    if let Some(a) = tls_alpn {
        cfg.tls.alpn = a
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
    }
    if let Some(v) = tls_verify {
        cfg.tls.verify = v;
    }
    if let Some(f) = tls_fingerprint.as_deref() {
        cfg.tls.fingerprint = parse_fingerprint(f)?;
    }
    if let Some(p) = tls_path {
        cfg.tls.path = if p.trim().is_empty() { None } else { Some(p) };
    }
    if let Some(h) = tls_host {
        cfg.tls.host = if h.trim().is_empty() { None } else { Some(h) };
    }
    Ok(())
}

fn apply_common(
    cfg: &mut ConnectionConfig,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    routing_mode: Option<String>,
    kill_switch: Option<bool>,
    bypass_private_networks: Option<bool>,
    ipv6: Option<bool>,
    dns_mode: Option<String>,
    dns_servers: Option<String>,
) -> Result<(), String> {
    if let Some(port) = socks_port {
        cfg.proxy.socks_port = port;
    }
    if let Some(port) = http_port {
        cfg.proxy.http_proxy_port = port;
    }
    cfg.kill_switch = kill_switch.unwrap_or(cfg.kill_switch);
    cfg.bypass_private_networks = bypass_private_networks.unwrap_or(cfg.bypass_private_networks);
    cfg.ipv6 = ipv6.unwrap_or(cfg.ipv6);
    // Ignore per-profile routing_mode from the UI/import — dashboard settings own it.
    let _ = routing_mode;
    cfg.routing_mode = rt_config::RoutingMode::ProxyOnly;
    if let Some(mode) = dns_mode.as_deref() {
        cfg.dns.mode = parse_dns_mode(mode)?;
    }
    if let Some(servers) = dns_servers.as_deref() {
        cfg.dns.servers = parse_dns_servers(servers);
    }
    Ok(())
}

fn apply_share_and_split(
    cfg: &mut ConnectionConfig,
    listen: Option<String>,
    split_bypass_cidrs: Option<String>,
    split_bypass_domains: Option<String>,
) {
    if let Some(l) = listen {
        let t = l.trim();
        if !t.is_empty() {
            cfg.proxy.listen = if t.eq_ignore_ascii_case("lan") {
                "0.0.0.0".into()
            } else {
                t.to_string()
            };
        }
    }
    if let Some(c) = split_bypass_cidrs {
        cfg.split_bypass_cidrs = parse_dns_servers(&c);
    }
    if let Some(d) = split_bypass_domains {
        cfg.split_bypass_domains = parse_dns_servers(&d);
    }
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_profiles(ctrl: State<'_, Arc<AppController>>) -> Result<Vec<ProfileDto>, String> {
    ctrl.list_profiles()
        .map(|v| v.iter().map(to_dto).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub fn add_ssh_profile(
    ctrl: State<'_, Arc<AppController>>,
    name: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    tofu: Option<bool>,
    routing_mode: Option<String>,
    kill_switch: Option<bool>,
    bypass_private_networks: Option<bool>,
    ipv6: Option<bool>,
    dns_mode: Option<String>,
    dns_servers: Option<String>,
    udpgw_enabled: Option<bool>,
    udpgw_host: Option<String>,
    udpgw_port: Option<u16>,
    udpgw_transparent_dns: Option<bool>,
    transport: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    tls_verify: Option<bool>,
    tls_fingerprint: Option<String>,
    tls_path: Option<String>,
    tls_host: Option<String>,
    listen: Option<String>,
    split_bypass_cidrs: Option<String>,
    split_bypass_domains: Option<String>,
) -> Result<ProfileDto, String> {
    let mut cfg = ConnectionConfig::new_ssh(name, host, port);
    cfg.username = Some(username);
    apply_common(
        &mut cfg,
        socks_port,
        http_port,
        routing_mode,
        kill_switch,
        bypass_private_networks,
        ipv6,
        dns_mode,
        dns_servers,
    )?;
    apply_share_and_split(&mut cfg, listen, split_bypass_cidrs, split_bypass_domains);
    apply_transport_tls(
        &mut cfg,
        transport,
        tls_sni,
        tls_alpn,
        tls_verify,
        tls_fingerprint,
        tls_path,
        tls_host,
    )?;
    apply_udpgw(
        &mut cfg,
        udpgw_enabled,
        udpgw_host,
        udpgw_port,
        udpgw_transparent_dns,
    );
    let secret = ctrl.put_secret(&password).map_err(|e| e.to_string())?;
    cfg.authentication = AuthMethod::Password {
        secret: Some(secret),
    };
    if let ProtocolSettings::Ssh {
        host_key_policy, ..
    } = &mut cfg.settings
    {
        *host_key_policy = if tofu.unwrap_or(true) {
            HostKeyPolicy::Tofu
        } else {
            HostKeyPolicy::Strict
        };
    }
    let saved = ctrl.save_profile(cfg).map_err(|e| e.to_string())?;
    Ok(to_dto(&saved))
}

#[tauri::command(rename_all = "snake_case")]
pub fn add_ss_profile(
    ctrl: State<'_, Arc<AppController>>,
    name: String,
    host: String,
    port: u16,
    method: String,
    password: String,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    routing_mode: Option<String>,
    kill_switch: Option<bool>,
    bypass_private_networks: Option<bool>,
    ipv6: Option<bool>,
    dns_mode: Option<String>,
    dns_servers: Option<String>,
    transport: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    tls_verify: Option<bool>,
    tls_fingerprint: Option<String>,
    tls_path: Option<String>,
    tls_host: Option<String>,
    listen: Option<String>,
    split_bypass_cidrs: Option<String>,
    split_bypass_domains: Option<String>,
) -> Result<ProfileDto, String> {
    let mut cfg = ConnectionConfig::new_shadowsocks(name, host, port, method);
    apply_common(
        &mut cfg,
        socks_port,
        http_port,
        routing_mode,
        kill_switch,
        bypass_private_networks,
        ipv6,
        dns_mode,
        dns_servers,
    )?;
    apply_share_and_split(&mut cfg, listen, split_bypass_cidrs, split_bypass_domains);
    apply_transport_tls(
        &mut cfg,
        transport,
        tls_sni,
        tls_alpn,
        tls_verify,
        tls_fingerprint,
        tls_path,
        tls_host,
    )?;
    let secret = ctrl.put_secret(&password).map_err(|e| e.to_string())?;
    cfg.authentication = AuthMethod::Password {
        secret: Some(secret),
    };
    let saved = ctrl.save_profile(cfg).map_err(|e| e.to_string())?;
    Ok(to_dto(&saved))
}

#[tauri::command(rename_all = "snake_case")]
pub fn add_vless_profile(
    ctrl: State<'_, Arc<AppController>>,
    name: String,
    host: String,
    port: u16,
    uuid: String,
    encryption: Option<String>,
    flow: Option<String>,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    routing_mode: Option<String>,
    kill_switch: Option<bool>,
    bypass_private_networks: Option<bool>,
    ipv6: Option<bool>,
    dns_mode: Option<String>,
    dns_servers: Option<String>,
    transport: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    tls_verify: Option<bool>,
    tls_fingerprint: Option<String>,
    tls_path: Option<String>,
    tls_host: Option<String>,
    listen: Option<String>,
    split_bypass_cidrs: Option<String>,
    split_bypass_domains: Option<String>,
) -> Result<ProfileDto, String> {
    let mut cfg = ConnectionConfig::new_vless(name, host, port, uuid);
    apply_common(
        &mut cfg,
        socks_port,
        http_port,
        routing_mode,
        kill_switch,
        bypass_private_networks,
        ipv6,
        dns_mode,
        dns_servers,
    )?;
    apply_share_and_split(&mut cfg, listen, split_bypass_cidrs, split_bypass_domains);
    apply_transport_tls(
        &mut cfg,
        transport,
        tls_sni,
        tls_alpn,
        tls_verify,
        tls_fingerprint,
        tls_path,
        tls_host,
    )?;
    if let ProtocolSettings::Vless {
        encryption: enc,
        flow: fl,
        host: vhost,
        path,
        ..
    } = &mut cfg.settings
    {
        if let Some(e) = encryption {
            *enc = e;
        }
        if let Some(f) = flow {
            *fl = f;
        }
        *vhost = cfg.tls.host.clone();
        *path = cfg.tls.path.clone();
    }
    let saved = ctrl.save_profile(cfg).map_err(|e| e.to_string())?;
    Ok(to_dto(&saved))
}

fn parse_dns_mode(mode: &str) -> Result<rt_config::DnsMode, String> {
    match mode {
        "system" => Ok(rt_config::DnsMode::System),
        "tunnel" => Ok(rt_config::DnsMode::Tunnel),
        "custom" => Ok(rt_config::DnsMode::Custom),
        "remote" => Ok(rt_config::DnsMode::Remote),
        other => Err(format!(
            "Unknown DNS mode `{other}`. Use system, tunnel, or custom."
        )),
    }
}

fn apply_udpgw(
    cfg: &mut ConnectionConfig,
    enabled: Option<bool>,
    host: Option<String>,
    port: Option<u16>,
    transparent_dns: Option<bool>,
) {
    if let Some(v) = enabled {
        cfg.udpgw.enabled = v;
    }
    if let Some(h) = host {
        if !h.is_empty() {
            cfg.udpgw.host = h;
        }
    }
    if let Some(p) = port {
        if p != 0 {
            cfg.udpgw.port = p;
        }
    }
    if let Some(v) = transparent_dns {
        cfg.udpgw.transparent_dns = v;
    }
}

fn parse_dns_servers(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn parse_routing_mode(mode: &str) -> Result<rt_config::RoutingMode, String> {
    match mode {
        "proxy_only" | "proxy" => Ok(rt_config::RoutingMode::ProxyOnly),
        "full_tunnel" | "fulltunnel" | "vpn" | "full" => Ok(rt_config::RoutingMode::FullTunnel),
        "split_tunnel" | "splittunnel" | "split" => Ok(rt_config::RoutingMode::SplitTunnel),
        other => Err(format!(
            "Unknown connection mode `{other}`. Use proxy_only, full_tunnel, or split_tunnel."
        )),
    }
}

#[tauri::command(rename_all = "snake_case")]
pub async fn emergency_restore() -> Result<String, String> {
    rt_tun::client::HelperClient::connect_default()
        .await
        .map_err(|e| {
            format!(
                "Could not reach the privileged helper ({e}). If networking is stuck, run: sudo easy-helper --cleanup-and-exit"
            )
        })?
        .emergency_restore()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub fn get_profile(ctrl: State<'_, Arc<AppController>>, id: String) -> Result<ProfileDto, String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let cfg = ctrl.get_profile(id).map_err(|e| e.to_string())?;
    Ok(to_dto(&cfg))
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_ssh_profile(
    ctrl: State<'_, Arc<AppController>>,
    id: String,
    name: String,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    tofu: Option<bool>,
    routing_mode: Option<String>,
    kill_switch: Option<bool>,
    bypass_private_networks: Option<bool>,
    ipv6: Option<bool>,
    dns_mode: Option<String>,
    dns_servers: Option<String>,
    udpgw_enabled: Option<bool>,
    udpgw_host: Option<String>,
    udpgw_port: Option<u16>,
    udpgw_transparent_dns: Option<bool>,
    transport: Option<String>,
    tls_sni: Option<String>,
    tls_alpn: Option<String>,
    tls_verify: Option<bool>,
    tls_fingerprint: Option<String>,
    tls_path: Option<String>,
    tls_host: Option<String>,
    method: Option<String>,
    uuid: Option<String>,
    encryption: Option<String>,
    flow: Option<String>,
    listen: Option<String>,
    split_bypass_cidrs: Option<String>,
    split_bypass_domains: Option<String>,
) -> Result<ProfileDto, String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let mut cfg = ctrl.get_profile(id).map_err(|e| e.to_string())?;
    cfg.name = name;
    cfg.host = host;
    cfg.port = port;
    if let Some(u) = username {
        cfg.username = Some(u);
    }
    apply_common(
        &mut cfg,
        socks_port,
        http_port,
        routing_mode,
        kill_switch,
        bypass_private_networks,
        ipv6,
        dns_mode,
        dns_servers,
    )?;
    apply_share_and_split(&mut cfg, listen, split_bypass_cidrs, split_bypass_domains);
    apply_transport_tls(
        &mut cfg,
        transport,
        tls_sni,
        tls_alpn,
        tls_verify,
        tls_fingerprint,
        tls_path,
        tls_host,
    )?;
    apply_udpgw(
        &mut cfg,
        udpgw_enabled,
        udpgw_host,
        udpgw_port,
        udpgw_transparent_dns,
    );
    match &mut cfg.settings {
        ProtocolSettings::Ssh {
            host_key_policy, ..
        } => {
            if let Some(tofu) = tofu {
                *host_key_policy = if tofu {
                    HostKeyPolicy::Tofu
                } else {
                    HostKeyPolicy::Strict
                };
            }
        }
        ProtocolSettings::Shadowsocks { method: m } => {
            if let Some(next) = method {
                *m = next;
            }
        }
        ProtocolSettings::Vless {
            uuid: id,
            encryption: enc,
            flow: fl,
            host: vhost,
            path,
        } => {
            if let Some(u) = uuid {
                *id = u;
            }
            if let Some(e) = encryption {
                *enc = e;
            }
            if let Some(f) = flow {
                *fl = f;
            }
            *vhost = cfg.tls.host.clone();
            *path = cfg.tls.path.clone();
        }
        _ => {}
    }
    let saved = ctrl.save_profile(cfg).map_err(|e| e.to_string())?;
    if let Some(password) = password {
        if !password.is_empty() {
            let updated = ctrl
                .set_password_secret(id, &password)
                .map_err(|e| e.to_string())?;
            return Ok(to_dto(&updated));
        }
    }
    Ok(to_dto(&saved))
}

#[tauri::command(rename_all = "snake_case")]
pub fn delete_profile(ctrl: State<'_, Arc<AppController>>, id: String) -> Result<(), String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    ctrl.delete_profile(id).map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn connect_profile(
    ctrl: State<'_, Arc<AppController>>,
    id: String,
) -> Result<ConnectionSnapshot, String> {
    let id = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    ctrl.connect(id).await.map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn disconnect(ctrl: State<'_, Arc<AppController>>) -> Result<ConnectionSnapshot, String> {
    ctrl.disconnect().await.map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub fn connection_status(ctrl: State<'_, Arc<AppController>>) -> ConnectionSnapshot {
    ctrl.connection_snapshot()
}

#[tauri::command(rename_all = "snake_case")]
pub fn get_app_settings(
    ctrl: State<'_, Arc<AppController>>,
) -> Result<rt_config::AppSettings, String> {
    ctrl.get_settings().map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub fn set_preferred_routing_mode(
    ctrl: State<'_, Arc<AppController>>,
    mode: String,
) -> Result<rt_config::AppSettings, String> {
    let parsed = parse_routing_mode(&mode)?;
    let mut settings = ctrl.get_settings().map_err(|e| e.to_string())?;
    settings.preferred_routing_mode = match parsed {
        rt_config::RoutingMode::ProxyOnly => "proxy_only".into(),
        rt_config::RoutingMode::FullTunnel => "full_tunnel".into(),
        rt_config::RoutingMode::SplitTunnel => "split_tunnel".into(),
    };
    ctrl.save_settings(settings.clone())
        .map_err(|e| e.to_string())?;
    Ok(settings)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn leak_report(
    ctrl: State<'_, Arc<AppController>>,
) -> Result<rt_diagnostics::LeakReport, String> {
    Ok(ctrl.leak_report().await)
}

#[tauri::command(rename_all = "snake_case")]
pub fn import_profile(
    ctrl: State<'_, Arc<AppController>>,
    text: String,
) -> Result<ProfileDto, String> {
    ctrl.import_profile_text(&text)
        .map(|c| to_dto(&c))
        .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn tcp_probe(
    ctrl: State<'_, Arc<AppController>>,
    host: String,
    port: Option<u16>,
) -> Result<rt_diagnostics::ProbeResult, String> {
    Ok(ctrl.tcp_probe(&host, port.unwrap_or(443)).await)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn traceroute(
    ctrl: State<'_, Arc<AppController>>,
    host: String,
) -> Result<rt_diagnostics::ProbeResult, String> {
    Ok(ctrl.traceroute(&host).await)
}
