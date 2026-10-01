//! VLESS adapter backed by an installed Xray or sing-box process.
//!
//! The external engine owns the VLESS wire protocol and transports. This crate
//! starts a private loopback SOCKS inbound and adapts it to `UpstreamConnector`.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use rt_config::{ConnectionConfig, ProtocolSettings, TlsFingerprintProfile, Transport};
use rt_socks::{SocksError, UpstreamConnector, UpstreamIo};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use uuid::Uuid;

const START_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Error)]
pub enum VlessError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("VLESS engine: {0}")]
    Engine(String),
}

pub type Result<T> = std::result::Result<T, VlessError>;

#[derive(Debug, Clone, Copy)]
enum EngineKind {
    Xray,
    SingBox,
}

impl EngineKind {
    fn label(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
        }
    }

    fn binary(self) -> String {
        let override_name = match self {
            Self::Xray => "EASY_XRAY_PATH",
            Self::SingBox => "EASY_SING_BOX_PATH",
        };
        std::env::var(override_name).unwrap_or_else(|_| self.label().into())
    }
}

struct EngineProcess {
    child: Mutex<Child>,
}

struct TemporaryConfig {
    path: PathBuf,
}

impl Drop for TemporaryConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            let _ = child.start_kill();
        }
    }
}

pub struct VlessConnector {
    socks_addr: SocketAddr,
    _engine: EngineProcess,
}

impl VlessConnector {
    /// Starts the requested engine. `EASY_VLESS_ENGINE` accepts `auto` (default),
    /// `xray`, or `sing-box`.
    pub async fn start(cfg: &ConnectionConfig) -> Result<Self> {
        let requested = std::env::var("EASY_VLESS_ENGINE")
            .unwrap_or_else(|_| "auto".into())
            .to_ascii_lowercase();
        let candidates: &[EngineKind] = match requested.as_str() {
            "auto" | "" => &[EngineKind::Xray, EngineKind::SingBox],
            "xray" => &[EngineKind::Xray],
            "sing-box" | "singbox" => &[EngineKind::SingBox],
            other => {
                return Err(VlessError::Config(format!(
                    "unknown EASY_VLESS_ENGINE `{other}`; use auto, xray, or sing-box"
                )))
            }
        };

        let mut failures = Vec::new();
        for kind in candidates {
            match start_engine(*kind, cfg).await {
                Ok(connector) => return Ok(connector),
                Err(error) => failures.push(format!("{}: {error}", kind.label())),
            }
        }
        Err(VlessError::Engine(format!(
            "could not start an external VLESS engine ({}). Install Xray or sing-box in PATH, or set EASY_XRAY_PATH / EASY_SING_BOX_PATH",
            failures.join("; ")
        )))
    }
}

async fn start_engine(kind: EngineKind, cfg: &ConnectionConfig) -> Result<VlessConnector> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let socks_addr = listener.local_addr()?;
    drop(listener);

    let config = match kind {
        EngineKind::Xray => build_xray_config(cfg, socks_addr.port())?,
        EngineKind::SingBox => build_sing_box_config(cfg, socks_addr.port())?,
    };
    let config_file = write_engine_config(kind, &config).await?;
    let mut command = Command::new(kind.binary());
    command.args(["run", "-c"]);
    command
        .arg(&config_file.path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            if error.kind() == ErrorKind::NotFound {
                return Err(VlessError::Engine(format!(
                    "binary `{}` was not found",
                    kind.binary()
                )));
            }
            return Err(error.into());
        }
    };

    let started = tokio::time::timeout(START_TIMEOUT, async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(VlessError::Engine(format!(
                    "{} exited during startup with {status}",
                    kind.label()
                )));
            }
            match TcpStream::connect(socks_addr).await {
                Ok(stream) => {
                    drop(stream);
                    return Ok(());
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    match started {
        Ok(Ok(())) => {
            tracing::info!(engine = kind.label(), %socks_addr, "external VLESS engine started");
            Ok(VlessConnector {
                socks_addr,
                _engine: EngineProcess {
                    child: Mutex::new(child),
                },
            })
        }
        Ok(Err(error)) => Err(error),
        Err(_) => {
            let _ = child.start_kill();
            Err(VlessError::Engine(format!(
                "{} did not open its local SOCKS port within {} seconds",
                kind.label(),
                START_TIMEOUT.as_secs()
            )))
        }
    }
}

async fn write_engine_config(kind: EngineKind, value: &Value) -> Result<TemporaryConfig> {
    let path = std::env::temp_dir().join(format!(
        "easy-vless-{}-{}.json",
        kind.label(),
        Uuid::new_v4()
    ));
    let bytes = serde_json::to_vec(value).map_err(|e| VlessError::Config(e.to_string()))?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&path).await?;
    file.write_all(&bytes).await?;
    file.flush().await?;
    Ok(TemporaryConfig { path })
}

fn vless_settings(cfg: &ConnectionConfig) -> Result<VlessSettings<'_>> {
    match &cfg.settings {
        ProtocolSettings::Vless {
            uuid,
            encryption,
            flow,
            network,
            security,
            host,
            path,
            reality_public_key,
            reality_short_id,
            grpc_service_name,
            xhttp_mode,
            spider_x,
        } => Ok(VlessSettings {
            uuid,
            encryption,
            flow,
            network,
            security,
            host: host.as_deref().or(cfg.tls.host.as_deref()),
            path: path.as_deref().or(cfg.tls.path.as_deref()),
            reality_public_key: reality_public_key.as_deref(),
            reality_short_id: reality_short_id.as_deref(),
            grpc_service_name: grpc_service_name.as_deref(),
            xhttp_mode: xhttp_mode.as_deref(),
            spider_x: spider_x.as_deref(),
        }),
        _ => Err(VlessError::Config("not a VLESS profile".into())),
    }
}

struct VlessSettings<'a> {
    uuid: &'a str,
    encryption: &'a str,
    flow: &'a str,
    network: &'a str,
    security: &'a str,
    host: Option<&'a str>,
    path: Option<&'a str>,
    reality_public_key: Option<&'a str>,
    reality_short_id: Option<&'a str>,
    grpc_service_name: Option<&'a str>,
    xhttp_mode: Option<&'a str>,
    spider_x: Option<&'a str>,
}

fn build_xray_config(cfg: &ConnectionConfig, socks_port: u16) -> Result<Value> {
    let v = vless_settings(cfg)?;
    let network = effective_network(cfg, v.network);
    let security = effective_security(cfg, v.security);
    let mut settings = json!({
        "address": cfg.host,
        "port": cfg.port,
        "id": v.uuid,
        "encryption": if v.encryption.is_empty() { "none" } else { v.encryption },
    });
    if !v.flow.is_empty() && !v.flow.eq_ignore_ascii_case("none") {
        settings["flow"] = json!(v.flow);
    }

    let mut stream = Map::new();
    stream.insert("method".into(), json!(xray_network(network)));
    stream.insert("security".into(), json!(security));
    add_xray_transport(&mut stream, network, &v);
    if security == "tls" {
        stream.insert("tlsSettings".into(), xray_tls_settings(cfg));
    } else if security == "reality" {
        stream.insert("realitySettings".into(), xray_reality_settings(cfg, &v)?);
    }

    Ok(json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [{
            "tag": "vless-out",
            "protocol": "vless",
            "settings": settings,
            "streamSettings": Value::Object(stream)
        }]
    }))
}

fn add_xray_transport(stream: &mut Map<String, Value>, network: &str, v: &VlessSettings<'_>) {
    let path = v.path.unwrap_or("/");
    match network {
        "ws" => {
            stream.insert(
                "wsSettings".into(),
                json!({ "path": path, "host": v.host.unwrap_or("") }),
            );
        }
        "grpc" => {
            stream.insert(
                "grpcSettings".into(),
                json!({ "serviceName": v.grpc_service_name.unwrap_or("") }),
            );
        }
        "httpupgrade" => {
            stream.insert(
                "httpupgradeSettings".into(),
                json!({ "path": path, "host": v.host.unwrap_or("") }),
            );
        }
        "xhttp" => {
            stream.insert(
                "xhttpSettings".into(),
                json!({
                    "path": path,
                    "host": v.host.unwrap_or(""),
                    "mode": v.xhttp_mode.unwrap_or("")
                }),
            );
        }
        _ => {}
    }
}

fn xray_tls_settings(cfg: &ConnectionConfig) -> Value {
    json!({
        "serverName": cfg.tls.sni.as_deref().unwrap_or(&cfg.host),
        "allowInsecure": !cfg.tls.verify,
        "alpn": cfg.tls.alpn,
        "fingerprint": fingerprint(&cfg.tls.fingerprint),
    })
}

fn xray_reality_settings(cfg: &ConnectionConfig, v: &VlessSettings<'_>) -> Result<Value> {
    Ok(json!({
        "serverName": cfg.tls.sni.as_deref().unwrap_or(&cfg.host),
        "fingerprint": fingerprint(&cfg.tls.fingerprint),
        "password": v.reality_public_key.ok_or_else(|| VlessError::Config("Reality public key is missing".into()))?,
        "shortId": v.reality_short_id.unwrap_or(""),
        "spiderX": v.spider_x.unwrap_or("/"),
    }))
}

fn build_sing_box_config(cfg: &ConnectionConfig, socks_port: u16) -> Result<Value> {
    let v = vless_settings(cfg)?;
    let network = effective_network(cfg, v.network);
    let security = effective_security(cfg, v.security);
    if network == "xhttp" {
        return Err(VlessError::Config(
            "sing-box does not support the XHTTP V2Ray transport; select Xray".into(),
        ));
    }
    if v.flow.eq_ignore_ascii_case("xtls-rprx-vision-udp443") {
        return Err(VlessError::Config(
            "sing-box does not support xtls-rprx-vision-udp443; select Xray".into(),
        ));
    }

    let mut outbound = Map::new();
    outbound.insert("type".into(), json!("vless"));
    outbound.insert("tag".into(), json!("vless-out"));
    outbound.insert("server".into(), json!(cfg.host));
    outbound.insert("server_port".into(), json!(cfg.port));
    outbound.insert("uuid".into(), json!(v.uuid));
    outbound.insert("network".into(), json!("tcp"));
    if !v.flow.is_empty() && !v.flow.eq_ignore_ascii_case("none") {
        outbound.insert("flow".into(), json!(v.flow));
    }
    if security != "none" {
        outbound.insert("tls".into(), sing_box_tls_settings(cfg, &v, security)?);
    }
    if network != "tcp" {
        outbound.insert("transport".into(), sing_box_transport(network, &v)?);
    }

    Ok(json!({
        "log": { "level": "warn" },
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port
        }],
        "outbounds": [Value::Object(outbound)],
        "route": { "final": "vless-out" }
    }))
}

fn sing_box_tls_settings(
    cfg: &ConnectionConfig,
    v: &VlessSettings<'_>,
    security: &str,
) -> Result<Value> {
    let mut tls = json!({
        "enabled": true,
        "server_name": cfg.tls.sni.as_deref().unwrap_or(&cfg.host),
        "insecure": !cfg.tls.verify,
        "alpn": cfg.tls.alpn,
    });
    let fp = fingerprint(&cfg.tls.fingerprint);
    if !fp.is_empty() {
        tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
    }
    if security == "reality" {
        tls["reality"] = json!({
            "enabled": true,
            "public_key": v.reality_public_key.ok_or_else(|| VlessError::Config("Reality public key is missing".into()))?,
            "short_id": v.reality_short_id.unwrap_or("")
        });
    }
    Ok(tls)
}

fn sing_box_transport(network: &str, v: &VlessSettings<'_>) -> Result<Value> {
    let path = v.path.unwrap_or("/");
    match network {
        "ws" => {
            let mut transport = json!({ "type": "ws", "path": path });
            if let Some(host) = v.host {
                transport["headers"] = json!({ "Host": host });
            }
            Ok(transport)
        }
        "grpc" => Ok(json!({
            "type": "grpc",
            "service_name": v.grpc_service_name.unwrap_or("")
        })),
        "httpupgrade" => Ok(json!({
            "type": "httpupgrade",
            "path": path,
            "host": v.host.unwrap_or("")
        })),
        other => Err(VlessError::Config(format!(
            "sing-box transport `{other}` is not supported"
        ))),
    }
}

fn normalize_network(value: &str) -> &str {
    if value.is_empty()
        || value.eq_ignore_ascii_case("raw")
        || value.eq_ignore_ascii_case("none")
        || value.eq_ignore_ascii_case("tcp")
    {
        "tcp"
    } else if value.eq_ignore_ascii_case("websocket") || value.eq_ignore_ascii_case("ws") {
        "ws"
    } else if value.eq_ignore_ascii_case("http_upgrade")
        || value.eq_ignore_ascii_case("httpupgrade")
    {
        "httpupgrade"
    } else if value.eq_ignore_ascii_case("grpc") {
        "grpc"
    } else if value.eq_ignore_ascii_case("xhttp") {
        "xhttp"
    } else {
        value
    }
}

fn normalize_security(value: &str) -> &str {
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        "none"
    } else if value.eq_ignore_ascii_case("tls") {
        "tls"
    } else if value.eq_ignore_ascii_case("reality") {
        "reality"
    } else {
        value
    }
}

fn effective_network<'a>(cfg: &ConnectionConfig, configured: &'a str) -> &'a str {
    if configured.is_empty() || configured.eq_ignore_ascii_case("tcp") {
        match cfg.transport {
            Transport::WebSocket | Transport::Wss => "ws",
            Transport::HttpUpgrade => "httpupgrade",
            _ => normalize_network(configured),
        }
    } else {
        normalize_network(configured)
    }
}

fn effective_security<'a>(cfg: &ConnectionConfig, configured: &'a str) -> &'a str {
    if configured.is_empty() || configured.eq_ignore_ascii_case("none") {
        match cfg.transport {
            Transport::Tls | Transport::Wss => "tls",
            Transport::HttpUpgrade if cfg.tls.sni.is_some() || !cfg.tls.alpn.is_empty() => "tls",
            _ => "none",
        }
    } else {
        normalize_security(configured)
    }
}

fn xray_network(network: &str) -> &str {
    match network {
        "tcp" => "raw",
        "ws" => "websocket",
        other => other,
    }
}

fn fingerprint(value: &TlsFingerprintProfile) -> &'static str {
    match value {
        TlsFingerprintProfile::Chrome => "chrome",
        TlsFingerprintProfile::Firefox => "firefox",
        TlsFingerprintProfile::Safari => "safari",
        TlsFingerprintProfile::Default => "chrome",
        TlsFingerprintProfile::Custom => "",
    }
}

#[async_trait]
impl UpstreamConnector for VlessConnector {
    async fn connect(&self, host: &str, port: u16) -> rt_socks::Result<Box<dyn UpstreamIo>> {
        let target = format!("{host}:{port}");
        tokio::time::timeout(CONNECT_TIMEOUT, socks_connect(self.socks_addr, host, port))
            .await
            .map_err(|_| SocksError::Upstream(format!("VLESS connect to {target} timed out")))?
            .map(|stream| Box::new(stream) as Box<dyn UpstreamIo>)
    }
}

async fn socks_connect(addr: SocketAddr, host: &str, port: u16) -> rt_socks::Result<TcpStream> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| SocksError::Upstream(format!("VLESS engine SOCKS connection: {e}")))?;
    stream
        .write_all(&[5, 1, 0])
        .await
        .map_err(|e| SocksError::Upstream(e.to_string()))?;
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|e| SocksError::Upstream(e.to_string()))?;
    if greeting != [5, 0] {
        return Err(SocksError::Upstream(format!(
            "VLESS engine rejected SOCKS authentication: {greeting:?}"
        )));
    }

    let mut request = vec![5, 1, 0];
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let bytes = host.as_bytes();
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(SocksError::Upstream(
                "invalid SOCKS destination host".into(),
            ));
        }
        request.extend_from_slice(&[3, bytes.len() as u8]);
        request.extend_from_slice(bytes);
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| SocksError::Upstream(e.to_string()))?;

    let mut reply = [0_u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| SocksError::Upstream(e.to_string()))?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(SocksError::Upstream(format!(
            "VLESS engine SOCKS connect failed with reply {}",
            reply[1]
        )));
    }
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| SocksError::Upstream(e.to_string()))?;
            len[0] as usize
        }
        atyp => {
            return Err(SocksError::Upstream(format!(
                "VLESS engine returned invalid SOCKS address type {atyp}"
            )))
        }
    };
    let mut bound = vec![0_u8; address_len + 2];
    stream
        .read_exact(&mut bound)
        .await
        .map_err(|e| SocksError::Upstream(e.to_string()))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ConnectionConfig {
        ConnectionConfig::new_vless(
            "test",
            "example.com",
            443,
            "00000000-0000-0000-0000-000000000000",
        )
    }

    #[test]
    fn xray_uses_private_socks_and_current_vless_shape() {
        let value = build_xray_config(&profile(), 32123).unwrap();
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["port"], 32123);
        assert_eq!(value["outbounds"][0]["settings"]["address"], "example.com");
        assert_eq!(value["outbounds"][0]["streamSettings"]["method"], "raw");
    }

    #[test]
    fn sing_box_rejects_xhttp() {
        let mut cfg = profile();
        if let ProtocolSettings::Vless { network, .. } = &mut cfg.settings {
            *network = "xhttp".into();
        }
        assert!(build_sing_box_config(&cfg, 32123).is_err());
        assert!(build_xray_config(&cfg, 32123).is_ok());
    }
}
