//! SSH-direct exit zones.
//!
//! Wire format recovered from RocketTunnel 3.0.8 (`com.hypertunnel.android`):
//! the zone list is a plaintext JSON command, and the chosen id is the
//! `X-Zone-Id` header on the entry host's smart-config HTTP GET.
//! The SSH username is not rewritten. See `docs/ZONES.md`.

use std::time::Duration;

use async_trait::async_trait;
use rt_config::{TlsSettings, Transport, ZoneInfo};
use rt_tls::DialRequest;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{Result, SshError};

const USER_AGENT: &str = "smart_config/1.0";
const DEFAULT_PATH: &str = "/";
const MAX_BODY: usize = 1024 * 1024;

/// Listing request. Credentials stay in memory for the HTTP body only.
#[derive(Debug, Clone)]
pub struct ZoneFetchRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub path: String,
    pub timeout: Duration,
}

impl ZoneFetchRequest {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password: password.into(),
            path: DEFAULT_PATH.into(),
            timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneList {
    pub hash: Option<String>,
    pub zones: Vec<ZoneInfo>,
    /// True when this list was read with HTTPS on the profile port.
    pub https: bool,
}

/// How a client obtains and applies zones. Tunnel/core depend on this, not on a UI.
#[async_trait]
pub trait ZoneProvider: Send + Sync {
    async fn fetch_zones(&self, req: ZoneFetchRequest) -> Result<ZoneList>;
    async fn signal_selected_zone(
        &self,
        host: &str,
        port: u16,
        zone_id: &str,
        https: bool,
    ) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HttpZoneProvider;

#[async_trait]
impl ZoneProvider for HttpZoneProvider {
    async fn fetch_zones(&self, req: ZoneFetchRequest) -> Result<ZoneList> {
        let body = zone_command_body(&req.username, &req.password);
        let mut errors = Vec::new();
        for attempt in zone_attempts(None) {
            let request = http_request(&ZoneHttpRequest {
                method: "POST",
                host: &req.host,
                port: req.port,
                path: &req.path,
                content_type: Some("application/json"),
                zone_id: None,
                body: Some(body.as_bytes()),
                https: attempt.https,
            });
            match exchange_attempt(
                &req.host,
                req.port,
                attempt,
                request.as_bytes(),
                req.timeout.min(Duration::from_secs(8)),
            )
            .await
            {
                Ok(response) if response.body.starts_with(b"SSH-") => {
                    return Err(SshError::Zones(
                        "This port speaks SSH, so it has no country list. The phone loads countries with an HTTP request to a smart-config host that has the zone flag, and this profile only has the SSH address.".into(),
                    ));
                }
                Ok(response) if (200..300).contains(&response.status) => {
                    match parse_zone_list(&response.body) {
                        Ok(mut list) => {
                            list.https = attempt.https;
                            return Ok(list);
                        }
                        Err(err) => errors.push(format!("{}: {err}", attempt.label())),
                    }
                }
                Ok(response) => {
                    errors.push(format!("{}: HTTP {}", attempt.label(), response.status))
                }
                Err(err) => errors.push(format!("{}: {err}", attempt.label())),
            }
        }
        Err(SshError::Zones(format!(
            "Could not load zones. Check connection and try again. ({})",
            errors.join("; ")
        )))
    }

    async fn signal_selected_zone(
        &self,
        host: &str,
        port: u16,
        zone_id: &str,
        https: bool,
    ) -> Result<()> {
        let zone_id = zone_id.trim();
        if zone_id.is_empty() {
            return Ok(());
        }
        let mut last_err = None;
        for attempt in zone_attempts(Some(https)) {
            let request = http_request(&ZoneHttpRequest {
                method: "GET",
                host,
                port,
                path: DEFAULT_PATH,
                content_type: None,
                zone_id: Some(zone_id),
                body: None,
                https: attempt.https,
            });
            match exchange_attempt(
                host,
                port,
                attempt,
                request.as_bytes(),
                Duration::from_secs(8),
            )
            .await
            {
                Ok(response) if response.body.starts_with(b"SSH-") || response.status == 0 => {
                    last_err = Some(SshError::Zones(
                        "entry host did not answer the zone HTTP request".into(),
                    ));
                }
                Ok(response) => {
                    tracing::info!(
                        host,
                        port,
                        status = response.status,
                        zone_id,
                        https = attempt.https,
                        "signaled selected zone"
                    );
                    return Ok(());
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            SshError::Zones("entry host did not answer the zone HTTP request".into())
        }))
    }
}

/// SSH auth username. RocketTunnel does not encode the zone into it.
pub fn ssh_username_for_zone(username: &str, _zone_id: Option<&str>) -> String {
    username.to_string()
}

/// `{"command":"zone","username":"...","password":"..."}`.
pub fn zone_command_body(username: &str, password: &str) -> String {
    serde_json::json!({
        "command": "zone",
        "username": username,
        "password": password,
    })
    .to_string()
}

/// smart-config HTTP request. `X-Zone-Id` is included only when `zone_id` is set.
pub struct ZoneHttpRequest<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub content_type: Option<&'a str>,
    pub zone_id: Option<&'a str>,
    pub body: Option<&'a [u8]>,
    pub https: bool,
}

pub fn http_request(req: &ZoneHttpRequest<'_>) -> String {
    let path = if req.path.is_empty() {
        DEFAULT_PATH
    } else {
        req.path
    };
    let host_header = host_header(req.host, req.port, req.https);
    let mut out = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n",
        method = req.method,
    );
    if let Some(id) = req.zone_id.map(str::trim).filter(|s| !s.is_empty()) {
        out.push_str("X-Zone-Id: ");
        out.push_str(id);
        out.push_str("\r\n");
    }
    if let Some(ct) = req.content_type {
        out.push_str("Content-Type: ");
        out.push_str(ct);
        out.push_str("\r\n");
    }
    if let Some(body) = req.body {
        out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        out.push_str(&String::from_utf8_lossy(body));
    } else {
        out.push_str("\r\n");
    }
    out
}

fn host_header(host: &str, port: u16, https: bool) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let default_port = if https { 443 } else { 80 };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Clone, Copy)]
struct ZoneAttempt {
    https: bool,
    verify: bool,
}

impl ZoneAttempt {
    fn label(self) -> &'static str {
        match (self.https, self.verify) {
            (true, true) => "https",
            (true, false) => "https-insecure",
            (false, _) => "http",
        }
    }
}

/// RocketTunnel picks `http://` or `https://` from the host flag and keeps the
/// host's own port. An SSH profile has no flag, so try TLS first (the smart
/// flowgraph's `tls` node uses ALPN `http/1.1`), then cleartext HTTP.
fn zone_attempts(https: Option<bool>) -> Vec<ZoneAttempt> {
    match https {
        Some(true) => vec![
            ZoneAttempt {
                https: true,
                verify: true,
            },
            ZoneAttempt {
                https: true,
                verify: false,
            },
        ],
        Some(false) => vec![ZoneAttempt {
            https: false,
            verify: false,
        }],
        // The phone's zone client writes cleartext HTTP. Try that before TLS so an
        // OpenSSH banner is recognized immediately instead of waiting out TLS timeouts.
        None => vec![
            ZoneAttempt {
                https: false,
                verify: false,
            },
            ZoneAttempt {
                https: true,
                verify: true,
            },
            ZoneAttempt {
                https: true,
                verify: false,
            },
        ],
    }
}

pub fn parse_zone_list(body: &[u8]) -> Result<ZoneList> {
    if body.starts_with(b"SSH-") {
        return Err(SshError::Zones(
            "Could not load zones. Check connection and try again.".into(),
        ));
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        SshError::Zones("Could not load zones. Check connection and try again.".into())
    })?;
    let root = value.as_object().ok_or_else(|| {
        SshError::Zones("Could not load zones. Check connection and try again.".into())
    })?;
    let hash = root
        .get("hash")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            root.get("response")
                .and_then(|v| v.get("hash"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    let zones_value = root
        .get("zones")
        .or_else(|| root.get("response").and_then(|v| v.get("zones")))
        .ok_or_else(|| SshError::Zones("Invalid response: no zones".into()))?;
    let items = zones_value
        .as_array()
        .ok_or_else(|| SshError::Zones("Invalid response: no zones".into()))?;
    if items.is_empty() {
        return Err(SshError::Zones("Invalid response: no zones".into()));
    }
    let mut zones = Vec::with_capacity(items.len());
    for item in items {
        if let Some(zone) = parse_zone_item(item) {
            zones.push(zone);
        }
    }
    if zones.is_empty() {
        return Err(SshError::Zones("Invalid response: no zones".into()));
    }
    Ok(ZoneList {
        hash,
        zones,
        https: false,
    })
}

fn parse_zone_item(item: &Value) -> Option<ZoneInfo> {
    match item {
        Value::String(s) => {
            let id = s.trim();
            if id.is_empty() {
                return None;
            }
            let iso = iso_if_code(id);
            Some(ZoneInfo {
                id: id.to_string(),
                name: id.to_string(),
                iso,
            })
        }
        Value::Object(obj) => {
            let id = first_str(obj, &["id", "zone.id", "code", "iso", "isoCode", "country"])?;
            let name = first_str(
                obj,
                &[
                    "name",
                    "friendlyCountryName",
                    "countryName",
                    "title",
                    "label",
                    "country",
                ],
            )
            .unwrap_or_else(|| id.clone());
            let iso = first_str(
                obj,
                &[
                    "iso",
                    "isoCode",
                    "code",
                    "country",
                    "countryCode",
                    "country_iso",
                    "country_code",
                ],
            )
            .and_then(|s| iso_if_code(&s))
            .or_else(|| iso_if_code(&id));
            Some(ZoneInfo { id, name, iso })
        }
        _ => None,
    }
}

fn first_str(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = obj.get(*key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn iso_if_code(value: &str) -> Option<String> {
    let up = value.trim().to_ascii_uppercase();
    if up.len() == 2 && up.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(up)
    } else {
        None
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn exchange_attempt(
    host: &str,
    port: u16,
    attempt: ZoneAttempt,
    request: &[u8],
    limit: Duration,
) -> Result<HttpResponse> {
    let fut = async {
        let mut stream = open_zone_stream(host, port, attempt).await?;
        stream.write_all(request).await.map_err(zone_io)?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = stream.read(&mut tmp).await.map_err(zone_io)?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_BODY + 8192 {
                return Err(SshError::Zones(
                    "Could not load zones. Check connection and try again. (response too large)"
                        .into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.starts_with(b"SSH-") {
                break;
            }
            if let Some(header_end) = find_header_end(&buf) {
                if let Some(len) = content_length(&buf[..header_end]) {
                    if buf.len() >= header_end + 4 + len {
                        break;
                    }
                }
            }
        }
        Ok::<_, SshError>(buf)
    };
    let buf = timeout(limit, fut).await.map_err(|_| {
        SshError::Zones("Could not load zones. Check connection and try again.".into())
    })??;
    split_http(&buf)
}

fn zone_io(err: std::io::Error) -> SshError {
    SshError::Zones(format!(
        "Could not load zones. Check connection and try again. ({err})"
    ))
}

async fn open_zone_stream(
    host: &str,
    port: u16,
    attempt: ZoneAttempt,
) -> Result<Box<dyn rt_tls::TransportIo>> {
    if !attempt.https {
        let stream = TcpStream::connect((host, port)).await.map_err(zone_io)?;
        let _ = stream.set_nodelay(true);
        return Ok(Box::new(stream));
    }
    let tls = TlsSettings {
        verify: attempt.verify,
        alpn: vec!["http/1.1".into()],
        ..TlsSettings::default()
    };
    let req = DialRequest::from_profile(host, port, Transport::Tls, tls);
    rt_tls::dial(&req).await.map_err(|err| {
        SshError::Zones(format!(
            "Could not load zones. Check connection and try again. ({err})"
        ))
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some(v) = line
            .split_once(':')
            .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.trim())
        {
            return v.parse().ok();
        }
    }
    None
}

fn split_http(buf: &[u8]) -> Result<HttpResponse> {
    if buf.starts_with(b"SSH-") {
        return Ok(HttpResponse {
            status: 0,
            body: buf.to_vec(),
        });
    }
    let header_end = find_header_end(buf).ok_or_else(|| {
        SshError::Zones("Could not load zones. Check connection and try again.".into())
    })?;
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| {
        SshError::Zones("Could not load zones. Check connection and try again.".into())
    })?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    if head_has_chunked(head) {
        body = decode_chunked(&body).unwrap_or(body);
    }
    Ok(HttpResponse { status, body })
}

fn head_has_chunked(head: &str) -> bool {
    head.lines().any(|line| {
        line.split_once(':')
            .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
            .map(|(_, v)| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    })
}

fn decode_chunked(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = input;
    loop {
        let nl = rest.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&rest[..nl]).ok()?.trim();
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[nl + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_body_is_zone_username_password() {
        let body = zone_command_body("alice", "s3cret");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["command"], "zone");
        assert_eq!(v["username"], "alice");
        assert_eq!(v["password"], "s3cret");
    }

    #[test]
    fn select_header_only_when_zone_set() {
        let auto = http_request(&ZoneHttpRequest {
            method: "GET",
            host: "entry.example",
            port: 8080,
            path: "/",
            content_type: None,
            zone_id: None,
            body: None,
            https: false,
        });
        assert!(auto.contains("User-Agent: smart_config/1.0\r\n"));
        assert!(auto.contains("Host: entry.example:8080\r\n"));
        assert!(!auto.contains("X-Zone-Id"));

        let forced = http_request(&ZoneHttpRequest {
            method: "GET",
            host: "entry.example",
            port: 80,
            path: "/",
            content_type: None,
            zone_id: Some("us"),
            body: None,
            https: false,
        });
        assert!(forced.contains("Host: entry.example\r\n"));
        assert!(forced.contains("X-Zone-Id: us\r\n"));

        let tls = http_request(&ZoneHttpRequest {
            method: "POST",
            host: "entry.example",
            port: 443,
            path: "/",
            content_type: None,
            zone_id: None,
            body: None,
            https: true,
        });
        assert!(tls.contains("Host: entry.example\r\n"));
        assert!(!tls.contains(":443"));
    }

    #[test]
    fn username_is_not_rewritten_for_zone() {
        assert_eq!(ssh_username_for_zone("alice", Some("de")), "alice");
        assert_eq!(ssh_username_for_zone("alice", None), "alice");
    }

    #[test]
    fn parses_object_and_string_zones() {
        let raw = br#"{
            "hash": "abc",
            "zones": [
                {"id": "us-east", "name": "United States", "iso": "us"},
                "de",
                {"code": "FR", "countryName": "France"}
            ]
        }"#;
        let list = parse_zone_list(raw).unwrap();
        assert_eq!(list.hash.as_deref(), Some("abc"));
        assert_eq!(list.zones.len(), 3);
        assert_eq!(list.zones[0].id, "us-east");
        assert_eq!(list.zones[0].iso.as_deref(), Some("US"));
        assert_eq!(list.zones[1].id, "de");
        assert_eq!(list.zones[1].iso.as_deref(), Some("DE"));
        assert_eq!(list.zones[2].id, "FR");
        assert_eq!(list.zones[2].name, "France");
    }

    #[test]
    fn accepts_response_wrapper() {
        let raw = br#"{"response":{"hash":"h1","zones":[{"id":"nl","isoCode":"NL","countryName":"Netherlands"}]}}"#;
        let list = parse_zone_list(raw).unwrap();
        assert_eq!(list.hash.as_deref(), Some("h1"));
        assert_eq!(list.zones[0].id, "nl");
        assert_eq!(list.zones[0].name, "Netherlands");
        assert_eq!(list.zones[0].iso.as_deref(), Some("NL"));
    }

    #[test]
    fn missing_zones_is_an_error() {
        let err = parse_zone_list(br#"{"hash":"x","ok":true}"#).unwrap_err();
        assert!(err.to_string().contains("Invalid response: no zones"));
    }

    #[test]
    fn ssh_banner_is_not_a_zone_list() {
        let err = parse_zone_list(b"SSH-2.0-OpenSSH_9.6").unwrap_err();
        assert!(err.to_string().contains("Could not load zones"));
    }
}
