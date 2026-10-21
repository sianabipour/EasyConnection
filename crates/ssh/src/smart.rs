//! RocketTunnel Smart Config GET/decrypt/SSH shim path.
//!
//! The response is an AES-256-GCM envelope: 12-byte nonce, ciphertext,
//! 16-byte tag. The compatibility key below is embedded in the reference
//! Android client's native library; it is not a user credential.

use std::io::Cursor;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rt_config::{AuthMethod, ConnectionConfig, ProtocolSettings, RocketSmartConfig};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::{Result, SshConnectOptions, SshError, SshSession};

const SMART_CONFIG_KEY: [u8; 32] = [
    115, 21, 66, 88, 89, 169, 231, 172, 80, 193, 91, 145, 10, 200, 80, 39, 25, 213, 15, 209, 178,
    103, 33, 217, 81, 134, 148, 19, 17, 134, 199, 88,
]; // APK compatibility key, not a user credential.
const MAX_SHIM_PAYLOAD: usize = 16 * 1024;
const MAX_SHIM_RESPONSE: usize = 64 * 1024;

#[derive(Deserialize)]
struct RawEndpoint {
    #[serde(rename = "type")]
    kind: String,
    hostname: String,
    port: u16,
    username: String,
    auth_method: String,
    auth: String,
    params: RawParams,
}

#[derive(Deserialize)]
struct RawParams {
    shim: RawShim,
}

#[derive(Deserialize)]
struct RawShim {
    enabled: bool,
    tokens: RawTokens,
    states: RawStates,
}

#[derive(Deserialize)]
struct RawTokens {
    host_port: String,
    ua: String,
}

#[derive(Deserialize)]
struct RawStates {
    tx: Vec<RawAction>,
    rx: Vec<RawAction>,
}

#[derive(Deserialize)]
struct RawAction {
    action: String,
    data: String,
    #[serde(default)]
    max_len: Option<usize>,
    #[serde(default)]
    flags: Vec<String>,
}

impl Drop for RawEndpoint {
    fn drop(&mut self) {
        self.hostname.zeroize();
        self.username.zeroize();
        self.auth.zeroize();
        self.params.shim.tokens.host_port.zeroize();
        self.params.shim.tokens.ua.zeroize();
        for state in self
            .params
            .shim
            .states
            .tx
            .iter_mut()
            .chain(self.params.shim.states.rx.iter_mut())
        {
            state.data.zeroize();
        }
    }
}

struct SmartEndpoint {
    host: String,
    port: u16,
    username: String,
    password: Zeroizing<String>,
    payload: Zeroizing<Vec<u8>>,
    marker: Vec<u8>,
    max_response: usize,
}

fn smart_error(message: &str) -> SshError {
    SshError::Zones(format!("Smart Config: {message}"))
}

fn decrypt_response(encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !(28..=1024 * 1024).contains(&encrypted.len()) {
        return Err(smart_error("invalid encrypted response length"));
    }
    let cipher = Aes256Gcm::new_from_slice(&SMART_CONFIG_KEY)
        .map_err(|_| smart_error("cipher initialization failed"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| smart_error("response authentication failed"))?;
    Ok(Zeroizing::new(plain))
}

fn render_tokens(template: &str, tokens: &RawTokens) -> Result<Vec<u8>> {
    let rendered = template
        .replace("[host_port]", &tokens.host_port)
        .replace("[ua]", &tokens.ua)
        .replace("[crlf]", "\r\n");
    if rendered.len() > MAX_SHIM_PAYLOAD || rendered.contains('[') || rendered.contains(']') {
        return Err(smart_error("unsupported shim token or payload length"));
    }
    Ok(rendered.into_bytes())
}

fn parse_endpoint(plain: &[u8], smart: &RocketSmartConfig) -> Result<SmartEndpoint> {
    let mut patches: Value =
        serde_json::from_slice(plain).map_err(|_| smart_error("invalid decrypted JSON patch"))?;
    let items = patches
        .as_array_mut()
        .ok_or_else(|| smart_error("expected JSON patch array"))?;
    let endpoint_value = items
        .iter_mut()
        .rev()
        .find(|item| {
            item.get("op").and_then(Value::as_str) == Some("merge")
                && item.pointer("/value/type").and_then(Value::as_str) == Some("ssh_darktunnel")
        })
        .and_then(|item| item.get_mut("value"))
        .map(Value::take)
        .ok_or_else(|| smart_error("no supported SSH tunnel in response"))?;
    let mut raw: RawEndpoint = serde_json::from_value(endpoint_value)
        .map_err(|_| smart_error("invalid SSH tunnel parameters"))?;
    // The observed Smart Config patch carries these exact literal markers.
    // The native client resolves them from the imported /i/ link before SSH
    // authentication. Sending the markers verbatim is rejected by the server.
    if raw.username == "<<username>>" {
        raw.username = smart.username.clone();
    }
    if raw.auth == "<<password>>" {
        raw.auth = smart.password.clone();
    }
    if raw.kind != "ssh_darktunnel"
        || raw.auth_method != "password"
        || raw.hostname.is_empty()
        || raw.hostname.len() > 253
        || raw
            .hostname
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
        || raw.port == 0
        || raw.username.is_empty()
        || raw.username.len() > 255
        || raw.auth.is_empty()
        || raw.auth.len() > 4096
        || !raw.params.shim.enabled
    {
        return Err(smart_error("unsupported SSH tunnel parameters"));
    }
    let tx = raw
        .params
        .shim
        .states
        .tx
        .first()
        .filter(|state| state.action == "payload")
        .ok_or_else(|| smart_error("unsupported shim transmit state"))?;
    let rx = raw
        .params
        .shim
        .states
        .rx
        .first()
        .filter(|state| state.action == "match_until" && state.flags.iter().any(|f| f == "skip"))
        .ok_or_else(|| smart_error("unsupported shim receive state"))?;
    let payload = Zeroizing::new(render_tokens(&tx.data, &raw.params.shim.tokens)?);
    let marker = render_tokens(&rx.data, &raw.params.shim.tokens)?;
    if marker.is_empty() || marker.len() > 128 || !marker.starts_with(b"SSH-") {
        return Err(smart_error("unsupported SSH shim marker"));
    }
    let max_response = rx
        .max_len
        .unwrap_or(MAX_SHIM_RESPONSE)
        .min(MAX_SHIM_RESPONSE);
    if max_response < marker.len() {
        return Err(smart_error("invalid shim response limit"));
    }
    Ok(SmartEndpoint {
        host: std::mem::take(&mut raw.hostname),
        port: raw.port,
        username: std::mem::take(&mut raw.username),
        password: Zeroizing::new(std::mem::take(&mut raw.auth)),
        payload,
        marker,
        max_response,
    })
}

async fn fetch_endpoint(smart: &RocketSmartConfig, zone_id: Option<&str>) -> Result<SmartEndpoint> {
    for (host, https) in smart.zone_hosts() {
        match crate::zones::get_smart_config_body(
            &host.host,
            host.port,
            &smart.path,
            https,
            zone_id,
        )
        .await
        {
            Ok(body) => {
                let body = Zeroizing::new(body);
                let plain = decrypt_response(&body)?;
                return parse_endpoint(&plain, smart);
            }
            Err(_) => tracing::debug!("Smart Config GET host did not answer"),
        }
    }
    Err(smart_error("could not fetch selected tunnel configuration"))
}

struct PrefixedTcp {
    inner: TcpStream,
    prefix: Cursor<Vec<u8>>,
}

impl AsyncRead for PrefixedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = self.prefix.get_ref().len() - self.prefix.position() as usize;
        if remaining > 0 {
            let count = remaining.min(buf.remaining());
            let start = self.prefix.position() as usize;
            buf.put_slice(&self.prefix.get_ref()[start..start + count]);
            self.prefix.set_position((start + count) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn open_shim(endpoint: &SmartEndpoint) -> Result<Box<dyn rt_tls::TransportIo>> {
    let task = async {
        let mut tcp = TcpStream::connect((&*endpoint.host, endpoint.port))
            .await
            .map_err(|_| smart_error("could not reach selected SSH endpoint"))?;
        let _ = tcp.set_nodelay(true);
        tcp.write_all(&endpoint.payload)
            .await
            .map_err(|_| smart_error("could not send SSH shim"))?;
        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tcp
                .read(&mut chunk)
                .await
                .map_err(|_| smart_error("could not read SSH shim response"))?;
            if n == 0 || response.len() + n > endpoint.max_response {
                return Err(smart_error("SSH shim did not return an SSH banner"));
            }
            response.extend_from_slice(&chunk[..n]);
            if let Some(at) = response
                .windows(endpoint.marker.len())
                .position(|window| window == endpoint.marker)
            {
                // The reference's `match_until` + `skip` discards the HTTP
                // prelude but retains the matched SSH marker for russh.
                return Ok(Box::new(PrefixedTcp {
                    inner: tcp,
                    prefix: Cursor::new(response.split_off(at)),
                }) as Box<dyn rt_tls::TransportIo>);
            }
        }
    };
    timeout(Duration::from_secs(15), task)
        .await
        .map_err(|_| smart_error("SSH shim timed out"))?
}

pub async fn connect_smart_profile(
    profile: &ConnectionConfig,
    link: &str,
    known_hosts: Option<PathBuf>,
) -> Result<SshSession> {
    let smart = rt_config::decode_rocket_smart_link(link)
        .map_err(|_| smart_error("saved import link is invalid"))?;
    let endpoint = fetch_endpoint(&smart, profile.selected_zone.as_deref()).await?;
    let stream = open_shim(&endpoint).await?;
    let (keepalive_secs, connect_timeout_secs, host_key_policy) = match &profile.settings {
        ProtocolSettings::Ssh {
            keepalive_secs,
            connect_timeout_secs,
            host_key_policy,
        } => (*keepalive_secs, *connect_timeout_secs, *host_key_policy),
        _ => return Err(smart_error("invalid SSH settings")),
    };
    let opts = SshConnectOptions {
        host: endpoint.host.clone(),
        port: endpoint.port,
        username: endpoint.username.clone(),
        auth: AuthMethod::None,
        keepalive_secs,
        connect_timeout_secs,
        host_key_policy,
        known_hosts_path: known_hosts,
        zone_id: None,
    };
    SshSession::connect_over_transport_password(opts, endpoint.password.as_str(), stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Payload;

    #[test]
    fn renders_observed_shim_tokens() {
        let tokens = RawTokens {
            host_port: "entry.example:80".into(),
            ua: "test-agent".into(),
        };
        assert_eq!(
            render_tokens(
                "POST [host_port] HTTP/1.1[crlf]User-Agent: [ua][crlf]",
                &tokens
            )
            .unwrap(),
            b"POST entry.example:80 HTTP/1.1\r\nUser-Agent: test-agent\r\n"
        );
    }

    #[test]
    fn rejects_bad_tag_without_exposing_plaintext() {
        assert!(decrypt_response(&[0u8; 28]).is_err());
    }

    #[test]
    fn decrypts_and_parses_synthetic_ssh_patch() {
        let plain = serde_json::json!([
            {"op": "merge", "path": "/params", "value": {}},
            {"op": "merge", "path": "/", "value": {
                "type": "ssh_darktunnel",
                "hostname": "example.invalid",
                "port": 80,
                "username": "test-user",
                "auth_method": "password",
                "auth": "synthetic-secret",
                "params": {"shim": {
                    "enabled": true,
                    "tokens": {"host_port": "example.invalid:80", "ua": "test-agent"},
                    "states": {
                        "tx": [{"action": "payload", "data": "GET [host_port] HTTP/1.1[crlf]User-Agent: [ua][crlf][crlf]"}],
                        "rx": [{"action": "match_until", "data": "SSH-2.0-", "flags": ["skip"], "max_len": 8192}]
                    }
                }}
            }}
        ]);
        let nonce = [7u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&SMART_CONFIG_KEY).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &serde_json::to_vec(&plain).unwrap(),
                    aad: &[],
                },
            )
            .unwrap();
        let mut body = nonce.to_vec();
        body.extend_from_slice(&encrypted);
        let decrypted = decrypt_response(&body).unwrap();
        let smart = RocketSmartConfig {
            username: "link-user".into(),
            password: "link-secret".into(),
            path: "/".into(),
            hosts: Vec::new(),
        };
        let endpoint = parse_endpoint(&decrypted, &smart).unwrap();
        assert_eq!(endpoint.host, "example.invalid");
        assert_eq!(endpoint.port, 80);
        assert_eq!(endpoint.username, "test-user");
        assert_eq!(endpoint.password.as_str(), "synthetic-secret");
        assert_eq!(endpoint.marker, b"SSH-2.0-");
        assert_eq!(endpoint.max_response, 8192);
        assert_eq!(
            endpoint.payload.as_slice(),
            b"GET example.invalid:80 HTTP/1.1\r\nUser-Agent: test-agent\r\n\r\n"
        );
    }

    #[test]
    fn substitutes_only_observed_smart_auth_markers() {
        let smart = RocketSmartConfig {
            username: "link-user".into(),
            password: "link-secret".into(),
            path: "/".into(),
            hosts: Vec::new(),
        };
        let plain = serde_json::to_vec(&serde_json::json!([{
            "op": "merge", "path": "/", "value": {
                "type": "ssh_darktunnel", "hostname": "example.invalid", "port": 80,
                "username": "<<username>>", "auth_method": "password", "auth": "<<password>>",
                "params": {"shim": {"enabled": true,
                    "tokens": {"host_port": "example.invalid:80", "ua": "test-agent"},
                    "states": {"tx": [{"action": "payload", "data": "[crlf]"}],
                               "rx": [{"action": "match_until", "data": "SSH-2.0-", "flags": ["skip"]}]}
                }}
            }
        }])).unwrap();
        let endpoint = parse_endpoint(&plain, &smart).unwrap();
        assert_eq!(endpoint.username, "link-user");
        assert_eq!(endpoint.password.as_str(), "link-secret");
    }
}
