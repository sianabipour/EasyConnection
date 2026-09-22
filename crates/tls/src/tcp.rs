//! Cached TCP connect with TCP_NODELAY. Reused by every transport so each
//! VLESS/SS flow does not pay a fresh DNS lookup for the same server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::{Result, TransportError};

const CACHE_TTL: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

static RESOLVE_CACHE: LazyLock<Mutex<HashMap<String, (Instant, Vec<SocketAddr>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve_cached(host, port).await?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addrs[..]))
        .await
        .map_err(|_| TransportError::Other(format!("TCP connect to {host}:{port} timed out")))?
        .map_err(|e| TransportError::Io(e))?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

async fn resolve_cached(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let key = format!("{host}:{port}");
    if let Some(addrs) = cached(&key) {
        return Ok(addrs);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| TransportError::Other(format!("resolve {host}:{port}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(TransportError::Other(format!("no addresses for {host}")));
    }
    if let Ok(mut cache) = RESOLVE_CACHE.lock() {
        cache.insert(key, (Instant::now(), addrs.clone()));
    }
    Ok(addrs)
}

fn cached(key: &str) -> Option<Vec<SocketAddr>> {
    let mut cache = RESOLVE_CACHE.lock().ok()?;
    let (at, addrs) = cache.get(key)?;
    if at.elapsed() > CACHE_TTL {
        cache.remove(key);
        return None;
    }
    Some(addrs.clone())
}
