use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::http_connect::handle_http_connect;
use crate::socks4::handle_socks4;
use crate::socks5::{handle_socks5, Socks5Auth};
use crate::upstream::UpstreamConnector;
use crate::{Result, SocksError};

#[derive(Debug, Default)]
pub struct ProxyStats {
    pub accepted: AtomicU64,
    pub active: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

pub struct ProxyHandles {
    pub socks_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub stats: Arc<ProxyStats>,
    shutdown: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

impl ProxyHandles {
    pub async fn stop(self) {
        self.shutdown.notify_waiters();
        for t in self.tasks {
            let _ = t.await;
        }
    }

    pub fn socks_endpoint(&self) -> String {
        format!("{}", self.socks_addr)
    }

    pub fn http_endpoint(&self) -> String {
        format!("{}", self.http_addr)
    }
}

pub struct ProxyServer;

impl ProxyServer {
    pub async fn start(
        listen: &str,
        socks_port: u16,
        http_port: u16,
        upstream: Arc<dyn UpstreamConnector>,
        auth: Socks5Auth,
    ) -> Result<ProxyHandles> {
        let socks_listener = TcpListener::bind(format!("{listen}:{socks_port}")).await?;
        let http_listener = TcpListener::bind(format!("{listen}:{http_port}")).await?;
        let socks_addr = socks_listener.local_addr()?;
        let http_addr = http_listener.local_addr()?;
        let stats = Arc::new(ProxyStats::default());
        let shutdown = Arc::new(Notify::new());
        let auth = Arc::new(auth);

        tracing::info!(%socks_addr, %http_addr, "local proxy listeners started");

        let mut tasks = Vec::new();

        {
            let upstream = Arc::clone(&upstream);
            let stats = Arc::clone(&stats);
            let shutdown = Arc::clone(&shutdown);
            let auth = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.notified() => break,
                        accepted = socks_listener.accept() => {
                            match accepted {
                                Ok((stream, peer)) => {
                                    crate::set_nodelay(&stream);
                                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                                    stats.active.fetch_add(1, Ordering::Relaxed);
                                    let upstream = Arc::clone(&upstream);
                                    let stats = Arc::clone(&stats);
                                    let stats_c = Arc::clone(&stats);
                                    let auth = Arc::clone(&auth);
                                    // Spawn immediately so channel opens run in parallel,
                                    // not serialized behind other SOCKS handshakes.
                                    tokio::spawn(async move {
                                        if let Err(e) = dispatch_socks(
                                            stream,
                                            upstream.as_ref(),
                                            auth.as_ref(),
                                            Some(stats_c),
                                        )
                                        .await
                                        {
                                            tracing::debug!(%peer, error = %e, "socks session ended");
                                        }
                                        stats.active.fetch_sub(1, Ordering::Relaxed);
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "socks accept failed");
                                    break;
                                }
                            }
                        }
                    }
                }
            }));
        }

        {
            let upstream = Arc::clone(&upstream);
            let stats = Arc::clone(&stats);
            let shutdown = Arc::clone(&shutdown);
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.notified() => break,
                        accepted = http_listener.accept() => {
                            match accepted {
                                Ok((stream, peer)) => {
                                    crate::set_nodelay(&stream);
                                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                                    stats.active.fetch_add(1, Ordering::Relaxed);
                                    let upstream = Arc::clone(&upstream);
                                    let stats = Arc::clone(&stats);
                                    let stats_c = Arc::clone(&stats);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_http_connect(
                                            stream,
                                            upstream.as_ref(),
                                            Some(stats_c),
                                        )
                                        .await
                                        {
                                            tracing::debug!(%peer, error = %e, "http connect ended");
                                        }
                                        stats.active.fetch_sub(1, Ordering::Relaxed);
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "http accept failed");
                                    break;
                                }
                            }
                        }
                    }
                }
            }));
        }

        Ok(ProxyHandles {
            socks_addr,
            http_addr,
            stats,
            shutdown,
            tasks,
        })
    }
}

async fn dispatch_socks(
    mut stream: TcpStream,
    upstream: &dyn UpstreamConnector,
    auth: &Socks5Auth,
    stats: Option<Arc<ProxyStats>>,
) -> Result<()> {
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    // peek by reading first byte then we need to prepend — use chain
    match ver[0] {
        0x05 => {
            // Re-feed version byte via a tiny prepend buffer
            let mut prefixed = VersionPrefixed::new(ver[0], stream);
            handle_socks5(&mut prefixed, upstream, auth, stats).await
        }
        0x04 => {
            let mut prefixed = VersionPrefixed::new(ver[0], stream);
            handle_socks4(&mut prefixed, upstream, stats).await
        }
        other => Err(SocksError::Protocol(format!(
            "unsupported proxy version {other:#x}"
        ))),
    }
}

/// Re-injects the already-read version byte into the stream.
struct VersionPrefixed {
    first: Option<u8>,
    inner: TcpStream,
}

impl VersionPrefixed {
    fn new(first: u8, inner: TcpStream) -> Self {
        Self {
            first: Some(first),
            inner,
        }
    }
}

impl tokio::io::AsyncRead for VersionPrefixed {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(b) = self.first.take() {
            if buf.remaining() > 0 {
                buf.put_slice(&[b]);
                return std::task::Poll::Ready(Ok(()));
            }
            self.first = Some(b);
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for VersionPrefixed {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
