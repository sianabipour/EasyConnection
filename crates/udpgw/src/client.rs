//! Multiplexed UDPGW client over a reliable stream (SSH `direct-tcpip`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::proto::{decode_body, encode_frame, UdpgwPacket, FLAG_DNS, FLAG_KEEPALIVE};
use crate::{Result, UdpgwError};

const KEEPALIVE_SECS: u64 = 10;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME: usize = 65535;

enum Flow {
    Udp { from: SocketAddr },
    Dns { tx: oneshot::Sender<Vec<u8>> },
}

struct Inner {
    writer: Mutex<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>,
    next_conid: AtomicU16,
    flows: Mutex<HashMap<u16, Flow>>,
    keys: Mutex<HashMap<(SocketAddr, SocketAddr), u16>>,
}

/// Handle used by the tunnel engine to send UDP / DNS through UDPGW.
#[derive(Clone)]
pub struct UdpgwHandle {
    inner: Arc<Inner>,
}

impl UdpgwHandle {
    pub async fn send_udp(
        &self,
        from: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        dns: bool,
    ) -> Result<()> {
        let conid = {
            let mut keys = self.inner.keys.lock().await;
            if let Some(id) = keys.get(&(from, dest)).copied() {
                id
            } else {
                let id = self.alloc_conid().await;
                keys.insert((from, dest), id);
                self.inner.flows.lock().await.insert(id, Flow::Udp { from });
                id
            }
        };
        let pkt = UdpgwPacket::data(conid, dest, payload.to_vec(), dns, false);
        self.write_packet(&pkt).await
    }

    pub async fn query_dns(&self, dest: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let conid = self.alloc_conid().await;
        let (tx, rx) = oneshot::channel();
        self.inner
            .flows
            .lock()
            .await
            .insert(conid, Flow::Dns { tx });
        let pkt = UdpgwPacket::data(conid, dest, query.to_vec(), true, false);
        if let Err(e) = self.write_packet(&pkt).await {
            self.inner.flows.lock().await.remove(&conid);
            return Err(e);
        }
        match tokio::time::timeout(DNS_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(UdpgwError::Closed),
            Err(_) => {
                self.inner.flows.lock().await.remove(&conid);
                Err(UdpgwError::Timeout)
            }
        }
    }

    async fn alloc_conid(&self) -> u16 {
        self.inner.next_conid.fetch_add(1, Ordering::Relaxed)
    }

    async fn write_packet(&self, pkt: &UdpgwPacket) -> Result<()> {
        let frame = encode_frame(pkt)?;
        let mut w = self.inner.writer.lock().await;
        w.write_all(&frame).await?;
        w.flush().await?;
        Ok(())
    }
}

/// Run the UDPGW client. Replies for UDP flows are sent on `replies`.
pub async fn run_udpgw<S>(
    stream: S,
    replies: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    stop: CancellationToken,
) -> Result<UdpgwHandle>
where
    S: IoStream + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let inner = Arc::new(Inner {
        writer: Mutex::new(Box::new(writer)),
        next_conid: AtomicU16::new(1),
        flows: Mutex::new(HashMap::new()),
        keys: Mutex::new(HashMap::new()),
    });
    let handle = UdpgwHandle {
        inner: Arc::clone(&inner),
    };

    let stop_ka = stop.clone();
    let ka = handle.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_ka.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(KEEPALIVE_SECS)) => {
                    let pkt = UdpgwPacket::keepalive(0);
                    if let Err(e) = ka.write_packet(&pkt).await {
                        debug!(error = %e, "UDPGW keepalive failed");
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        if let Err(e) = read_loop(reader, inner, replies, stop).await {
            warn!(error = %e, "UDPGW reader exited");
        }
    });

    Ok(handle)
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    inner: Arc<Inner>,
    replies: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        let mut hdr = [0u8; 2];
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            res = reader.read_exact(&mut hdr) => { res?; }
        }
        let len = u16::from_le_bytes(hdr) as usize;
        if len == 0 || len > MAX_FRAME {
            return Err(UdpgwError::Packet(format!("invalid frame length {len}")));
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        let pkt = decode_body(&body)?;
        if pkt.flags & FLAG_KEEPALIVE != 0 {
            continue;
        }
        let mut flows = inner.flows.lock().await;
        match flows.remove(&pkt.conid) {
            Some(Flow::Dns { tx }) => {
                let _ = tx.send(pkt.payload);
            }
            Some(Flow::Udp { from }) => {
                // Keep the flow for further datagrams on this conid.
                flows.insert(pkt.conid, Flow::Udp { from });
                drop(flows);
                if replies.send((from, pkt.payload)).await.is_err() {
                    return Ok(());
                }
            }
            None => {
                debug!(
                    conid = pkt.conid,
                    dns = pkt.flags & FLAG_DNS != 0,
                    "UDPGW reply for unknown conid"
                );
            }
        }
    }
}

/// Marker so the client can own a boxed SSH/TCP stream.
pub trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}
