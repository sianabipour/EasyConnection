//! Idle pool of already-handshaked transports to the same server.
//!
//! VLESS and Shadowsocks open a new tunnel stream per TCP flow. Prefilling TLS
//! (or TCP) sessions means the first browser/app request pays only the inner
//! protocol header, not a full TCP+TLS handshake.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::{dial, DialRequest, Result, TransportIo};

const MAX_IDLE_AGE: Duration = Duration::from_secs(25);

pub struct IdlePool {
    req: DialRequest,
    max_idle: usize,
    idle: Mutex<VecDeque<(Instant, Box<dyn TransportIo>)>>,
    filling: AtomicUsize,
}

impl IdlePool {
    pub fn new(req: DialRequest, max_idle: usize) -> Arc<Self> {
        Arc::new(Self {
            req,
            max_idle: max_idle.max(1),
            idle: Mutex::new(VecDeque::new()),
            filling: AtomicUsize::new(0),
        })
    }

    pub async fn take(self: &Arc<Self>) -> Result<Box<dyn TransportIo>> {
        {
            let mut q = self.idle.lock().await;
            let now = Instant::now();
            while let Some((at, stream)) = q.pop_front() {
                if now.saturating_duration_since(at) < MAX_IDLE_AGE {
                    self.spawn_fill();
                    return Ok(stream);
                }
            }
        }
        self.spawn_fill();
        dial(&self.req).await
    }

    pub async fn fill(self: &Arc<Self>, n: usize) {
        let mut tasks = Vec::new();
        for _ in 0..n {
            let pool = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                pool.fill_one().await;
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }

    fn spawn_fill(self: &Arc<Self>) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.fill_one().await;
        });
    }

    async fn fill_one(&self) {
        if self.idle.lock().await.len() >= self.max_idle {
            return;
        }
        let inflight = self.filling.fetch_add(1, Ordering::Relaxed);
        if inflight >= self.max_idle {
            self.filling.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        let result = dial(&self.req).await;
        self.filling.fetch_sub(1, Ordering::Relaxed);
        if let Ok(stream) = result {
            let mut q = self.idle.lock().await;
            if q.len() < self.max_idle {
                q.push_back((Instant::now(), stream));
            }
        }
    }
}
