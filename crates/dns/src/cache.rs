//! Short-lived cache of DNS messages so the first page/app burst does not
//! serialize on repeated identical lookups.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const DEFAULT_TTL: Duration = Duration::from_secs(45);
const MAX_ENTRIES: usize = 512;

pub struct DnsMessageCache {
    inner: Mutex<HashMap<Vec<u8>, (Instant, Vec<u8>)>>,
}

impl DnsMessageCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let key = &query[2..];
        let mut map = self.inner.lock();
        let (at, body) = map.get(key)?;
        if at.elapsed() > DEFAULT_TTL {
            map.remove(key);
            return None;
        }
        let mut out = body.clone();
        if out.len() >= 2 {
            out[0] = query[0];
            out[1] = query[1];
        }
        Some(out)
    }

    pub fn put(&self, query: &[u8], response: &[u8]) {
        if query.len() < 12 || response.len() < 12 {
            return;
        }
        let mut map = self.inner.lock();
        if map.len() >= MAX_ENTRIES {
            map.clear();
        }
        map.insert(query[2..].to_vec(), (Instant::now(), response.to_vec()));
    }
}

impl Default for DnsMessageCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_transaction_id() {
        let cache = DnsMessageCache::new();
        let mut q = vec![0x00, 0x01];
        q.extend_from_slice(&[0u8; 12]);
        let mut r = vec![0x00, 0x01];
        r.extend_from_slice(&[0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        cache.put(&q, &r);
        let mut q2 = q.clone();
        q2[0] = 0xAB;
        q2[1] = 0xCD;
        let hit = cache.get(&q2).expect("cached");
        assert_eq!(&hit[0..2], &[0xAB, 0xCD]);
        assert_eq!(&hit[2..4], &[0x81, 0x80]);
    }
}
