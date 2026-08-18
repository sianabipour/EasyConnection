//! Micro-benchmarks used by `scripts/bench.sh` (Phase 8).
//! CPU-only: no extra disk (SQLite WAL / vault writes) so CI and quota-limited
//! hosts still produce numbers.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use rt_config::{AuthMethod, ConnectionConfig};
use rt_nftables::render_table;
use rt_shadowsocks::evp_bytes_to_key;

fn timed(iters: u32, mut f: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed()
}

fn ns_per(total: Duration, iters: u32) -> f64 {
    total.as_secs_f64() * 1e9 / f64::from(iters)
}

fn main() -> anyhow::Result<()> {
    let mut cfg = ConnectionConfig::new_ssh("bench", "203.0.113.10", 22);
    cfg.username = Some("ops".into());
    cfg.authentication = AuthMethod::Password { secret: None };

    let ser_iters = 2_000;
    let ser = timed(ser_iters, || {
        let encoded = serde_json::to_string(&cfg).unwrap();
        let decoded: ConnectionConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.host, "203.0.113.10");
    });

    let kdf_iters = 5_000;
    let kdf = timed(kdf_iters, || {
        let k = evp_bytes_to_key(b"bench-password", 32);
        assert_eq!(k.len(), 32);
    });

    let render_iters = 2_000;
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let render = timed(render_iters, || {
        let script = render_table(&[ip], &[], true, 13450, 13453, true, 13451);
        assert!(script.contains("table inet easy"));
    });

    println!("Easy Connection micro-benchmarks");
    println!(
        "  config JSON roundtrip             {:>8.0} ns/op  ({} iters)",
        ns_per(ser, ser_iters),
        ser_iters
    );
    println!(
        "  shadowsocks evp_bytes_to_key      {:>8.0} ns/op  ({} iters)",
        ns_per(kdf, kdf_iters),
        kdf_iters
    );
    println!(
        "  nftables render_table             {:>8.0} ns/op  ({} iters)",
        ns_per(render, render_iters),
        render_iters
    );
    Ok(())
}
