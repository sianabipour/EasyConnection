import { useEffect, useState } from "react";
import { useConnection } from "../hooks/useConnection";

function formatRate(bps: number) {
  if (bps < 1024) return `${bps.toFixed(0)} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${(bps / (1024 * 1024)).toFixed(1)} MB/s`;
}

function tunnelLabel(snapshot: { routing_mode: string; tun_name?: string | null }) {
  if (snapshot.tun_name) return "VPN";
  if (snapshot.routing_mode.includes("full")) return "VPN (starting)";
  if (snapshot.routing_mode.includes("split")) return "Split";
  return "Proxy";
}

export function HomePage() {
  const { snapshot, busy, error, disconnect, profiles, connect } = useConnection();
  const connected = snapshot.state === "connected" || snapshot.state === "degraded";
  const primary = profiles[0];
  const [downHistory, setDownHistory] = useState<number[]>(() => Array(24).fill(0));
  const [upHistory, setUpHistory] = useState<number[]>(() => Array(24).fill(0));

  useEffect(() => {
    setDownHistory((prev) => [...prev.slice(1), snapshot.stats.rate_down_bps]);
    setUpHistory((prev) => [...prev.slice(1), snapshot.stats.rate_up_bps]);
  }, [snapshot.stats.rate_down_bps, snapshot.stats.rate_up_bps]);

  return (
    <div className="mx-auto flex max-w-xl flex-col items-center gap-8 pt-6 text-center">
      <div>
        <h1 className="text-4xl font-semibold tracking-tight text-white md:text-5xl">Easy Connection</h1>
        <p className="mt-2 text-[var(--color-muted)]">Native Linux tunnel &amp; proxy client</p>
      </div>

      <div className="w-full rounded-2xl border border-[var(--color-line)] bg-[color:rgb(18_26_36_/_0.9)] px-8 py-10 shadow-[0_20px_60px_rgba(0,0,0,0.35)]">
        <div className="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--color-muted)]">Status</div>
        <div
          className={[
            "text-3xl font-semibold",
            connected ? "text-[var(--color-ok)]" : snapshot.state === "error" ? "text-[var(--color-danger)]" : "text-white",
          ].join(" ")}
        >
          ● {snapshot.state.replaceAll("_", " ").toUpperCase()}
        </div>

        <div className="mt-3 text-lg text-[var(--color-muted)]">
          {snapshot.profile_name || snapshot.server_label || "No active profile"}
          {snapshot.latency_ms != null ? ` — ${snapshot.latency_ms} ms` : ""}
        </div>

        <div className="mt-8 flex justify-center">
          {connected ? (
            <button
              type="button"
              disabled={busy}
              onClick={() => void disconnect()}
              className="rounded-lg bg-[var(--color-danger)] px-10 py-3 text-sm font-semibold uppercase tracking-wide text-white transition hover:brightness-110 disabled:opacity-50"
            >
              Disconnect
            </button>
          ) : (
            <button
              type="button"
              disabled={busy || !primary}
              onClick={() => primary && void connect(primary.id)}
              className="rounded-lg bg-[var(--color-accent)] px-10 py-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-ink)] transition hover:brightness-110 disabled:opacity-50"
            >
              {primary ? `Connect ${primary.name}` : "Add a server first"}
            </button>
          )}
        </div>

        <div className="mt-8">
          <Sparkline down={downHistory} up={upHistory} />
        </div>

        <div className="mt-6 grid grid-cols-2 gap-4 text-left text-sm">
          <Stat label="Down" value={formatRate(snapshot.stats.rate_down_bps)} />
          <Stat label="Up" value={formatRate(snapshot.stats.rate_up_bps)} />
          <Stat label="Tunnel" value={connected ? tunnelLabel(snapshot) : "—"} />
          <Stat label="DNS" value={snapshot.dns_status} />
          <Stat label="IPv6" value={snapshot.ipv6 ? "Enabled" : "Disabled"} />
          <Stat label="UDPGW" value={snapshot.udpgw_status} />
        </div>

        {snapshot.socks_endpoint && (
          <div className="mt-6 rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-3 text-left font-mono text-xs text-[var(--color-accent)]">
            {snapshot.socks_endpoint}
          </div>
        )}

        {snapshot.udp_note && connected && (
          <p className="mt-4 text-left text-xs text-[var(--color-muted)]">{snapshot.udp_note}</p>
        )}
        {connected && snapshot.tun_name && (
          <p className="mt-3 text-left text-xs text-[var(--color-muted)]">
            System TCP is intercepted — do not set a browser proxy. Test with{" "}
            <span className="font-mono text-[var(--color-accent)]">curl https://ifconfig.me</span>.
            UDP/QUIC needs UDPGW on this profile and badvpn-udpgw on the server.
          </p>
        )}

        {(error || snapshot.last_error_detail) && (
          <pre className="mt-6 whitespace-pre-wrap rounded-lg border border-[color:rgb(239_107_107_/_0.35)] bg-[color:rgb(239_107_107_/_0.08)] px-4 py-3 text-left text-xs text-[var(--color-danger)]">
            {error || snapshot.last_error_detail}
          </pre>
        )}
      </div>
    </div>
  );
}

function Sparkline({ down, up }: { down: number[]; up: number[] }) {
  const w = 320;
  const h = 56;
  const max = Math.max(1, ...down, ...up);
  const toPoints = (values: number[]) =>
    values
      .map((v, i) => {
        const x = values.length <= 1 ? 0 : (i / (values.length - 1)) * w;
        const y = h - 4 - (v / max) * (h - 8);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");

  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} className="h-14 w-full" aria-hidden>
        <polyline fill="none" stroke="rgb(90 200 250)" strokeWidth="2" points={toPoints(down)} />
        <polyline fill="none" stroke="rgb(140 160 180)" strokeWidth="1.5" points={toPoints(up)} />
      </svg>
      <div className="mt-1 flex justify-between text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
        <span>Down / up (live)</span>
        <span>last ~35s</span>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2">
      <div className="text-[11px] uppercase tracking-wider text-[var(--color-muted)]">{label}</div>
      <div className="mt-1 font-medium text-white">{value}</div>
    </div>
  );
}
