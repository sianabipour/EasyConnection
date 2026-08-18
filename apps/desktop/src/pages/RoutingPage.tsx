import { useState } from "react";
import { useConnection } from "../hooks/useConnection";
import { api } from "../lib/api";
import type { LeakReport, ProbeResult } from "../lib/types";

export function RoutingPage() {
  const { snapshot, profiles } = useConnection();
  const active = profiles.find((p) => p.id === snapshot.profile_id);
  const [report, setReport] = useState<LeakReport | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [probeHost, setProbeHost] = useState("ifconfig.me");
  const [probePort, setProbePort] = useState("443");
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [trace, setTrace] = useState<ProbeResult | null>(null);
  const [probing, setProbing] = useState(false);

  async function runLeakCheck() {
    setChecking(true);
    setError(null);
    try {
      setReport(await api.leakReport());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChecking(false);
    }
  }

  async function runTcpProbe() {
    setProbing(true);
    setError(null);
    try {
      setProbe(await api.tcpProbe(probeHost, Number(probePort) || 443));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbing(false);
    }
  }

  async function runTraceroute() {
    setProbing(true);
    setError(null);
    try {
      setTrace(await api.traceroute(probeHost));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbing(false);
    }
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold">Routing</h1>
      <p className="mt-1 text-sm text-[var(--color-muted)]">
        System-wide VPN uses TUN <code className="text-[var(--color-accent)]">easy0</code> and nftables table{" "}
        <code className="text-[var(--color-accent)]">inet easy</code>. The GUI never edits firewall rules itself.
      </p>

      <div className="mt-6 space-y-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm">
        <Row k="Mode" v={snapshot.routing_mode.replaceAll("_", " ")} />
        <Row k="TUN" v={snapshot.tun_name || "not attached"} />
        <Row k="Helper" v={snapshot.helper_ok ? "session active" : "idle"} />
        <Row k="Kill switch" v={snapshot.kill_switch ? "armed" : "off"} />
        <Row k="DNS" v={snapshot.dns_status} />
        <Row k="IPv6" v={snapshot.ipv6 ? "enabled" : "disabled"} />
        <Row k="UDPGW" v={snapshot.udpgw_status} />
        <Row k="Profile" v={active ? `${active.name} (${active.routing_mode})` : "—"} />
        {snapshot.udp_note && (
          <p className="pt-2 text-xs text-[var(--color-muted)]">{snapshot.udp_note}</p>
        )}
      </div>

      <div className="mt-6 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm">
        <div className="flex items-center justify-between gap-3">
          <p className="font-medium text-white">DNS / IPv6 leak check</p>
          <button
            type="button"
            disabled={checking}
            onClick={() => void runLeakCheck()}
            className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-ink)] disabled:opacity-50"
          >
            {checking ? "Checking…" : "Run check"}
          </button>
        </div>
        <p className="mt-2 text-xs text-[var(--color-muted)]">
          Reads easy0, table inet easy, and resolvectl. Connect a full-tunnel profile first for a useful report.
        </p>
        {error && <p className="mt-3 text-sm text-[var(--color-danger)]">{error}</p>}
        {report && (
          <div className="mt-3 space-y-2 text-sm">
            <Row k="TUN present" v={report.tun_present ? "yes" : "no"} />
            <Row k="nft table" v={report.nft_table_present ? "yes" : "no"} />
            <Row
              k="Link DNS"
              v={report.resolved_link_dns.length ? report.resolved_link_dns.join(", ") : "none"}
            />
            <Row k="Tunnel DNS" v={report.using_tunnel_dns ? "yes" : "no"} />
            <Row k="TUN IPv6 ULA" v={report.ipv6_enabled_on_tun ? "yes" : "no"} />
            <Row
              k="Global IPv6"
              v={report.ipv6_global_addrs.length ? report.ipv6_global_addrs.join(", ") : "none"}
            />
            <Row k="UDP redirect" v={report.udp_redirected ? "yes (UDPGW intercept)" : "no (UDP rejected)"} />
            <ul className="mt-2 list-disc space-y-1 pl-5 text-[var(--color-muted)]">
              {report.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="mt-6 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm">
        <p className="font-medium text-white">TCP probe / traceroute</p>
        <p className="mt-2 text-xs text-[var(--color-muted)]">
          ICMP ping is not on the TCP intercept path. Probe uses a TCP connect; traceroute uses{" "}
          <code className="text-[var(--color-accent)]">traceroute -T</code> when installed.
        </p>
        <div className="mt-3 grid grid-cols-[1fr_5.5rem] gap-2">
          <input
            className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel-2)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
            value={probeHost}
            onChange={(e) => setProbeHost(e.target.value)}
            placeholder="host"
          />
          <input
            className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel-2)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
            value={probePort}
            onChange={(e) => setProbePort(e.target.value)}
            placeholder="443"
          />
        </div>
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            disabled={probing || !probeHost}
            onClick={() => void runTcpProbe()}
            className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-ink)] disabled:opacity-50"
          >
            TCP probe
          </button>
          <button
            type="button"
            disabled={probing || !probeHost}
            onClick={() => void runTraceroute()}
            className="rounded-lg border border-[var(--color-line)] px-3 py-1.5 text-xs text-[var(--color-muted)] hover:text-white disabled:opacity-50"
          >
            Traceroute
          </button>
        </div>
        {probe && <ProbeBlock title="TCP probe" result={probe} />}
        {trace && <ProbeBlock title="Traceroute" result={trace} />}
      </div>

      <div className="mt-6 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-white">What this phase does</p>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>Proxy Only: local SOCKS5 + HTTP CONNECT. System DNS is left alone.</li>
          <li>Full Tunnel: TCP via nft redirect, DNS via systemd-resolved on easy0 plus DNS-over-TCP.</li>
          <li>Split: extra CIDR/domain bypass at connect time. Process/cgroup split is not implemented.</li>
          <li>IPv6 off: public IPv6 is rejected so apps fall back to IPv4. IPv6 on: dual-stack intercept + TUN ULA.</li>
          <li>UDPGW: enable on an SSH profile and run badvpn-udpgw on the server. Status is honest — not every UDP app works.</li>
          <li>Disconnect restores routes, nftables, resolvectl, and the TUN device.</li>
        </ul>
      </div>
    </div>
  );
}

function ProbeBlock({ title, result }: { title: string; result: ProbeResult }) {
  return (
    <div className="mt-3 rounded-lg border border-[var(--color-line)] px-3 py-2">
      <div className="flex justify-between text-xs uppercase tracking-wider text-[var(--color-muted)]">
        <span>{title}</span>
        <span className={result.ok ? "text-[var(--color-ok)]" : "text-[var(--color-danger)]"}>
          {result.ok ? "ok" : "failed"}
          {result.latency_ms != null ? ` · ${result.latency_ms} ms` : ""}
        </span>
      </div>
      <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-xs text-white">
        {result.output}
      </pre>
      {result.note && <p className="mt-2 text-xs text-[var(--color-muted)]">{result.note}</p>}
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-4 border-b border-[var(--color-line)] py-2 last:border-0">
      <span className="text-[var(--color-muted)]">{k}</span>
      <span className="text-right text-white">{v}</span>
    </div>
  );
}
