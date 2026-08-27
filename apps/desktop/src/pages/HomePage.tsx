import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useConnection } from "../hooks/useConnection";
import { api } from "../lib/api";

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

type Panel = "none" | "add" | "import";

export function HomePage() {
  const {
    snapshot,
    busy,
    error,
    disconnect,
    profiles,
    connect,
    remove,
    importProfile,
    preferredMode,
    setPreferredMode,
  } = useConnection();
  const connected = snapshot.state === "connected" || snapshot.state === "degraded";
  const [downHistory, setDownHistory] = useState<number[]>(() => Array(24).fill(0));
  const [upHistory, setUpHistory] = useState<number[]>(() => Array(24).fill(0));
  const [panel, setPanel] = useState<Panel>("none");
  const [importText, setImportText] = useState("");
  const [importErr, setImportErr] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [pingBusy, setPingBusy] = useState<string | null>(null);
  const [pingMsg, setPingMsg] = useState<Record<string, string>>({});

  useEffect(() => {
    setDownHistory((prev) => [...prev.slice(1), snapshot.stats.rate_down_bps]);
    setUpHistory((prev) => [...prev.slice(1), snapshot.stats.rate_up_bps]);
  }, [snapshot.stats.rate_down_bps, snapshot.stats.rate_up_bps]);

  async function runImport() {
    setImportErr(null);
    setImporting(true);
    try {
      await importProfile(importText);
      setImportText("");
      setPanel("none");
    } catch (err) {
      setImportErr(err instanceof Error ? err.message : String(err));
    } finally {
      setImporting(false);
    }
  }

  async function pasteClipboard() {
    setImportErr(null);
    try {
      const { readText } = await import("@tauri-apps/plugin-clipboard-manager");
      setImportText(await readText());
    } catch {
      try {
        setImportText(await navigator.clipboard.readText());
      } catch (err) {
        setImportErr(err instanceof Error ? err.message : String(err));
      }
    }
  }

  async function pingProfile(id: string, host: string, port: number) {
    setPingBusy(id);
    try {
      const r = await api.tcpProbe(host, port);
      setPingMsg((m) => ({
        ...m,
        [id]: r.ok
          ? `OK ${r.latency_ms ?? "?"} ms (TCP)`
          : r.output || r.note || "unreachable",
      }));
    } catch (e) {
      setPingMsg((m) => ({
        ...m,
        [id]: e instanceof Error ? e.message : String(e),
      }));
    } finally {
      setPingBusy(null);
    }
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 pt-2">
      <div className="text-center">
        <h1 className="text-4xl font-semibold tracking-tight text-white md:text-5xl">Easy Connection</h1>
        <p className="mt-2 text-[var(--color-muted)]">Native Linux tunnel &amp; proxy client</p>
      </div>

      <div className="rounded-2xl border border-[var(--color-line)] bg-[color:rgb(18_26_36_/_0.9)] px-6 py-8 shadow-[0_20px_60px_rgba(0,0,0,0.35)]">
        <div className="mb-2 text-center text-xs uppercase tracking-[0.2em] text-[var(--color-muted)]">
          Status
        </div>
        <div
          className={[
            "text-center text-3xl font-semibold",
            connected
              ? "text-[var(--color-ok)]"
              : snapshot.state === "error"
                ? "text-[var(--color-danger)]"
                : "text-white",
          ].join(" ")}
        >
          ● {snapshot.state.replaceAll("_", " ").toUpperCase()}
        </div>

        <div className="mt-3 text-center text-lg text-[var(--color-muted)]">
          {snapshot.profile_name || snapshot.server_label || "No active profile"}
          {snapshot.latency_ms != null ? ` — ${snapshot.latency_ms} ms` : ""}
        </div>

        <div className="mt-6 flex justify-center gap-2">
          <ModeChip
            active={preferredMode === "proxy_only"}
            disabled={connected || busy}
            label="Proxy"
            onClick={() => void setPreferredMode("proxy_only")}
          />
          <ModeChip
            active={preferredMode === "full_tunnel"}
            disabled={connected || busy}
            label="VPN / Tunnel"
            onClick={() => void setPreferredMode("full_tunnel")}
          />
          <ModeChip
            active={preferredMode === "split_tunnel"}
            disabled={connected || busy}
            label="Split"
            onClick={() => void setPreferredMode("split_tunnel")}
          />
        </div>
        <p className="mt-2 text-center text-[11px] text-[var(--color-muted)]">
          Mode is chosen here for the next Connect — not stored in imported configs.
        </p>

        <div className="mt-6 flex justify-center">
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
            <p className="text-sm text-[var(--color-muted)]">Pick a config below to connect</p>
          )}
        </div>

        <div className="mt-6">
          <Sparkline down={downHistory} up={upHistory} />
        </div>

        <div className="mt-6 grid grid-cols-2 gap-4 text-left text-sm">
          <Stat label="Down" value={formatRate(snapshot.stats.rate_down_bps)} />
          <Stat label="Up" value={formatRate(snapshot.stats.rate_up_bps)} />
          <Stat label="Tunnel" value={connected ? tunnelLabel(snapshot) : preferredMode.replaceAll("_", " ")} />
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
          </p>
        )}

        {(error || snapshot.last_error_detail) && (
          <pre className="mt-6 whitespace-pre-wrap rounded-lg border border-[color:rgb(239_107_107_/_0.35)] bg-[color:rgb(239_107_107_/_0.08)] px-4 py-3 text-left text-xs text-[var(--color-danger)]">
            {error || snapshot.last_error_detail}
          </pre>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setPanel((p) => (p === "add" ? "none" : "add"))}
          className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-ink)]"
        >
          {panel === "add" ? "Hide add form" : "Add connection"}
        </button>
        <button
          type="button"
          onClick={() => setPanel((p) => (p === "import" ? "none" : "import"))}
          className="rounded-lg border border-[var(--color-line)] px-4 py-2 text-sm text-[var(--color-muted)] hover:text-white"
        >
          {panel === "import" ? "Hide import" : "Import config"}
        </button>
        <Link
          to="/add"
          className="rounded-lg border border-[var(--color-line)] px-4 py-2 text-sm text-[var(--color-muted)] hover:text-white"
        >
          Full add page
        </Link>
      </div>

      {panel === "import" && (
        <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
          <p className="text-sm font-medium text-white">Import</p>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            JSON, <code className="text-[var(--color-accent)]">ss://</code>,{" "}
            <code className="text-[var(--color-accent)]">vless://</code>, or{" "}
            <code className="text-[var(--color-accent)]">ssh://</code>. Routing mode is not imported.
          </p>
          <textarea
            className="mt-3 h-24 w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel-2)] px-3 py-2 font-mono text-xs text-white outline-none focus:border-[var(--color-accent)]"
            placeholder="Paste a URI or JSON profile…"
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
          />
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              disabled={importing || !importText.trim()}
              onClick={() => void runImport()}
              className="rounded-md bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-[var(--color-ink)] disabled:opacity-40"
            >
              {importing ? "Importing…" : "Import"}
            </button>
            <button
              type="button"
              onClick={() => void pasteClipboard()}
              className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white"
            >
              Paste clipboard
            </button>
          </div>
          {importErr && <p className="mt-2 text-sm text-[var(--color-danger)]">{importErr}</p>}
        </div>
      )}

      {panel === "add" && (
        <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-muted)]">
          Use the full form for SSH / Shadowsocks / VLESS details.{" "}
          <Link to="/add" className="text-[var(--color-accent)] underline">
            Open Add Connection
          </Link>
        </div>
      )}

      <div>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-[var(--color-muted)]">
          Configs
        </h2>
        {profiles.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[var(--color-line)] px-6 py-10 text-center text-[var(--color-muted)]">
            No profiles yet — add or import one.
          </div>
        ) : (
          <ul className="space-y-3">
            {profiles.map((p) => {
              const active =
                snapshot.profile_id === p.id &&
                (snapshot.state === "connected" || snapshot.state === "degraded");
              return (
                <li
                  key={p.id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-4"
                >
                  <div className="min-w-0 text-left">
                    <div className="font-medium text-white">{p.name}</div>
                    <div className="mt-1 font-mono text-xs text-[var(--color-muted)]">
                      {p.protocol}+{p.transport}://
                      {p.protocol === "ssh" && p.username ? `${p.username}@` : ""}
                      {p.host}:{p.port}
                    </div>
                    {pingMsg[p.id] && (
                      <div className="mt-1 text-xs text-[var(--color-accent)]">{pingMsg[p.id]}</div>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={busy || active}
                      onClick={() => void connect(p.id)}
                      className="rounded-md bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-[var(--color-ink)] disabled:opacity-40"
                    >
                      {active ? "Connected" : "Connect"}
                    </button>
                    <button
                      type="button"
                      disabled={pingBusy === p.id}
                      onClick={() => void pingProfile(p.id, p.host, p.port)}
                      className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white disabled:opacity-40"
                    >
                      {pingBusy === p.id ? "Pinging…" : "Ping"}
                    </button>
                    <Link
                      to={`/servers/${p.id}/edit`}
                      className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white"
                    >
                      Edit
                    </Link>
                    <button
                      type="button"
                      onClick={() => void remove(p.id)}
                      className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white"
                    >
                      Delete
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function ModeChip({
  active,
  disabled,
  label,
  onClick,
}: {
  active: boolean;
  disabled?: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={[
        "rounded-full px-4 py-1.5 text-xs font-semibold uppercase tracking-wide transition disabled:opacity-40",
        active
          ? "bg-[var(--color-accent)] text-[var(--color-ink)]"
          : "border border-[var(--color-line)] text-[var(--color-muted)] hover:text-white",
      ].join(" ")}
    >
      {label}
    </button>
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

