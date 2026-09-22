import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useConnection } from "../hooks/useConnection";
import { api } from "../lib/api";
import type { Profile, RoutingMode, ZoneInfo } from "../lib/types";
import { ZonePicker } from "./ZonePicker";

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

function zoneLabel(profile: Profile): string {
  if (profile.protocol !== "ssh") return "";
  if (!profile.selected_zone) return "Auto";
  const match = profile.zones?.find((z) => z.id === profile.selected_zone);
  return match?.name || profile.selected_zone;
}

export function HomePage() {
  const navigate = useNavigate();
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
    refresh,
  } = useConnection();
  const connected = snapshot.state === "connected" || snapshot.state === "degraded";
  const [downHistory, setDownHistory] = useState<number[]>(() => Array(24).fill(0));
  const [upHistory, setUpHistory] = useState<number[]>(() => Array(24).fill(0));
  const [menuOpen, setMenuOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importErr, setImportErr] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [pingBusy, setPingBusy] = useState<string | null>(null);
  const [pingMsg, setPingMsg] = useState<Record<string, string>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [zoneFor, setZoneFor] = useState<Profile | null>(null);
  const [zoneList, setZoneList] = useState<ZoneInfo[]>([]);
  const [zoneSelected, setZoneSelected] = useState<string | null>(null);
  const [zoneLoading, setZoneLoading] = useState(false);
  const [zoneError, setZoneError] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setDownHistory((prev) => [...prev.slice(1), snapshot.stats.rate_down_bps]);
    setUpHistory((prev) => [...prev.slice(1), snapshot.stats.rate_up_bps]);
  }, [snapshot.stats.rate_down_bps, snapshot.stats.rate_up_bps]);

  useEffect(() => {
    if (selectedId && profiles.some((p) => p.id === selectedId)) return;
    const active = profiles.find((p) => p.id === snapshot.profile_id);
    setSelectedId(active?.id || profiles[0]?.id || null);
  }, [profiles, selectedId, snapshot.profile_id]);

  useEffect(() => {
    if (!menuOpen) return;
    function onPointer(event: MouseEvent) {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    }
    window.addEventListener("mousedown", onPointer);
    return () => window.removeEventListener("mousedown", onPointer);
  }, [menuOpen]);

  const selected = profiles.find((p) => p.id === selectedId) || null;

  async function runImport() {
    setImportErr(null);
    setImporting(true);
    try {
      await importProfile(importText);
      setImportText("");
      setImportOpen(false);
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

  async function chooseMode(mode: RoutingMode) {
    if (mode === preferredMode) return;
    const reconnectId = connected ? snapshot.profile_id || selectedId : null;
    await setPreferredMode(mode);
    if (reconnectId) {
      await disconnect();
      await connect(reconnectId);
    }
  }

  async function openZones(profile: Profile) {
    setZoneFor(profile);
    setZoneList(profile.zones || []);
    setZoneSelected(profile.selected_zone || null);
    setZoneError(null);
    setZoneLoading(true);
    try {
      const fresh = await api.fetchZones(profile.id);
      setZoneList(fresh.zones || []);
      setZoneSelected(fresh.selected_zone || null);
      await refresh();
    } catch (err) {
      setZoneError(err instanceof Error ? err.message : String(err));
    } finally {
      setZoneLoading(false);
    }
  }

  async function pickZone(zoneId: string | null) {
    if (!zoneFor) return;
    setZoneSelected(zoneId);
    try {
      const fresh = await api.setSelectedZone(zoneFor.id, zoneId);
      setZoneSelected(fresh.selected_zone || null);
      setZoneList(fresh.zones || zoneList);
      await refresh();
    } catch (err) {
      setZoneError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 pt-2">
      <div className="flex items-start justify-between gap-3">
        <div className="text-center sm:text-left">
          <h1 className="text-4xl font-semibold tracking-tight text-white md:text-5xl">Easy Connection</h1>
          <p className="mt-2 text-[var(--color-muted)]">Native Linux tunnel &amp; proxy client</p>
        </div>
        <div className="relative" ref={menuRef}>
          <button
            type="button"
            aria-label="More"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((open) => !open)}
            className="flex h-10 w-10 items-center justify-center rounded-full border border-[var(--color-line)] text-lg tracking-widest text-[var(--color-muted)] hover:text-white"
          >
            ···
          </button>
          {menuOpen && (
            <div className="absolute right-0 z-20 mt-2 w-48 overflow-hidden rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] py-1 shadow-[0_16px_40px_rgba(0,0,0,0.45)]">
              <button
                type="button"
                className="block w-full px-4 py-2.5 text-left text-sm text-white hover:bg-[var(--color-panel-2)]"
                onClick={() => {
                  setMenuOpen(false);
                  navigate("/add");
                }}
              >
                Add connection
              </button>
              <button
                type="button"
                className="block w-full px-4 py-2.5 text-left text-sm text-white hover:bg-[var(--color-panel-2)]"
                onClick={() => {
                  setMenuOpen(false);
                  setImportOpen((open) => !open);
                }}
              >
                Import
              </button>
            </div>
          )}
        </div>
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
          {snapshot.profile_name || selected?.name || snapshot.server_label || "No active profile"}
          {snapshot.latency_ms != null ? ` — ${snapshot.latency_ms} ms` : ""}
        </div>

        <div className="mt-6 flex justify-center gap-2">
          <ModeChip
            active={preferredMode === "proxy_only"}
            disabled={busy}
            label="Proxy"
            onClick={() => void chooseMode("proxy_only")}
          />
          <ModeChip
            active={preferredMode === "full_tunnel"}
            disabled={busy}
            label="VPN / Tunnel"
            onClick={() => void chooseMode("full_tunnel")}
          />
          <ModeChip
            active={preferredMode === "split_tunnel"}
            disabled={busy}
            label="Split"
            onClick={() => void chooseMode("split_tunnel")}
          />
        </div>
        <p className="mt-2 text-center text-[11px] text-[var(--color-muted)]">
          {connected
            ? "Switching Proxy or Tunnel reconnects immediately with that mode."
            : "Proxy and Tunnel apply on the next Connect."}
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
            <button
              type="button"
              disabled={busy || !selected}
              onClick={() => selected && void connect(selected.id)}
              className="rounded-lg bg-[var(--color-accent)] px-10 py-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-ink)] transition hover:brightness-110 disabled:opacity-40"
            >
              {busy ? "Connecting…" : "Connect"}
            </button>
          )}
        </div>
        {!connected && (
          <p className="mt-3 text-center text-xs text-[var(--color-muted)]">
            {selected ? `Selected: ${selected.name}` : "Select a config below"}
          </p>
        )}

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

      {importOpen && (
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

      <div>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-[var(--color-muted)]">
          Configs
        </h2>
        {profiles.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[var(--color-line)] px-6 py-10 text-center text-[var(--color-muted)]">
            No profiles yet. Use the menu above to add or import one.
          </div>
        ) : (
          <ul className="space-y-3">
            {profiles.map((p) => {
              const active =
                snapshot.profile_id === p.id &&
                (snapshot.state === "connected" || snapshot.state === "degraded");
              const picked = selectedId === p.id;
              const country = zoneLabel(p);
              return (
                <li key={p.id}>
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => setSelectedId(p.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") setSelectedId(p.id);
                    }}
                    className={[
                      "w-full cursor-pointer rounded-2xl border px-4 py-4 text-left transition",
                      picked
                        ? "border-[var(--color-accent)] bg-[color:rgb(94_234_212_/_0.08)] shadow-[0_0_0_1px_rgba(94,234,212,0.35)]"
                        : "border-[var(--color-line)] bg-[var(--color-panel)] hover:border-[color:rgb(255_255_255_/_0.18)]",
                    ].join(" ")}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span
                            className={[
                              "h-2.5 w-2.5 shrink-0 rounded-full",
                              active ? "bg-[var(--color-ok)]" : "bg-[var(--color-line)]",
                            ].join(" ")}
                          />
                          <span className="truncate font-medium text-white">{p.name}</span>
                        </div>
                        <div className="mt-1 truncate font-mono text-xs text-[var(--color-muted)]">
                          {p.protocol}+{p.transport}://
                          {p.protocol === "ssh" && p.username ? `${p.username}@` : ""}
                          {p.host}:{p.port}
                        </div>
                        {p.protocol === "ssh" && (
                          <div className="mt-2 inline-flex items-center rounded-full border border-[var(--color-line)] px-2 py-0.5 text-[11px] uppercase tracking-wide text-[var(--color-muted)]">
                            Zone {country}
                          </div>
                        )}
                        {pingMsg[p.id] && (
                          <div className="mt-1 text-xs text-[var(--color-accent)]">{pingMsg[p.id]}</div>
                        )}
                      </div>
                      <div className="flex shrink-0 flex-wrap justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                        {p.protocol === "ssh" && (
                          <button
                            type="button"
                            onClick={() => void openZones(p)}
                            className="rounded-md bg-[var(--color-panel-2)] px-3 py-1.5 text-sm text-white hover:brightness-125"
                          >
                            Change zone
                          </button>
                        )}
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
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {zoneFor && (
        <div
          className="fixed inset-0 z-30 flex items-center justify-center bg-black/60 p-4"
          onClick={() => setZoneFor(null)}
        >
          <div
            className="max-h-[80vh] w-full max-w-lg overflow-auto rounded-2xl border border-[var(--color-line)] bg-[var(--color-ink)] p-4 shadow-[0_24px_80px_rgba(0,0,0,0.55)]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <p className="text-base font-medium text-white">Change zone</p>
                <p className="text-xs text-[var(--color-muted)]">{zoneFor.name}</p>
              </div>
              <button
                type="button"
                onClick={() => setZoneFor(null)}
                className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white"
              >
                Close
              </button>
            </div>
            <ZonePicker
              zones={zoneList}
              selectedId={zoneSelected}
              loading={zoneLoading}
              error={zoneError}
              onReload={() => void openZones(zoneFor)}
              onSelect={(id) => void pickZone(id)}
            />
          </div>
        </div>
      )}
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
