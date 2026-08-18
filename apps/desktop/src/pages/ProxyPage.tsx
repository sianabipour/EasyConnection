import { useConnection } from "../hooks/useConnection";

export function ProxyPage() {
  const { snapshot, profiles } = useConnection();
  const active = profiles.find((p) => p.id === snapshot.profile_id);
  const listen = active?.proxy.listen || "";
  const shared =
    listen === "0.0.0.0" ||
    listen === "::" ||
    Boolean(snapshot.socks_endpoint?.includes("0.0.0.0")) ||
    Boolean(snapshot.http_endpoint?.includes("0.0.0.0"));

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold">Proxy</h1>
      <p className="mt-1 text-sm text-[var(--color-muted)]">Local listeners shared by the active tunnel.</p>

      <div className="mt-6 space-y-3">
        <Endpoint title="SOCKS5" value={snapshot.socks_endpoint || "Not listening"} />
        <Endpoint title="HTTP CONNECT" value={snapshot.http_endpoint || "Not listening"} />
      </div>

      {shared && (
        <div className="mt-6 rounded-xl border border-[color:rgb(239_160_70_/_0.45)] bg-[color:rgb(239_160_70_/_0.08)] px-4 py-3 text-sm text-[var(--color-warn,#e8b86d)]">
          These ports are bound on all interfaces. Anyone on the LAN can use this machine as a proxy
          for as long as the tunnel is up. Bind 127.0.0.1 unless you intend to share.
        </div>
      )}
    </div>
  );
}

function Endpoint({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-4">
      <div className="text-xs uppercase tracking-wider text-[var(--color-muted)]">{title}</div>
      <div className="mt-2 flex items-center justify-between gap-3">
        <code className="font-mono text-sm text-[var(--color-accent)]">{value}</code>
        <button
          type="button"
          className="rounded-md border border-[var(--color-line)] px-3 py-1 text-xs text-[var(--color-muted)] hover:text-white"
          onClick={() => void navigator.clipboard.writeText(value)}
          disabled={!value.startsWith("socks") && !value.startsWith("http")}
        >
          Copy
        </button>
      </div>
    </div>
  );
}
