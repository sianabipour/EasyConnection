import { useState } from "react";
import { Link } from "react-router-dom";
import { useConnection } from "../hooks/useConnection";

export function ServersPage() {
  const { profiles, connect, remove, busy, snapshot, error, importProfile } = useConnection();
  const [importText, setImportText] = useState("");
  const [importErr, setImportErr] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

  async function runImport() {
    setImportErr(null);
    setImporting(true);
    try {
      await importProfile(importText);
      setImportText("");
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

  return (
    <div className="mx-auto max-w-3xl">
      <div className="mb-6 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Servers</h1>
          <p className="mt-1 text-sm text-[var(--color-muted)]">Profiles stored locally with secrets outside SQLite.</p>
        </div>
        <Link
          to="/add"
          className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-ink)]"
        >
          Add Connection
        </Link>
      </div>

      {(error || snapshot.last_error_detail || snapshot.last_error) && (
        <pre className="mb-4 whitespace-pre-wrap rounded-lg border border-[color:rgb(239_107_107_/_0.35)] bg-[color:rgb(239_107_107_/_0.08)] px-4 py-3 text-xs text-[var(--color-danger)]">
          {error || snapshot.last_error_detail || snapshot.last_error}
        </pre>
      )}

      <div className="mb-6 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
        <p className="text-sm font-medium text-white">Import</p>
        <p className="mt-1 text-xs text-[var(--color-muted)]">
          JSON export, <code className="text-[var(--color-accent)]">ss://</code>,{" "}
          <code className="text-[var(--color-accent)]">vless://</code>, or{" "}
          <code className="text-[var(--color-accent)]">ssh://</code>. Parsed only — never executed.
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

      {profiles.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[var(--color-line)] px-6 py-16 text-center text-[var(--color-muted)]">
          No profiles yet.
        </div>
      ) : (
        <ul className="space-y-3">
          {profiles.map((p) => {
            const active = snapshot.profile_id === p.id && snapshot.state === "connected";
            return (
              <li
                key={p.id}
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-4"
              >
                <div>
                  <div className="font-medium text-white">{p.name}</div>
                  <div className="mt-1 font-mono text-xs text-[var(--color-muted)]">
                    {p.protocol}+{p.transport}://
                    {p.protocol === "ssh" && p.username ? `${p.username}@` : ""}
                    {p.host}:{p.port} · {p.routing_mode.replaceAll("_", " ")}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={busy || active}
                    onClick={() => void connect(p.id)}
                    className="rounded-md bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-[var(--color-ink)] disabled:opacity-40"
                  >
                    {active ? "Connected" : "Connect"}
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
  );
}
