import { useMemo, useState } from "react";
import type { ZoneInfo } from "../lib/types";

function flagEmoji(iso: string | null | undefined): string {
  if (!iso) return "";
  const up = iso.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(up)) return "";
  const base = 0x1f1e6;
  return String.fromCodePoint(base + up.charCodeAt(0) - 65, base + up.charCodeAt(1) - 65);
}

export function ZonePicker({
  zones,
  selectedId,
  loading,
  error,
  onReload,
  onSelect,
}: {
  zones: ZoneInfo[];
  selectedId: string | null;
  loading: boolean;
  error: string | null;
  onReload: () => void;
  onSelect: (zoneId: string | null) => void;
}) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return zones;
    return zones.filter((z) =>
      [z.name, z.id, z.iso || ""].some((part) => part.toLowerCase().includes(q)),
    );
  }, [zones, query]);

  return (
    <div className="space-y-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-white">Exit country</p>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Leave on Auto and the entry host picks the best zone. A normal OpenSSH server has no list.
          </p>
        </div>
        <button
          type="button"
          onClick={onReload}
          disabled={loading}
          className="shrink-0 rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white disabled:opacity-40"
        >
          {loading ? "Loading zones…" : "Load countries"}
        </button>
      </div>

      {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}

      {zones.length > 0 && (
        <>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search zones…"
            className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel-2)] px-3 py-2 text-sm text-white outline-none focus:border-[var(--color-accent)]"
          />
          <ul className="max-h-64 space-y-1 overflow-y-auto">
            <li>
              <button
                type="button"
                onClick={() => onSelect(null)}
                className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm ${
                  !selectedId
                    ? "bg-[color:rgb(94_234_212_/_0.12)] text-white"
                    : "text-[var(--color-muted)] hover:bg-[var(--color-panel-2)] hover:text-white"
                }`}
              >
                <span className="w-6 text-center">◎</span>
                <span>Auto / Best</span>
              </button>
            </li>
            {filtered.map((zone) => {
              const active = selectedId === zone.id;
              const flag = flagEmoji(zone.iso);
              return (
                <li key={zone.id}>
                  <button
                    type="button"
                    onClick={() => onSelect(active ? null : zone.id)}
                    className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm ${
                      active
                        ? "bg-[color:rgb(94_234_212_/_0.12)] text-white"
                        : "text-[var(--color-muted)] hover:bg-[var(--color-panel-2)] hover:text-white"
                    }`}
                  >
                    <span className="w-6 text-center">{flag || zone.iso || "•"}</span>
                    <span className="min-w-0 flex-1 truncate">{zone.name || zone.id}</span>
                    <span className="font-mono text-xs opacity-70">{zone.iso || zone.id}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          {filtered.length === 0 && (
            <p className="text-xs text-[var(--color-muted)]">No zones match that search.</p>
          )}
        </>
      )}
    </div>
  );
}
