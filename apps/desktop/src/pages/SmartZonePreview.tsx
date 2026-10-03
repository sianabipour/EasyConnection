import { useMemo, useState } from "react";
import type { ZoneInfo } from "../lib/types";

function flag(iso: string | null | undefined): string {
  if (!iso || !/^[A-Z]{2}$/.test(iso.toUpperCase())) return "";
  const code = iso.toUpperCase();
  return String.fromCodePoint(
    0x1f1e6 + code.charCodeAt(0) - 65,
    0x1f1e6 + code.charCodeAt(1) - 65,
  );
}

export function SmartZonePreview({
  zones,
  loading,
  error,
  onLoad,
}: {
  zones: ZoneInfo[];
  loading: boolean;
  error: string | null;
  onLoad: () => void;
}) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const search = query.trim().toLowerCase();
    return zones.filter((zone) =>
      [zone.name, zone.id, zone.iso || ""].some((field) => field.toLowerCase().includes(search)),
    );
  }, [zones, query]);

  return (
    <section aria-label="Smart Config countries" className="mt-4 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel-2)] p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-white">Smart Config countries</p>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Read-only preview. Easy cannot yet use the encrypted Smart Config response to connect through a selected country.
          </p>
        </div>
        <button
          type="button"
          disabled={loading}
          onClick={onLoad}
          className="min-h-11 rounded-md border border-[var(--color-line)] px-3 text-sm text-white hover:bg-[var(--color-panel)] disabled:opacity-50"
        >
          {loading ? "Loading…" : "Load countries"}
        </button>
      </div>
      {error && <p role="alert" className="mt-3 text-sm text-[var(--color-danger)]">{error}</p>}
      {zones.length > 0 && (
        <>
          <p role="status" className="mt-3 text-xs text-[var(--color-muted)]">{zones.length} zones returned by the provider</p>
          <label className="mt-3 block text-sm text-[var(--color-muted)]">
            Search countries
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="mt-1 w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
            />
          </label>
          <ul className="mt-2 max-h-64 overflow-y-auto" aria-label="Available Smart Config zones">
            {filtered.map((zone) => (
              <li key={zone.id} className="flex items-center gap-2 border-b border-[var(--color-line)] px-1 py-2 text-sm text-white last:border-0">
                <span className="w-7 text-center" aria-hidden>{flag(zone.iso) || "•"}</span>
                <span className="min-w-0 flex-1 truncate">{zone.name || zone.id}</span>
                <span className="font-mono text-xs text-[var(--color-muted)]">{zone.id}</span>
              </li>
            ))}
          </ul>
          {filtered.length === 0 && <p role="status" className="py-3 text-sm text-[var(--color-muted)]">No matching countries.</p>}
        </>
      )}
    </section>
  );
}
