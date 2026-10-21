import { useEffect, useMemo, useRef, useState } from "react";
import type { Profile, ZoneInfo } from "../lib/types";

function flag(iso?: string | null) {
  if (!iso || !/^[A-Z]{2}$/i.test(iso)) return "";
  const code = iso.toUpperCase();
  return String.fromCodePoint(
    0x1f1e6 + code.charCodeAt(0) - 65,
    0x1f1e6 + code.charCodeAt(1) - 65,
  );
}

export function ZonePickerDialog({
  profile,
  loading,
  saving,
  error,
  onReload,
  onSelect,
  onClose,
}: {
  profile: Profile;
  loading: boolean;
  saving: boolean;
  error: string | null;
  onReload: () => void;
  onSelect: (zone: ZoneInfo | null) => void;
  onClose: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState("");
  const zones = profile.zones || [];
  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    return zones.filter((zone) =>
      [zone.name, zone.id, zone.iso || ""].some((value) => value.toLowerCase().includes(term)),
    );
  }, [zones, query]);

  useEffect(() => {
    const dialog = dialogRef.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby="zone-picker-title"
      onCancel={onClose}
      onClose={onClose}
      className="w-[min(32rem,calc(100vw-2rem))] max-h-[80vh] rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-0 text-white backdrop:bg-black/70"
    >
      <div className="border-b border-[var(--color-line)] px-5 py-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id="zone-picker-title" className="text-lg font-semibold">Choose exit country</h2>
            <p className="mt-1 text-xs text-[var(--color-muted)]">{profile.name}</p>
          </div>
          <button type="button" aria-label="Close country picker" onClick={onClose} className="rounded-md px-2 py-1 text-[var(--color-muted)] hover:text-white">✕</button>
        </div>
        <label className="mt-4 block text-sm text-[var(--color-muted)]">
          Search countries
          <input
            autoFocus
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            className="mt-1 w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel-2)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
          />
        </label>
      </div>
      <div className="max-h-[48vh] overflow-y-auto px-3 py-2">
        <button
          type="button"
          disabled={saving}
          aria-pressed={!profile.selected_zone}
          onClick={() => onSelect(null)}
          className="flex min-h-11 w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm hover:bg-[var(--color-panel-2)] disabled:opacity-50"
        >
          <span>Auto / Best</span><span aria-hidden>{!profile.selected_zone ? "✓" : ""}</span>
        </button>
        {filtered.map((zone) => (
          <button
            key={zone.id}
            type="button"
            disabled={saving}
            aria-pressed={profile.selected_zone === zone.id}
            onClick={() => onSelect(zone)}
            className="flex min-h-11 w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm hover:bg-[var(--color-panel-2)] disabled:opacity-50"
          >
            <span className="w-7 text-center" aria-hidden>{flag(zone.iso) || "•"}</span>
            <span className="min-w-0 flex-1 truncate">{zone.name || zone.id}</span>
            <span className="font-mono text-xs text-[var(--color-muted)]">{zone.id}</span>
            <span aria-hidden>{profile.selected_zone === zone.id ? "✓" : ""}</span>
          </button>
        ))}
        {!loading && filtered.length === 0 && <p role="status" className="px-3 py-4 text-sm text-[var(--color-muted)]">No matching countries.</p>}
      </div>
      <div className="border-t border-[var(--color-line)] px-5 py-3 text-xs text-[var(--color-muted)]">
        <div className="flex items-center justify-between gap-3">
          <span role="status">{loading ? "Loading countries…" : `${zones.length} countries available`}</span>
          <button type="button" disabled={loading || saving} onClick={onReload} className="text-[var(--color-accent)] hover:underline disabled:opacity-50">Reload</button>
        </div>
        {error && <p role="alert" className="mt-2 text-[var(--color-danger)]">{error}</p>}
        {saving && <p role="status" className="mt-2">Saving selection…</p>}
      </div>
    </dialog>
  );
}
