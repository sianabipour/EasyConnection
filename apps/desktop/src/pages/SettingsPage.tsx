import { useState } from "react";
import { api } from "../lib/api";

export function SettingsPage() {
  const [restoreMsg, setRestoreMsg] = useState<string | null>(null);
  const [restoreErr, setRestoreErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function emergencyRestore() {
    setBusy(true);
    setRestoreMsg(null);
    setRestoreErr(null);
    try {
      setRestoreMsg(await api.emergencyRestore());
    } catch (e) {
      setRestoreErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold">Settings</h1>
      <p className="mt-1 text-sm text-[var(--color-muted)]">
        Defaults stay conservative. Use emergency restore if a crash left routes or nftables behind.
      </p>
      <div className="mt-6 space-y-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 text-sm">
        <Row k="Host key policy default" v="TOFU (configurable per profile)" />
        <Row k="TLS verify default" v="Enabled" />
        <Row k="Secrets backend" v="Encrypted local vault (Secret Service planned)" />
        <Row k="Privileged helper" v="/run/easy/helper.sock" />
      </div>

      <div className="mt-6 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
        <h2 className="text-sm font-semibold text-white">Network recovery</h2>
        <p className="mt-1 text-sm text-[var(--color-muted)]">
          Removes <code>easy0</code>, <code>table inet easy</code>, and routes this app added.
        </p>
        <button
          type="button"
          disabled={busy}
          onClick={() => void emergencyRestore()}
          className="mt-3 rounded-md border border-[var(--color-danger)] px-3 py-1.5 text-sm text-[var(--color-danger)] disabled:opacity-50"
        >
          {busy ? "Restoring…" : "Emergency restore networking"}
        </button>
        {restoreMsg && <p className="mt-3 text-sm text-[var(--color-ok)]">{restoreMsg}</p>}
        {restoreErr && <p className="mt-3 whitespace-pre-wrap text-sm text-[var(--color-danger)]">{restoreErr}</p>}
      </div>
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
