export function AboutPage() {
  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold">About</h1>
      <p className="mt-3 text-sm leading-relaxed text-[var(--color-muted)]">
        Easy Connection is a standards-compatible tunneling client for Ubuntu. Undocumented proprietary
        wire formats are not invented here — see PROTOCOLS.md. The terminal CLI is{" "}
        <code className="text-[var(--color-accent)]">easy</code>.
      </p>
      <p className="mt-4 text-sm text-[var(--color-muted)]">
        Version 0.1.0 · Phase 8 (packaging, uninstall cleanup, Ubuntu 26.04 install)
      </p>
    </div>
  );
}
