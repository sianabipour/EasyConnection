export function LogsPage() {
  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="text-2xl font-semibold">Logs</h1>
      <p className="mt-1 text-sm text-[var(--color-muted)]">
        Structured logs are emitted by the Rust engine (`RUST_LOG` / app settings). Credentials are never logged.
      </p>
      <pre className="mt-6 overflow-auto rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4 font-mono text-xs text-[var(--color-muted)]">
        {`Filter categories: Core | SSH | TLS | DNS | Routing | TUN | UDPGW | Proxy | System
Use the CLI with RUST_LOG=rt_ssh=debug,rt_tunnel=info for verbose sessions.`}
      </pre>
    </div>
  );
}
