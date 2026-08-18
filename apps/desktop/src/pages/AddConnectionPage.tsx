import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useConnection } from "../hooks/useConnection";
import type {
  DnsMode,
  FingerprintKind,
  ProtocolKind,
  RoutingMode,
  TransportKind,
} from "../lib/types";

function asRoutingMode(value: string | undefined): RoutingMode {
  if (value === "full_tunnel" || value === "fulltunnel") return "full_tunnel";
  if (value === "split_tunnel" || value === "splittunnel") return "split_tunnel";
  return "proxy_only";
}

function asDnsMode(value: string | undefined, routing: RoutingMode): DnsMode {
  if (value === "custom") return "custom";
  if (value === "remote") return "remote";
  if (value === "system") return routing === "proxy_only" ? "system" : "tunnel";
  return routing === "proxy_only" ? "system" : "tunnel";
}

function asProtocol(value: string | undefined): ProtocolKind {
  if (value === "shadowsocks") return "shadowsocks";
  if (value === "vless") return "vless";
  return "ssh";
}

function asTransport(value: string | undefined): TransportKind {
  if (value === "tls") return "tls";
  if (value === "websocket") return "websocket";
  if (value === "wss") return "wss";
  if (value === "http_upgrade") return "http_upgrade";
  return "direct";
}

function asFingerprint(value: string | undefined): FingerprintKind {
  if (value === "chrome" || value === "firefox" || value === "safari" || value === "custom") {
    return value;
  }
  return "default";
}

function defaultPort(protocol: ProtocolKind): string {
  if (protocol === "shadowsocks") return "8388";
  if (protocol === "vless") return "443";
  return "22";
}

function needsTlsFields(transport: TransportKind): boolean {
  return transport === "tls" || transport === "wss" || transport === "http_upgrade";
}

function needsPath(transport: TransportKind): boolean {
  return transport === "websocket" || transport === "wss" || transport === "http_upgrade";
}

export function AddConnectionPage() {
  const { id } = useParams<{ id: string }>();
  const editing = Boolean(id);
  const { addSsh, addSs, addVless, updateProfile, getProfile } = useConnection();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const [protocol, setProtocol] = useState<ProtocolKind>("ssh");
  const [transport, setTransport] = useState<TransportKind>("direct");
  const [mode, setMode] = useState<RoutingMode>("proxy_only");
  const [dnsMode, setDnsMode] = useState<DnsMode>("system");
  const [ipv6, setIpv6] = useState(false);
  const [udpgw, setUdpgw] = useState(false);
  const [tlsVerify, setTlsVerify] = useState(true);
  const [fingerprint, setFingerprint] = useState<FingerprintKind>("default");
  const [loading, setLoading] = useState(editing);
  const [defaults, setDefaults] = useState({
    name: "",
    host: "",
    port: "22",
    username: "",
    socks_port: "1080",
    http_port: "8080",
    tofu: true,
    kill_switch: false,
    bypass_private: true,
    dns_servers: "",
    udpgw_host: "127.0.0.1",
    udpgw_port: "7300",
    udpgw_dns: false,
    tls_sni: "",
    tls_alpn: "",
    tls_path: "/",
    tls_host: "",
    ss_method: "aes-256-gcm",
    vless_uuid: "",
    vless_encryption: "none",
    vless_flow: "",
    share_lan: false,
    split_cidrs: "",
    split_domains: "",
  });

  function setRoutingMode(next: RoutingMode) {
    setMode(next);
    if (next !== "proxy_only" && dnsMode === "system") {
      setDnsMode("tunnel");
    }
  }

  function changeProtocol(next: ProtocolKind) {
    if (editing) return;
    const prevDefault = defaultPort(protocol);
    setProtocol(next);
    setDefaults((d) => (d.port === prevDefault ? { ...d, port: defaultPort(next) } : d));
    if (next !== "ssh") setUdpgw(false);
  }

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setLoading(true);
    void getProfile(id)
      .then((profile) => {
        if (cancelled) return;
        const routing = asRoutingMode(profile.routing_mode);
        setProtocol(asProtocol(profile.protocol));
        setTransport(asTransport(profile.transport));
        setMode(routing);
        setDnsMode(asDnsMode(profile.dns_mode, routing));
        setIpv6(Boolean(profile.ipv6));
        setUdpgw(Boolean(profile.udpgw_enabled));
        setTlsVerify(profile.tls_verify !== false);
        setFingerprint(asFingerprint(profile.tls_fingerprint));
        setDefaults({
          name: profile.name,
          host: profile.host,
          port: String(profile.port),
          username: profile.username || "",
          socks_port: String(profile.proxy.socks_port),
          http_port: String(profile.proxy.http_proxy_port),
          tofu: profile.tofu !== false,
          kill_switch: Boolean(profile.kill_switch),
          bypass_private: profile.bypass_private_networks !== false,
          dns_servers: (profile.dns_servers || []).join(", "),
          udpgw_host: profile.udpgw_host || "127.0.0.1",
          udpgw_port: String(profile.udpgw_port || 7300),
          udpgw_dns: Boolean(profile.udpgw_transparent_dns),
          tls_sni: profile.tls_sni || "",
          tls_alpn: (profile.tls_alpn || []).join(", "),
          tls_path: profile.tls_path || "/",
          tls_host: profile.tls_host || "",
          ss_method: profile.ss_method || "aes-256-gcm",
          vless_uuid: profile.vless_uuid || "",
          vless_encryption: profile.vless_encryption || "none",
          vless_flow: profile.vless_flow || "",
          share_lan: profile.proxy.listen === "0.0.0.0" || profile.proxy.listen === "::",
          split_cidrs: (profile.split_bypass_cidrs || []).join(", "),
          split_domains: (profile.split_bypass_domains || []).join(", "),
        });
        if (
          profile.kill_switch ||
          profile.bypass_private_networks === false ||
          profile.ipv6 ||
          profile.udpgw_enabled ||
          (profile.dns_mode && profile.dns_mode !== "system") ||
          (profile.transport && profile.transport !== "direct") ||
          profile.proxy.listen === "0.0.0.0" ||
          (profile.split_bypass_cidrs && profile.split_bypass_cidrs.length > 0) ||
          (profile.split_bypass_domains && profile.split_bypass_domains.length > 0)
        ) {
          setAdvanced(true);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [id, getProfile]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const fd = new FormData(e.currentTarget);
    const shared = {
      name: String(fd.get("name") || ""),
      host: String(fd.get("host") || ""),
      port: Number(fd.get("port") || defaultPort(protocol)),
      socks_port: Number(fd.get("socks_port") || 1080),
      http_port: Number(fd.get("http_port") || 8080),
      routing_mode: mode,
      kill_switch: fd.get("kill_switch") === "on",
      bypass_private_networks: advanced ? fd.get("bypass_private") === "on" : true,
      ipv6,
      dns_mode: dnsMode,
      dns_servers: String(fd.get("dns_servers") || ""),
      transport,
      tls_sni: String(fd.get("tls_sni") || ""),
      tls_alpn: String(fd.get("tls_alpn") || ""),
      tls_verify: tlsVerify,
      tls_fingerprint: fingerprint,
      tls_path: String(fd.get("tls_path") || "/"),
      tls_host: String(fd.get("tls_host") || ""),
      listen: fd.get("share_lan") === "on" ? "0.0.0.0" : "127.0.0.1",
      split_bypass_cidrs: String(fd.get("split_cidrs") || ""),
      split_bypass_domains: String(fd.get("split_domains") || ""),
    };
    try {
      if (editing && id) {
        const password = String(fd.get("password") || "");
        await updateProfile({
          id,
          ...shared,
          username: String(fd.get("username") || defaults.username),
          password: password || undefined,
          tofu: fd.get("tofu") === "on",
          udpgw_enabled: protocol === "ssh" && udpgw,
          udpgw_host: String(fd.get("udpgw_host") || "127.0.0.1"),
          udpgw_port: Number(fd.get("udpgw_port") || 7300),
          udpgw_transparent_dns: fd.get("udpgw_dns") === "on",
          method: String(fd.get("ss_method") || defaults.ss_method),
          uuid: String(fd.get("vless_uuid") || defaults.vless_uuid),
          encryption: String(fd.get("vless_encryption") || "none"),
          flow: String(fd.get("vless_flow") || ""),
        });
      } else if (protocol === "shadowsocks") {
        await addSs({
          ...shared,
          method: String(fd.get("ss_method") || "aes-256-gcm"),
          password: String(fd.get("password") || ""),
        });
      } else if (protocol === "vless") {
        await addVless({
          ...shared,
          uuid: String(fd.get("vless_uuid") || ""),
          encryption: String(fd.get("vless_encryption") || "none"),
          flow: String(fd.get("vless_flow") || ""),
        });
      } else {
        await addSsh({
          ...shared,
          username: String(fd.get("username") || ""),
          password: String(fd.get("password") || ""),
          tofu: fd.get("tofu") === "on",
          udpgw_enabled: udpgw,
          udpgw_host: String(fd.get("udpgw_host") || "127.0.0.1"),
          udpgw_port: Number(fd.get("udpgw_port") || 7300),
          udpgw_transparent_dns: fd.get("udpgw_dns") === "on",
        });
      }
      navigate("/servers");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  if (loading) {
    return <p className="text-sm text-[var(--color-muted)]">Loading connection…</p>;
  }

  return (
    <div className="mx-auto max-w-lg">
      <h1 className="text-2xl font-semibold">{editing ? "Edit Connection" : "Add Connection"}</h1>
      <p className="mt-1 text-sm text-[var(--color-muted)]">
        SSH, Shadowsocks AEAD, or VLESS over Direct / TLS / WebSocket / HTTP Upgrade
      </p>

      <form key={id || "new"} onSubmit={onSubmit} className="mt-6 space-y-4">
        <label className="block text-sm">
          <span className="mb-1 block text-[var(--color-muted)]">Protocol</span>
          <select
            className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)] disabled:opacity-60"
            value={protocol}
            disabled={editing}
            onChange={(e) => changeProtocol(e.target.value as ProtocolKind)}
          >
            <option value="ssh">SSH</option>
            <option value="shadowsocks">Shadowsocks (AEAD TCP)</option>
            <option value="vless">VLESS (encryption=none)</option>
          </select>
        </label>

        <Field label="Name" name="name" required placeholder="Germany VPS" defaultValue={defaults.name} />
        <Field label="Host" name="host" required placeholder="vpn.example.com" defaultValue={defaults.host} />
        <div className="grid grid-cols-2 gap-3">
          <Field key={`port-${protocol}-${defaults.port}`} label="Port" name="port" type="number" defaultValue={defaults.port} />
          {protocol === "ssh" && (
            <Field label="Username" name="username" required={!editing} defaultValue={defaults.username} />
          )}
          {protocol === "shadowsocks" && (
            <label className="block text-sm">
              <span className="mb-1 block text-[var(--color-muted)]">Method</span>
              <select
                name="ss_method"
                defaultValue={defaults.ss_method}
                className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
              >
                <option value="aes-256-gcm">aes-256-gcm</option>
                <option value="aes-128-gcm">aes-128-gcm</option>
              </select>
            </label>
          )}
        </div>

        {protocol === "vless" && (
          <Field
            label="UUID"
            name="vless_uuid"
            required={!editing}
            placeholder="00000000-0000-0000-0000-000000000000"
            defaultValue={defaults.vless_uuid}
          />
        )}

        {protocol !== "vless" && (
          <Field
            label={editing ? "Password (leave blank to keep current)" : "Password"}
            name="password"
            type="password"
            required={!editing}
            autoComplete="off"
          />
        )}

        <label className="block text-sm">
          <span className="mb-1 block text-[var(--color-muted)]">Transport</span>
          <select
            className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
            value={transport}
            onChange={(e) => setTransport(e.target.value as TransportKind)}
          >
            <option value="direct">Direct TCP</option>
            <option value="tls">TLS (openssl s_client)</option>
            <option value="websocket">WebSocket</option>
            <option value="wss">WSS (TLS + WebSocket)</option>
            <option value="http_upgrade">HTTP Upgrade</option>
          </select>
        </label>

        {(needsTlsFields(transport) || needsPath(transport)) && (
          <div className="space-y-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
            {needsTlsFields(transport) && (
              <>
                <Field label="SNI" name="tls_sni" placeholder="same as host if empty" defaultValue={defaults.tls_sni} />
                <Field label="ALPN (comma-separated)" name="tls_alpn" placeholder="leave empty for SSH-over-TLS" defaultValue={defaults.tls_alpn} />
                <label className="block text-sm">
                  <span className="mb-1 block text-[var(--color-muted)]">Fingerprint profile</span>
                  <select
                    className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
                    value={fingerprint}
                    onChange={(e) => setFingerprint(e.target.value as FingerprintKind)}
                  >
                    <option value="default">Default (no extra ALPN)</option>
                    <option value="chrome">Chrome (ALPN hint only)</option>
                    <option value="firefox">Firefox (ALPN hint only)</option>
                    <option value="safari">Safari (ALPN hint only)</option>
                    <option value="custom">Custom (use ALPN field)</option>
                  </select>
                </label>
                <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
                  <input
                    type="checkbox"
                    checked={tlsVerify}
                    onChange={(e) => setTlsVerify(e.target.checked)}
                    className="accent-[var(--color-accent)]"
                  />
                  Verify TLS certificates (keep on)
                </label>
                <p className="text-xs text-[var(--color-muted)]">
                  TLS uses system <code className="text-[var(--color-accent)]">openssl s_client</code>.
                  Fingerprint profiles only set conventional ALPN — they are not JA3 impersonation.
                </p>
              </>
            )}
            {needsPath(transport) && (
              <div className="grid grid-cols-2 gap-3">
                <Field label="Path" name="tls_path" defaultValue={defaults.tls_path} />
                <Field label="Host header" name="tls_host" placeholder="defaults to SNI / host" defaultValue={defaults.tls_host} />
              </div>
            )}
          </div>
        )}

        {protocol === "vless" && (
          <p className="text-xs text-[var(--color-muted)]">
            VLESS encryption must be <code className="text-[var(--color-accent)]">none</code>.
            Vision / XTLS is not implemented.
            <input type="hidden" name="vless_encryption" value={defaults.vless_encryption || "none"} />
            <input type="hidden" name="vless_flow" value={defaults.vless_flow} />
          </p>
        )}

        <fieldset className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
          <legend className="px-1 text-sm text-[var(--color-muted)]">Connection Mode</legend>
          <ModeRadio
            value="proxy_only"
            checked={mode === "proxy_only"}
            onChange={setRoutingMode}
            title="Proxy Only"
            hint="Apps must use the local SOCKS/HTTP ports. No root helper required."
          />
          <ModeRadio
            value="full_tunnel"
            checked={mode === "full_tunnel"}
            onChange={setRoutingMode}
            title="VPN / Full Tunnel"
            hint="Routes system TCP through the selected protocol via TUN easy0. Requires the privileged helper."
          />
          <ModeRadio
            value="split_tunnel"
            checked={mode === "split_tunnel"}
            onChange={setRoutingMode}
            title="Split Tunnel"
            hint="Full-tunnel TCP plus extra CIDR/domain bypass. Process/cgroup split is not implemented."
          />
        </fieldset>

        {protocol === "ssh" && (
          <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
            <input
              type="checkbox"
              name="tofu"
              defaultChecked={defaults.tofu}
              className="accent-[var(--color-accent)]"
            />
            Trust host key on first use (reject later mismatches)
          </label>
        )}

        <button
          type="button"
          className="text-sm text-[var(--color-accent)]"
          onClick={() => setAdvanced((v) => !v)}
        >
          {advanced ? "Hide" : "Show"} advanced settings
        </button>

        {advanced && (
          <div className="space-y-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
            <div className="grid grid-cols-2 gap-3">
              <Field label="SOCKS port" name="socks_port" type="number" defaultValue={defaults.socks_port} />
              <Field label="HTTP port" name="http_port" type="number" defaultValue={defaults.http_port} />
            </div>
            <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
              <input
                type="checkbox"
                name="share_lan"
                defaultChecked={defaults.share_lan}
                className="accent-[var(--color-accent)]"
              />
              Share proxy on LAN (bind 0.0.0.0)
            </label>
            <p className="text-xs text-[var(--color-muted)]">
              Anyone on the local network can use SOCKS/HTTP while connected. Keep this off unless you intend to share.
            </p>
            <Field
              label="Split bypass CIDRs"
              name="split_cidrs"
              placeholder="10.0.0.0/8, 192.168.1.0/24"
              defaultValue={defaults.split_cidrs}
            />
            <Field
              label="Split bypass domains"
              name="split_domains"
              placeholder="intranet.example, printer.local"
              defaultValue={defaults.split_domains}
            />
            <p className="text-xs text-[var(--color-muted)]">
              Domains are resolved at connect time and skipped by nft redirect. Process-based split is not implemented.
            </p>
            <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
              <input
                type="checkbox"
                name="bypass_private"
                defaultChecked={defaults.bypass_private}
                className="accent-[var(--color-accent)]"
              />
              Bypass private networks (10/8, 172.16/12, 192.168/16, …)
            </label>
            <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
              <input
                type="checkbox"
                name="kill_switch"
                defaultChecked={defaults.kill_switch}
                className="accent-[var(--color-accent)]"
              />
              Kill switch (block non-tunnel traffic while connected)
            </label>
            <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
              <input
                type="checkbox"
                name="ipv6"
                checked={ipv6}
                onChange={(e) => setIpv6(e.target.checked)}
                className="accent-[var(--color-accent)]"
              />
              Enable IPv6 on the TUN (dual-stack intercept; off rejects public IPv6)
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-[var(--color-muted)]">DNS mode</span>
              <select
                className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
                value={dnsMode}
                onChange={(e) => setDnsMode(e.target.value as DnsMode)}
              >
                <option value="system">System (leave systemd-resolved alone)</option>
                <option value="tunnel">Tunnel (link DNS + DNS-over-TCP via the tunnel)</option>
                <option value="custom">Custom servers (via tunnel)</option>
                <option value="remote">Remote (same path as tunnel)</option>
              </select>
            </label>
            {(dnsMode === "custom" || dnsMode === "tunnel" || dnsMode === "remote") && (
              <Field
                label="DNS servers"
                name="dns_servers"
                placeholder="1.1.1.1, 8.8.8.8"
                defaultValue={defaults.dns_servers}
              />
            )}
            {protocol === "ssh" && (
              <>
                <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
                  <input
                    type="checkbox"
                    name="udpgw"
                    checked={udpgw}
                    onChange={(e) => setUdpgw(e.target.checked)}
                    className="accent-[var(--color-accent)]"
                  />
                  UDPGW (system UDP over SSH — remote must run badvpn-udpgw)
                </label>
                {udpgw && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <Field label="UDPGW host (on the SSH server)" name="udpgw_host" defaultValue={defaults.udpgw_host} />
                      <Field label="UDPGW port" name="udpgw_port" type="number" defaultValue={defaults.udpgw_port} />
                    </div>
                    <label className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
                      <input
                        type="checkbox"
                        name="udpgw_dns"
                        defaultChecked={defaults.udpgw_dns}
                        className="accent-[var(--color-accent)]"
                      />
                      Transparent DNS via UDPGW (falls back to DNS-over-TCP)
                    </label>
                    <p className="text-xs text-[var(--color-muted)]">
                      Typical remote command: <code className="text-[var(--color-accent)]">badvpn-udpgw --listen-addr 127.0.0.1:7300</code>.
                      QUIC/games may still fail; the UI will say connected, not “all UDP works”.
                    </p>
                  </div>
                )}
              </>
            )}
            {protocol !== "ssh" && (
              <p className="text-xs text-[var(--color-muted)]">
                UDPGW is SSH-only. Shadowsocks and VLESS carry TCP (and DNS-over-TCP) in this phase.
              </p>
            )}
            <p className="text-xs text-[var(--color-muted)]">
              Full/split tunnel upgrades System DNS to Tunnel so queries do not leak to the LAN resolver.
              Kill switch uses nftables table inet easy only. Use Settings → Emergency restore if you get locked out.
            </p>
          </div>
        )}

        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}

        <button
          type="submit"
          className="w-full rounded-lg bg-[var(--color-accent)] py-3 text-sm font-semibold text-[var(--color-ink)]"
        >
          {editing ? "Save changes" : "Save"}
        </button>
      </form>
    </div>
  );
}

function ModeRadio(props: {
  value: RoutingMode;
  checked: boolean;
  onChange: (v: RoutingMode) => void;
  title: string;
  hint: string;
}) {
  return (
    <label className="mt-2 flex cursor-pointer gap-3 text-left">
      <input
        type="radio"
        name="routing_mode"
        className="mt-1 accent-[var(--color-accent)]"
        checked={props.checked}
        onChange={() => props.onChange(props.value)}
      />
      <span>
        <span className="block text-sm text-white">{props.title}</span>
        <span className="block text-xs text-[var(--color-muted)]">{props.hint}</span>
      </span>
    </label>
  );
}

function Field(props: {
  label: string;
  name: string;
  type?: string;
  required?: boolean;
  placeholder?: string;
  defaultValue?: string;
  autoComplete?: string;
}) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-[var(--color-muted)]">{props.label}</span>
      <input
        className="w-full rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-white outline-none focus:border-[var(--color-accent)]"
        name={props.name}
        type={props.type || "text"}
        required={props.required}
        placeholder={props.placeholder}
        defaultValue={props.defaultValue}
        autoComplete={props.autoComplete}
      />
    </label>
  );
}
