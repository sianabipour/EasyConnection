import { invoke } from "@tauri-apps/api/core";
import type {
  ConnectionSnapshot,
  LeakReport,
  NewSsProfile,
  NewSshProfile,
  NewVlessProfile,
  ProbeResult,
  Profile,
  RoutingMode,
  UpdateProfile,
} from "./types";

export type AppSettingsDto = {
  theme: string;
  start_minimized: boolean;
  reconnect_base_delay_ms: number;
  reconnect_max_delay_ms: number;
  log_level: string;
  preferred_routing_mode: string;
};

const browserFallback = typeof window !== "undefined" && !("__TAURI_INTERNALS__" in window);

let mockProfiles: Profile[] = [];
let mockSnap: ConnectionSnapshot = {
  state: "disconnected",
  phase: "idle",
  profile_id: null,
  profile_name: null,
  socks_endpoint: null,
  http_endpoint: null,
  connected_since: null,
  last_error: null,
  last_error_detail: null,
  stats: {
    bytes_down: 0,
    bytes_up: 0,
    rate_down_bps: 0,
    rate_up_bps: 0,
    active_flows: 0,
  },
  ipv6: false,
  routing_mode: "proxy_only",
  dns_status: "system",
  udpgw_status: "disabled",
  server_label: null,
  latency_ms: null,
};

/** Tauri 2 looks up camelCase command keys; we also send snake_case for older shells. */
function withIpcArgAliases(args?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!args) return args;
  const out: Record<string, unknown> = { ...args };
  for (const [key, value] of Object.entries(args)) {
    if (key.includes("_")) {
      const camel = key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
      out[camel] = value;
    }
  }
  return out;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!browserFallback) {
    return invoke<T>(cmd, withIpcArgAliases(args));
  }
  // Vite-only preview: UI shell without native backend.
  switch (cmd) {
    case "list_profiles":
      return mockProfiles as T;
    case "connection_status":
      return mockSnap as T;
    case "add_ssh_profile":
    case "add_ss_profile":
    case "add_vless_profile": {
      const p = args as unknown as NewSshProfile & NewSsProfile & NewVlessProfile;
      const protocol =
        cmd === "add_ss_profile" ? "shadowsocks" : cmd === "add_vless_profile" ? "vless" : "ssh";
      const profile: Profile = {
        id: crypto.randomUUID(),
        name: p.name,
        protocol,
        transport: p.transport || "direct",
        host: p.host,
        port: p.port,
        username: p.username,
        ipv6: Boolean(p.ipv6),
        routing_mode: p.routing_mode || "proxy_only",
        kill_switch: p.kill_switch,
        bypass_private_networks: p.bypass_private_networks,
        tofu: p.tofu,
        dns_mode: p.dns_mode,
        dns_servers: p.dns_servers
          ? p.dns_servers.split(/[,\s]+/).filter(Boolean)
          : [],
        udpgw_enabled: p.udpgw_enabled,
        udpgw_host: p.udpgw_host,
        udpgw_port: p.udpgw_port,
        udpgw_transparent_dns: p.udpgw_transparent_dns,
        tls_sni: p.tls_sni || null,
        tls_alpn: p.tls_alpn ? p.tls_alpn.split(/[,\s]+/).filter(Boolean) : [],
        tls_verify: p.tls_verify !== false,
        tls_fingerprint: p.tls_fingerprint || "default",
        tls_path: p.tls_path || null,
        tls_host: p.tls_host || null,
        ss_method: p.method,
        vless_uuid: p.uuid,
        vless_encryption: p.encryption,
        vless_flow: p.flow,
        split_bypass_cidrs: p.split_bypass_cidrs
          ? p.split_bypass_cidrs.split(/[,\s]+/).filter(Boolean)
          : [],
        split_bypass_domains: p.split_bypass_domains
          ? p.split_bypass_domains.split(/[,\s]+/).filter(Boolean)
          : [],
        proxy: {
          socks_port: p.socks_port,
          http_proxy_port: p.http_port,
          listen: p.listen || "127.0.0.1",
        },
      };
      mockProfiles = [...mockProfiles, profile];
      return profile as T;
    }
    case "get_profile": {
      const found = mockProfiles.find((p) => p.id === args?.id);
      if (!found) throw new Error("profile not found");
      return found as T;
    }
    case "update_ssh_profile": {
      const input = args as unknown as UpdateProfile;
      mockProfiles = mockProfiles.map((p) =>
        p.id === input.id
          ? {
              ...p,
              name: input.name,
              host: input.host,
              port: input.port,
              username: input.username,
              routing_mode: input.routing_mode,
              kill_switch: input.kill_switch,
              bypass_private_networks: input.bypass_private_networks,
              tofu: input.tofu,
              ipv6: input.ipv6,
              dns_mode: input.dns_mode,
              dns_servers: input.dns_servers
                ? input.dns_servers.split(/[,\s]+/).filter(Boolean)
                : [],
              udpgw_enabled: input.udpgw_enabled,
              udpgw_host: input.udpgw_host,
              udpgw_port: input.udpgw_port,
              udpgw_transparent_dns: input.udpgw_transparent_dns,
              transport: input.transport || p.transport,
              tls_sni: input.tls_sni,
              tls_alpn: input.tls_alpn ? input.tls_alpn.split(/[,\s]+/).filter(Boolean) : [],
              tls_verify: input.tls_verify,
              tls_fingerprint: input.tls_fingerprint,
              tls_path: input.tls_path,
              tls_host: input.tls_host,
              ss_method: input.method ?? p.ss_method,
              vless_uuid: input.uuid ?? p.vless_uuid,
              vless_encryption: input.encryption ?? p.vless_encryption,
              vless_flow: input.flow ?? p.vless_flow,
              split_bypass_cidrs: input.split_bypass_cidrs
                ? input.split_bypass_cidrs.split(/[,\s]+/).filter(Boolean)
                : p.split_bypass_cidrs,
              split_bypass_domains: input.split_bypass_domains
                ? input.split_bypass_domains.split(/[,\s]+/).filter(Boolean)
                : p.split_bypass_domains,
              proxy: {
                ...p.proxy,
                socks_port: input.socks_port,
                http_proxy_port: input.http_port,
                listen: input.listen || p.proxy.listen,
              },
            }
          : p,
      );
      const updated = mockProfiles.find((p) => p.id === input.id);
      if (!updated) throw new Error("profile not found");
      return updated as T;
    }
    case "delete_profile":
      mockProfiles = mockProfiles.filter((p) => p.id !== args?.id);
      return undefined as T;
    case "connect_profile":
      mockSnap = {
        ...mockSnap,
        state: "error",
        last_error: "Native backend required",
        last_error_detail:
          "Connect requires the Tauri/Rust engine. Use `easy connect` CLI or `cargo tauri dev`.",
      };
      return mockSnap as T;
    case "disconnect":
      mockSnap = { ...mockSnap, state: "disconnected", last_error: null };
      return mockSnap as T;
    case "emergency_restore":
      return "Helper not available in browser preview" as T;
    case "leak_report":
      return {
        tun_present: false,
        nft_table_present: false,
        resolved_link_dns: [],
        using_tunnel_dns: false,
        ipv6_enabled_on_tun: false,
        ipv6_global_addrs: [],
        udp_redirected: false,
        notes: ["Native backend required for leak checks."],
      } as T;
    case "import_profile":
      throw new Error("Import requires the Tauri/Rust engine.");
    case "get_app_settings":
      return {
        theme: "system",
        start_minimized: false,
        reconnect_base_delay_ms: 1000,
        reconnect_max_delay_ms: 60000,
        log_level: "info",
        preferred_routing_mode: "proxy_only",
      } as T;
    case "set_preferred_routing_mode":
      return {
        theme: "system",
        start_minimized: false,
        reconnect_base_delay_ms: 1000,
        reconnect_max_delay_ms: 60000,
        log_level: "info",
        preferred_routing_mode: String(args?.mode || "proxy_only"),
      } as T;
    case "tcp_probe":
    case "traceroute":
      return {
        ok: false,
        kind: cmd === "traceroute" ? "traceroute" : "tcp",
        target: String(args?.host || ""),
        latency_ms: null,
        output: "Native backend required",
        note: "ICMP ping is not available on the TCP intercept path.",
      } as T;
    default:
      throw new Error(`Unknown command in browser preview: ${cmd}`);
  }
}

export const api = {
  listProfiles: () => call<Profile[]>("list_profiles"),
  addSshProfile: (input: NewSshProfile) => call<Profile>("add_ssh_profile", { ...input }),
  addSsProfile: (input: NewSsProfile) => call<Profile>("add_ss_profile", { ...input }),
  addVlessProfile: (input: NewVlessProfile) => call<Profile>("add_vless_profile", { ...input }),
  getProfile: (id: string) => call<Profile>("get_profile", { id }),
  updateProfile: (input: UpdateProfile) => call<Profile>("update_ssh_profile", { ...input }),
  deleteProfile: (id: string) => call<void>("delete_profile", { id }),
  connect: (id: string) => call<ConnectionSnapshot>("connect_profile", { id }),
  disconnect: () => call<ConnectionSnapshot>("disconnect"),
  status: () => call<ConnectionSnapshot>("connection_status"),
  emergencyRestore: () => call<string>("emergency_restore"),
  leakReport: () => call<LeakReport>("leak_report"),
  importProfile: (text: string) => call<Profile>("import_profile", { text }),
  tcpProbe: (host: string, port?: number) =>
    call<ProbeResult>("tcp_probe", { host, port }),
  traceroute: (host: string) => call<ProbeResult>("traceroute", { host }),
  getSettings: () => call<AppSettingsDto>("get_app_settings"),
  setPreferredRoutingMode: (mode: RoutingMode | string) =>
    call<AppSettingsDto>("set_preferred_routing_mode", { mode }),
};
