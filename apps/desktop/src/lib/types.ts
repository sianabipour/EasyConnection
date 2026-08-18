export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "authenticating"
  | "establishing_tunnel"
  | "connected"
  | "degraded"
  | "reconnecting"
  | "disconnecting"
  | "error";

export type ConnectionSnapshot = {
  state: ConnectionState;
  phase: Record<string, unknown> | string;
  profile_id: string | null;
  profile_name: string | null;
  socks_endpoint: string | null;
  http_endpoint: string | null;
  connected_since: string | null;
  last_error: string | null;
  last_error_detail: string | null;
  stats: {
    bytes_down: number;
    bytes_up: number;
    rate_down_bps: number;
    rate_up_bps: number;
    active_flows: number;
  };
  ipv6: boolean;
  routing_mode: string;
  dns_status: string;
  udpgw_status: string;
  server_label: string | null;
  latency_ms: number | null;
  tun_name?: string | null;
  helper_ok?: boolean;
  udp_note?: string | null;
  kill_switch?: boolean;
};

export type Profile = {
  id: string;
  name: string;
  protocol: string;
  transport: string;
  host: string;
  port: number;
  username?: string | null;
  ipv6: boolean;
  routing_mode: string;
  kill_switch?: boolean;
  bypass_private_networks?: boolean;
  tofu?: boolean;
  dns_mode?: string;
  dns_servers?: string[];
  udpgw_enabled?: boolean;
  udpgw_host?: string;
  udpgw_port?: number;
  udpgw_transparent_dns?: boolean;
  tls_sni?: string | null;
  tls_alpn?: string[];
  tls_verify?: boolean;
  tls_fingerprint?: string;
  tls_path?: string | null;
  tls_host?: string | null;
  ss_method?: string | null;
  vless_uuid?: string | null;
  vless_encryption?: string | null;
  vless_flow?: string | null;
  split_bypass_cidrs?: string[];
  split_bypass_domains?: string[];
  proxy: {
    socks_port: number;
    http_proxy_port: number;
    listen: string;
  };
};

export type RoutingMode = "proxy_only" | "full_tunnel" | "split_tunnel";
export type DnsMode = "system" | "tunnel" | "custom" | "remote";
export type ProtocolKind = "ssh" | "shadowsocks" | "vless";
export type TransportKind = "direct" | "tls" | "websocket" | "wss" | "http_upgrade";
export type FingerprintKind = "default" | "chrome" | "firefox" | "safari" | "custom";

export type TransportFields = {
  transport: TransportKind;
  tls_sni: string;
  tls_alpn: string;
  tls_verify: boolean;
  tls_fingerprint: FingerprintKind;
  tls_path: string;
  tls_host: string;
};

export type SharedProfileFields = {
  name: string;
  host: string;
  port: number;
  socks_port: number;
  http_port: number;
  routing_mode: RoutingMode;
  kill_switch: boolean;
  bypass_private_networks: boolean;
  ipv6: boolean;
  dns_mode: DnsMode;
  dns_servers: string;
  listen: string;
  split_bypass_cidrs: string;
  split_bypass_domains: string;
} & TransportFields;

export type NewSshProfile = SharedProfileFields & {
  username: string;
  password: string;
  tofu: boolean;
  udpgw_enabled: boolean;
  udpgw_host: string;
  udpgw_port: number;
  udpgw_transparent_dns: boolean;
};

export type NewSsProfile = SharedProfileFields & {
  method: string;
  password: string;
};

export type NewVlessProfile = SharedProfileFields & {
  uuid: string;
  encryption: string;
  flow: string;
};

export type UpdateProfile = SharedProfileFields & {
  id: string;
  username?: string;
  password?: string;
  tofu?: boolean;
  udpgw_enabled?: boolean;
  udpgw_host?: string;
  udpgw_port?: number;
  udpgw_transparent_dns?: boolean;
  method?: string;
  uuid?: string;
  encryption?: string;
  flow?: string;
};

export type ProbeResult = {
  ok: boolean;
  kind: string;
  target: string;
  latency_ms: number | null;
  output: string;
  note: string | null;
};

export type LeakReport = {
  tun_present: boolean;
  nft_table_present: boolean;
  resolved_link_dns: string[];
  using_tunnel_dns: boolean;
  ipv6_enabled_on_tun: boolean;
  ipv6_global_addrs: string[];
  udp_redirected: boolean;
  notes: string[];
};
