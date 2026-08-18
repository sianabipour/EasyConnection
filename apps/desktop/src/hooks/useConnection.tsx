import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api } from "../lib/api";
import type { ConnectionSnapshot, Profile } from "../lib/types";

type Ctx = {
  snapshot: ConnectionSnapshot;
  profiles: Profile[];
  busy: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  connect: (id: string) => Promise<void>;
  disconnect: () => Promise<void>;
  addSsh: (input: Parameters<typeof api.addSshProfile>[0]) => Promise<void>;
  addSs: (input: Parameters<typeof api.addSsProfile>[0]) => Promise<void>;
  addVless: (input: Parameters<typeof api.addVlessProfile>[0]) => Promise<void>;
  updateProfile: (input: Parameters<typeof api.updateProfile>[0]) => Promise<void>;
  getProfile: (id: string) => Promise<Profile>;
  remove: (id: string) => Promise<void>;
  importProfile: (text: string) => Promise<void>;
};

const ConnectionContext = createContext<Ctx | null>(null);

const empty: ConnectionSnapshot = {
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

export function ConnectionProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<ConnectionSnapshot>(empty);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [s, p] = await Promise.all([api.status(), api.listProfiles()]);
    setSnapshot(s);
    setProfiles(p);
  }, []);

  useEffect(() => {
    void refresh().catch((e: Error) => setError(e.message));
    const id = window.setInterval(() => {
      void api.status().then(setSnapshot).catch(() => undefined);
    }, 1500);
    return () => window.clearInterval(id);
  }, [refresh]);

  const connect = async (id: string) => {
    setBusy(true);
    setError(null);
    try {
      const s = await api.connect(id);
      setSnapshot(s);
      if (s.last_error) setError(s.last_error_detail || s.last_error);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      await refresh();
    }
  };

  const disconnect = async () => {
    setBusy(true);
    try {
      setSnapshot(await api.disconnect());
    } finally {
      setBusy(false);
    }
  };

  const addSsh = async (input: Parameters<typeof api.addSshProfile>[0]) => {
    await api.addSshProfile(input);
    await refresh();
  };

  const addSs = async (input: Parameters<typeof api.addSsProfile>[0]) => {
    await api.addSsProfile(input);
    await refresh();
  };

  const addVless = async (input: Parameters<typeof api.addVlessProfile>[0]) => {
    await api.addVlessProfile(input);
    await refresh();
  };

  const updateProfile = async (input: Parameters<typeof api.updateProfile>[0]) => {
    await api.updateProfile(input);
    await refresh();
  };

  const getProfile = useCallback((id: string) => api.getProfile(id), []);

  const remove = async (id: string) => {
    await api.deleteProfile(id);
    await refresh();
  };

  const importProfile = async (text: string) => {
    await api.importProfile(text);
    await refresh();
  };

  return (
    <ConnectionContext.Provider
      value={{
        snapshot,
        profiles,
        busy,
        error,
        refresh,
        connect,
        disconnect,
        addSsh,
        addSs,
        addVless,
        updateProfile,
        getProfile,
        remove,
        importProfile,
      }}
    >
      {children}
    </ConnectionContext.Provider>
  );
}

export function useConnection() {
  const ctx = useContext(ConnectionContext);
  if (!ctx) throw new Error("ConnectionProvider missing");
  return ctx;
}
