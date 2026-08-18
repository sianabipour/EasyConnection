import { NavLink, Route, Routes } from "react-router-dom";
import { HomePage } from "./pages/HomePage";
import { ServersPage } from "./pages/ServersPage";
import { AddConnectionPage } from "./pages/AddConnectionPage";
import { ProxyPage } from "./pages/ProxyPage";
import { RoutingPage } from "./pages/RoutingPage";
import { LogsPage } from "./pages/LogsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { AboutPage } from "./pages/AboutPage";
import { ConnectionProvider, useConnection } from "./hooks/useConnection";

const nav = [
  { to: "/", label: "Home" },
  { to: "/servers", label: "Servers" },
  { to: "/add", label: "Add Connection" },
  { to: "/proxy", label: "Proxy" },
  { to: "/routing", label: "Routing" },
  { to: "/logs", label: "Logs" },
  { to: "/settings", label: "Settings" },
  { to: "/about", label: "About" },
];

function Shell() {
  const { snapshot } = useConnection();
  const connected = snapshot.state === "connected" || snapshot.state === "degraded";

  return (
    <div className="flex h-full min-h-0">
      <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--color-line)] bg-[color:rgb(12_18_25_/_0.85)] px-3 py-5 backdrop-blur">
        <div className="mb-8 px-2">
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-accent)]">
            Easy Connection
          </div>
          <div className="text-lg font-semibold tracking-tight">CLI: easy</div>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                [
                  "rounded-md px-3 py-2 text-sm transition",
                  isActive
                    ? "bg-[var(--color-panel-2)] text-white"
                    : "text-[var(--color-muted)] hover:bg-[var(--color-panel)] hover:text-white",
                ].join(" ")
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-4 rounded-md border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 text-xs text-[var(--color-muted)]">
          <div className="flex items-center gap-2">
            <span
              className={[
                "inline-block h-2 w-2 rounded-full",
                connected ? "bg-[var(--color-ok)]" : "bg-[var(--color-muted)]",
              ].join(" ")}
            />
            {snapshot.state.replaceAll("_", " ")}
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-auto p-6 md:p-8">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/servers" element={<ServersPage />} />
          <Route path="/servers/:id/edit" element={<AddConnectionPage />} />
          <Route path="/add" element={<AddConnectionPage />} />
          <Route path="/proxy" element={<ProxyPage />} />
          <Route path="/routing" element={<RoutingPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/about" element={<AboutPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <ConnectionProvider>
      <Shell />
    </ConnectionProvider>
  );
}
