import { Link } from "react-router-dom";
import { useConnection } from "../hooks/useConnection";

export function ServersPage() {
  const { profiles, remove, snapshot, error } = useConnection();

  return (
    <div className="mx-auto max-w-3xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold">Servers</h1>
        <p className="mt-1 text-sm text-[var(--color-muted)]">
          Manage profiles here. Select a profile and connect from the dashboard.
        </p>
      </div>

      {(error || snapshot.last_error_detail || snapshot.last_error) && (
        <pre className="mb-4 whitespace-pre-wrap rounded-lg border border-[color:rgb(239_107_107_/_0.35)] bg-[color:rgb(239_107_107_/_0.08)] px-4 py-3 text-xs text-[var(--color-danger)]">
          {error || snapshot.last_error_detail || snapshot.last_error}
        </pre>
      )}

      {profiles.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[var(--color-line)] px-6 py-16 text-center text-[var(--color-muted)]">
          No profiles yet. Add one from the dashboard menu.
        </div>
      ) : (
        <ul className="space-y-3">
          {profiles.map((profile) => (
            <li
              key={profile.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-4"
            >
              <div className="min-w-0">
                <div className="font-medium text-white">{profile.name}</div>
                <div className="mt-1 truncate font-mono text-xs text-[var(--color-muted)]">
                  {profile.protocol}+{profile.transport}://{profile.host}:{profile.port}
                  {profile.protocol === "ssh" &&
                    (profile.selected_zone ? " · unsupported saved zone" : " · automatic exit")}
                </div>
              </div>
              <div className="flex gap-2">
                <Link
                  to={`/servers/${profile.id}/edit`}
                  className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white"
                >
                  Edit
                </Link>
                <button
                  type="button"
                  onClick={() => void remove(profile.id)}
                  className="rounded-md border border-[var(--color-line)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-white"
                >
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
