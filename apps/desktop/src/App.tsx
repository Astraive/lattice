import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import "./App.css";

const stack = [
  {
    label: "Desktop shell",
    state: "Ready",
    detail: "React, TypeScript, Vite, and Tauri v2",
  },
  {
    label: "Protected identity",
    state: "Available",
    detail: "Device keys are wrapped by the OS credential store",
  },
  {
    label: "Spaces and messaging",
    state: "Disabled",
    detail: "Production MLS, authorization, and event integration are not complete",
  },
  {
    label: "Desktop discovery",
    state: "Not enabled",
    detail: "No nearby or LAN transport is active on desktop",
  },
] as const;

function Mark() {
  return (
    <svg aria-hidden="true" className="mark" viewBox="0 0 40 40">
      <path d="M9 11.5 20 5l11 6.5v17L20 35 9 28.5v-17Z" />
      <path d="m14 14.5 6-3.5 6 3.5v11L20 29l-6-3.5v-11Z" />
      <circle cx="20" cy="20" r="2.5" />
    </svg>
  );
}

type IdentityStatus = {
  fingerprint: string;
  public_bundle: string;
  next_author_sequence: number;
};

type LocalSpaceSummary = {
  spaceId: string;
  groupReference: string;
};

type LocalSpacePage = {
  spaces: LocalSpaceSummary[];
  nextCursor: string | null;
};
function App() {
  const [identity, setIdentity] = useState<IdentityStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [spaces, setSpaces] = useState<LocalSpaceSummary[]>([]);
  const [spaceCursor, setSpaceCursor] = useState<string | null>(null);
  const [spaceError, setSpaceError] = useState<string | null>(null);
  const [spacesBusy, setSpacesBusy] = useState(false);
  const [spacesLoaded, setSpacesLoaded] = useState(false);
  const runtimeAvailable = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

  async function runIdentityCommand(command: "initialize_device_identity" | "get_device_identity") {
    setBusy(true);
    setError(null);
    try {
      setIdentity(await invoke<IdentityStatus>(command));
    } catch (cause) {
      setIdentity(null);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function runSpacesCommand(after: string | null = null) {
    setSpacesBusy(true);
    setSpaceError(null);
    try {
      const page = await invoke<LocalSpacePage>("list_local_spaces", { after });
      setSpaces((current) => (after ? [...current, ...page.spaces] : page.spaces));
      setSpaceCursor(page.nextCursor);
      setSpacesLoaded(true);
    } catch (cause) {
      setSpaceError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSpacesBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Lattice home">
          <Mark />
          <span>Lattice</span>
        </a>
        <span className="stage">Local client</span>
      </header>

      <main>
        <section className="hero" aria-labelledby="page-title">
          <p className="eyebrow">Local-first community communication</p>
          <h1 id="page-title">Your communities should not depend on a central account.</h1>
          <p className="lede">
            The desktop client can browse locally recovered Spaces and protect a device identity
            with the OS credential store. Authenticated membership, message authoring, and delivery
            remain disabled until their MLS and authorization paths are complete.
          </p>
          <div className="principles">
            <span>Offline correctness</span>
            <span>Explicit delivery state</span>
            <span>Replaceable paths</span>
          </div>
        </section>

        <section className="status-panel" aria-labelledby="status-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Workspace status</p>
              <h2 id="status-title">Implementation boundaries</h2>
            </div>
            <span className="local-badge">
              <span className="status-dot" aria-hidden="true" />
              Local profile
            </span>
          </div>

          <div className="status-grid">
            {stack.map((item) => (
              <article className="status-card" key={item.label}>
                <p>{item.label}</p>
                <strong>{item.state}</strong>
                <span>{item.detail}</span>
              </article>
            ))}
          </div>

          <section aria-labelledby="identity-title">
            <h3 id="identity-title">Device identity</h3>
            <p>
              Private keys are never displayed. Initializing uses the OS credential store and
              persists only protected key material in the local database.
            </p>
            {runtimeAvailable ? (
              <div>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runIdentityCommand("initialize_device_identity")}
                >
                  {busy ? "Working…" : "Initialize or reopen identity"}
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void runIdentityCommand("get_device_identity")}
                >
                  Show existing identity
                </button>
              </div>
            ) : (
              <p>Open the Tauri desktop app to use its native OS-keyring commands.</p>
            )}
            {error && <p role="alert">{error}</p>}
            {identity && (
              <div aria-live="polite">
                <p>
                  Fingerprint: <code>{identity.fingerprint}</code>
                </p>
                <p>Next local event sequence: {identity.next_author_sequence}</p>
                <details>
                  <summary>Public identity bundle</summary>
                  <code>{identity.public_bundle}</code>
                </details>
              </div>
            )}
          </section>
          <section className="space-browser" aria-labelledby="spaces-title">
            <div className="space-browser-heading">
              <div>
                <h3 id="spaces-title">Local Spaces</h3>
                <p>
                  Verified local Genesis snapshots only; this does not imply current membership.
                </p>
              </div>
              {runtimeAvailable && (
                <button
                  type="button"
                  disabled={spacesBusy}
                  onClick={() => void runSpacesCommand(spacesLoaded ? spaceCursor : null)}
                >
                  {spacesBusy
                    ? "Loading…"
                    : spaceCursor
                      ? "Load next page"
                      : spacesLoaded
                        ? "Refresh Spaces"
                        : "Load local Spaces"}
                </button>
              )}
            </div>
            {!runtimeAvailable && (
              <p>Open the desktop app to inspect its protected local Space store.</p>
            )}
            {spaceError && <p role="alert">{spaceError}</p>}
            {spacesLoaded && spaces.length === 0 && <p>No local Space snapshots were found.</p>}
            {spaces.length > 0 && (
              <ul className="space-list" aria-live="polite">
                {spaces.map((space) => (
                  <li key={`${space.spaceId}:${space.groupReference}`}>
                    <span>Space</span>
                    <code>{space.spaceId}</code>
                    <span>MLS group</span>
                    <code>{space.groupReference}</code>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </section>
      </main>

      <footer>
        <span>No project cloud is required.</span>
        <span>Capabilities appear only when implemented and verified.</span>
      </footer>
    </div>
  );
}

export default App;
