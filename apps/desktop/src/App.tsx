import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import { PeerIdentityPinPanel } from "./features/identity/PeerIdentityPinPanel";
import { LocalSpaceBrowser } from "./features/spaces/LocalSpaceBrowser";
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

function App() {
  const [identity, setIdentity] = useState<IdentityStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
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
            <PeerIdentityPinPanel
              runtimeAvailable={runtimeAvailable}
              identityReady={identity !== null}
            />
          </section>
          <LocalSpaceBrowser runtimeAvailable={runtimeAvailable} />
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
