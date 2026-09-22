import "./App.css";

const stack = [
  {
    label: "Desktop shell",
    state: "Ready",
    detail: "React, TypeScript, Vite, and Tauri v2",
  },
  {
    label: "Protocol lab",
    state: "Planned",
    detail: "Canonical events and convergence arrive in M0",
  },
  {
    label: "Nearby paths",
    state: "Not configured",
    detail: "No Bluetooth or local network access is active",
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

function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Lattice home">
          <Mark />
          <span>Lattice</span>
        </a>
        <span className="stage">Protocol lab</span>
      </header>

      <main>
        <section className="hero" aria-labelledby="page-title">
          <p className="eyebrow">Local-first community communication</p>
          <h1 id="page-title">Your communities should not depend on a central account.</h1>
          <p className="lede">
            Lattice keeps authenticated state on your devices and uses nearby or optional relay
            paths when available. This repository is in protocol-lab development; identity,
            messaging, and network actions are not enabled yet.
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
              Local shell
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
