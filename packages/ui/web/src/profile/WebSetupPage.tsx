import { LatticeLogo } from "@lattice/ui-shared";
import type { ReactNode } from "react";

export function WebSetupPage({ children }: { children: ReactNode }) {
  return (
    <section className="lattice-web-setup">
      <header className="masthead">
        <span className="wordmark" role="img" aria-label="Lattice Web">
          <LatticeLogo />
        </span>
        <span className="masthead-note">Web profile</span>
      </header>
      <section className="intro" aria-labelledby="page-title">
        <div className="intro-copy">
          <p className="eyebrow">Private by ownership</p>
          <h1 id="page-title">A profile that stays in this browser.</h1>
          <p className="intro-summary">
            Your identity and local data belong to this origin. No account server holds your
            profile.
          </p>
        </div>
        <fieldset className="ownership-flow">
          <legend className="visually-hidden">Profile ownership flow</legend>
          <div className="flow-node">
            <span className="flow-dot flow-dot-ui" aria-hidden="true" />
            <span>Browser view</span>
          </div>
          <span className="flow-line" aria-hidden="true" />
          <div className="flow-node flow-node-active">
            <span className="flow-dot flow-dot-worker" aria-hidden="true" />
            <span>Private worker</span>
          </div>
          <span className="flow-line" aria-hidden="true" />
          <div className="flow-node">
            <span className="flow-dot flow-dot-store" aria-hidden="true" />
            <span>Local OPFS</span>
          </div>
        </fieldset>
      </section>
      {children}
    </section>
  );
}
