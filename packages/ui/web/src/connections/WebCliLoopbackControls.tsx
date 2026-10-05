import { ActionButton, FormField, StatusNotice } from "@lattice/ui-shared";

export function WebCliLoopbackControls({
  status,
  url,
  token,
  busy,
  onUrlChange,
  onTokenChange,
  onReconcile,
}: {
  status: string;
  url: string;
  token: string;
  busy: boolean;
  onUrlChange: (value: string) => void;
  onTokenChange: (value: string) => void;
  onReconcile: () => void;
}) {
  return (
    <section className="web-controls" aria-labelledby="cli-bridge-title">
      <div className="control-heading">
        <p className="eyebrow">Local command-line peer</p>
        <h2 id="cli-bridge-title">CLI loopback sync</h2>
      </div>
      <StatusNotice kind="info">{status}</StatusNotice>
      <FormField label="CLI loopback WebSocket URL" htmlFor="cli-bridge-url">
        <input
          id="cli-bridge-url"
          type="url"
          value={url}
          onChange={(event) => onUrlChange(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </FormField>
      <FormField label="One-session pairing token" htmlFor="cli-bridge-token">
        <input
          id="cli-bridge-token"
          type="password"
          value={token}
          onChange={(event) => onTokenChange(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </FormField>
      <ActionButton
        className="button button-quiet"
        type="button"
        disabled={busy || !token.trim()}
        onClick={onReconcile}
      >
        Reconcile with CLI
      </ActionButton>
      <p className="field-hint">
        This bridge is loopback-only. Start <code>lattice sync web-serve-once</code> in the CLI with
        this browser Origin, then enter its one-time token. Canonical signed event bytes are
        transferred unchanged and validated by both profiles&apos; Core. HTTPS-hosted pages cannot
        use this plaintext loopback socket.
      </p>
    </section>
  );
}
