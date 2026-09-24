import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

type PinnedIdentityStatus = {
  fingerprint: string;
  publicBundle: string;
};

type PeerIdentityPinPanelProps = {
  runtimeAvailable: boolean;
  identityReady: boolean;
};

export function PeerIdentityPinPanel({
  runtimeAvailable,
  identityReady,
}: PeerIdentityPinPanelProps) {
  const [bundleHex, setBundleHex] = useState("");
  const [fingerprintHex, setFingerprintHex] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("No peer identity pin is selected.");
  const [error, setError] = useState<string | null>(null);
  const [pinned, setPinned] = useState<PinnedIdentityStatus | null>(null);

  async function pinIdentity() {
    setBusy(true);
    setError(null);
    setPinned(null);
    try {
      const result = await invoke<PinnedIdentityStatus>("pin_peer_identity", {
        bundleHex,
        expectedFingerprintHex: fingerprintHex,
      });
      setPinned(result);
      setStatus(
        "Exact bundle bytes match this full fingerprint and are stored locally. This does not authenticate a session or grant Space membership.",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function lookUpPin() {
    setBusy(true);
    setError(null);
    setPinned(null);
    try {
      const result = await invoke<PinnedIdentityStatus | null>("get_pinned_identity", {
        fingerprintHex,
      });
      setPinned(result);
      setStatus(
        result
          ? "Local pin found. It does not authenticate a session or grant Space membership."
          : "No local pin exists for this fingerprint.",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="identity-pin" aria-labelledby="identity-pin-title">
      <h4 id="identity-pin-title">Pin a peer identity</h4>
      <p>
        Compare the full fingerprint out of band before saving these public bytes. A pin does not
        connect to that peer or add it to a Space.
      </p>
      {runtimeAvailable ? (
        <>
          <div className="identity-pin-fields">
            <label>
              Public bundle (65 bytes, hex)
              <input
                type="text"
                value={bundleHex}
                maxLength={130}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setBundleHex(event.currentTarget.value)}
              />
            </label>
            <label>
              Full fingerprint (32 bytes, hex)
              <input
                type="text"
                value={fingerprintHex}
                maxLength={64}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setFingerprintHex(event.currentTarget.value)}
              />
            </label>
          </div>
          <div className="identity-pin-actions">
            <button
              type="button"
              disabled={busy || !identityReady || !bundleHex || !fingerprintHex}
              onClick={() => void pinIdentity()}
            >
              {busy ? "Saving…" : "Pin exact identity"}
            </button>
            <button
              type="button"
              disabled={busy || !identityReady || !fingerprintHex}
              onClick={() => void lookUpPin()}
            >
              Look up saved pin
            </button>
          </div>
        </>
      ) : (
        <p>Open the Tauri desktop app to save or look up a local pin.</p>
      )}
      <p aria-live="polite">{status}</p>
      {error && <p role="alert">{error}</p>}
      {pinned && (
        <div className="identity-pin-result">
          <p>
            Pinned fingerprint: <code>{pinned.fingerprint}</code>
          </p>
          <p>
            Public bundle: <code>{pinned.publicBundle}</code>
          </p>
        </div>
      )}
    </section>
  );
}
