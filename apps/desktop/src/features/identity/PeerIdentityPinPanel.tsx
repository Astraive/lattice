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

type ActiveTask = "csr" | "pin" | "lookup" | null;

function isFixedHex(value: string, characterCount: number) {
  return value.length === characterCount && /^[0-9a-fA-F]+$/.test(value);
}

function hexValidationMessage(label: string, characterCount: number, value: string) {
  if (value.length !== characterCount) {
    return `${label} must contain exactly ${characterCount} hexadecimal characters.`;
  }
  return `${label} may contain only hexadecimal characters (0–9, a–f).`;
}

export function PeerIdentityPinPanel({
  runtimeAvailable,
  identityReady,
}: PeerIdentityPinPanelProps) {
  const [bundleHex, setBundleHex] = useState("");
  const [fingerprintHex, setFingerprintHex] = useState("");
  const [activeTask, setActiveTask] = useState<ActiveTask>(null);
  const [status, setStatus] = useState("No peer identity pin is selected.");
  const [error, setError] = useState<string | null>(null);
  const [invalidField, setInvalidField] = useState<"bundle" | "fingerprint" | null>(null);
  const [pinned, setPinned] = useState<PinnedIdentityStatus | null>(null);
  const [csrPem, setCsrPem] = useState<string | null>(null);
  const [csrError, setCsrError] = useState<string | null>(null);
  const [csrCopyStatus, setCsrCopyStatus] = useState("");
  const busy = activeTask !== null;

  async function createCertificateRequest() {
    setActiveTask("csr");
    setCsrError(null);
    setCsrPem(null);
    setCsrCopyStatus("");
    try {
      setCsrPem(await invoke<string>("get_device_certificate_signing_request"));
    } catch (cause) {
      setCsrError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setActiveTask(null);
    }
  }

  async function copyCertificateRequest() {
    if (!csrPem) return;
    setCsrError(null);
    setCsrCopyStatus("");
    try {
      await navigator.clipboard.writeText(csrPem);
      setCsrCopyStatus("Certificate request copied to the clipboard.");
    } catch (cause) {
      setCsrError(
        cause instanceof Error
          ? `Could not copy the certificate request: ${cause.message}`
          : "Could not copy the certificate request. Select and copy the PEM text instead.",
      );
    }
  }

  function clearPinResult() {
    setError(null);
    setInvalidField(null);
    setPinned(null);
    setStatus("Entered values have not been checked or saved.");
  }

  async function pinIdentity() {
    if (!isFixedHex(bundleHex, 130)) {
      setError(hexValidationMessage("Public bundle", 130, bundleHex));
      setInvalidField("bundle");
      setPinned(null);
      return;
    }
    if (!isFixedHex(fingerprintHex, 64)) {
      setError(hexValidationMessage("Full fingerprint", 64, fingerprintHex));
      setInvalidField("fingerprint");
      setPinned(null);
      return;
    }

    setActiveTask("pin");
    setError(null);
    setInvalidField(null);
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
      setActiveTask(null);
    }
  }

  async function lookUpPin() {
    if (!isFixedHex(fingerprintHex, 64)) {
      setError(hexValidationMessage("Full fingerprint", 64, fingerprintHex));
      setInvalidField("fingerprint");
      setPinned(null);
      return;
    }

    setActiveTask("lookup");
    setError(null);
    setInvalidField(null);
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
      setActiveTask(null);
    }
  }

  return (
    <>
      <section className="identity-csr" aria-labelledby="identity-csr-title">
        <h4 id="identity-csr-title">Device certificate request</h4>
        <p>
          Generate a PKCS#10 request for a certificate authority. The request binds this device's
          signing key to its full-fingerprint URI; it never exports private key material. The issued
          certificate must preserve that URI. This client does not issue or validate certificates.
        </p>
        {runtimeAvailable ? (
          <div className="identity-pin-actions">
            <button
              type="button"
              disabled={busy || !identityReady}
              onClick={() => void createCertificateRequest()}
            >
              {activeTask === "csr" ? "Generating…" : "Generate certificate request"}
            </button>
          </div>
        ) : (
          <p>Open the Tauri desktop app to generate a local certificate request.</p>
        )}
        {!identityReady && runtimeAvailable && (
          <p>Initialize or open the protected device identity before generating a request.</p>
        )}
        {csrPem && (
          <>
            <label className="identity-csr-output">
              Certificate signing request (PEM)
              <textarea
                readOnly
                rows={10}
                spellCheck={false}
                value={csrPem}
                aria-label="Certificate signing request in PEM format"
              />
            </label>
            <div className="identity-pin-actions">
              <button type="button" disabled={busy} onClick={() => void copyCertificateRequest()}>
                Copy PEM
              </button>
            </div>
            <p role="status" aria-live="polite">
              {csrCopyStatus}
            </p>
          </>
        )}
        {csrError && <p role="alert">{csrError}</p>}
      </section>
      <section className="identity-pin" aria-labelledby="identity-pin-title">
        <h4 id="identity-pin-title">Pin a peer identity</h4>
        <p>
          Compare the full fingerprint out of band before saving these public bytes. A pin does not
          connect to that peer or add it to a Space.
        </p>
        {runtimeAvailable ? (
          <form
            className="identity-pin-form"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void pinIdentity();
            }}
          >
            <div className="identity-pin-fields">
              <label>
                Public bundle (65 bytes, 130 hex characters)
                <input
                  type="text"
                  value={bundleHex}
                  maxLength={130}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  aria-invalid={invalidField === "bundle"}
                  aria-describedby={error ? "pin-error" : undefined}
                  disabled={busy || !identityReady}
                  onChange={(event) => {
                    setBundleHex(event.currentTarget.value);
                    clearPinResult();
                  }}
                />
              </label>
              <label>
                Full fingerprint (32 bytes, 64 hex characters)
                <input
                  type="text"
                  value={fingerprintHex}
                  maxLength={64}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  aria-invalid={invalidField === "fingerprint"}
                  aria-describedby={error ? "pin-error" : undefined}
                  disabled={busy || !identityReady}
                  onChange={(event) => {
                    setFingerprintHex(event.currentTarget.value);
                    clearPinResult();
                  }}
                />
              </label>
            </div>
            {!identityReady && (
              <p>
                Initialize or open the protected device identity before saving or looking up pins.
              </p>
            )}
            <div className="identity-pin-actions">
              <button type="submit" disabled={busy || !identityReady}>
                {activeTask === "pin" ? "Saving…" : "Pin exact identity"}
              </button>
              <button
                type="button"
                disabled={busy || !identityReady}
                onClick={() => void lookUpPin()}
              >
                {activeTask === "lookup" ? "Looking up…" : "Look up saved pin"}
              </button>
            </div>
          </form>
        ) : (
          <p>Open the Tauri desktop app to save or look up a local pin.</p>
        )}
        {error && (
          <p id="pin-error" role="alert">
            {error}
          </p>
        )}
        <p role="status" aria-live="polite">
          {status}
        </p>
        {pinned && (
          <div className="identity-pin-result" aria-live="polite">
            <p>
              Pinned fingerprint: <code>{pinned.fingerprint}</code>
            </p>
            <p>
              Public bundle: <code>{pinned.publicBundle}</code>
            </p>
          </div>
        )}
      </section>
    </>
  );
}
