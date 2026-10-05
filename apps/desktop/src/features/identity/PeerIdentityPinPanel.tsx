import { ActionButton, FormField, StatusNotice } from "@lattice/ui-shared";
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

type ActiveTask = "csr" | "pin" | "lookup" | "unpin" | null;

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

  async function unpinIdentity() {
    if (!isFixedHex(fingerprintHex, 64)) {
      setError(hexValidationMessage("Full fingerprint", 64, fingerprintHex));
      setInvalidField("fingerprint");
      return;
    }
    if (!pinned || pinned.fingerprint.toLowerCase() !== fingerprintHex.toLowerCase()) {
      setError("Look up the exact locally pinned fingerprint before removing it.");
      setInvalidField("fingerprint");
      return;
    }

    setActiveTask("unpin");
    setError(null);
    setInvalidField(null);
    try {
      const removed = await invoke<boolean>("unpin_peer_identity", { fingerprintHex });
      setPinned(null);
      setStatus(
        removed
          ? "Local peer pin removed. This does not revoke the remote identity or change Space membership."
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
        <h3 id="identity-csr-title">Device certificate request</h3>
        <p>
          Generate a PKCS#10 request for a certificate authority. The request binds this device's
          signing key to its full-fingerprint URI; it never exports private key material. The issued
          certificate must preserve that URI. This client does not issue or validate certificates.
        </p>
        {runtimeAvailable ? (
          <div className="identity-pin-actions">
            <ActionButton
              type="button"
              tone="quiet"
              disabled={busy || !identityReady}
              onClick={() => void createCertificateRequest()}
            >
              {activeTask === "csr" ? "Generating…" : "Generate certificate request"}
            </ActionButton>
          </div>
        ) : (
          <p>Open the Tauri desktop app to generate a local certificate request.</p>
        )}
        {!identityReady && runtimeAvailable && (
          <p>Initialize or open the protected device identity before generating a request.</p>
        )}
        {csrPem && (
          <>
            <div className="identity-csr-output">
              <FormField label="Certificate signing request (PEM)" htmlFor="identity-csr-pem">
                <textarea
                  id="identity-csr-pem"
                  readOnly
                  rows={10}
                  spellCheck={false}
                  value={csrPem}
                  aria-label="Certificate signing request in PEM format"
                />
              </FormField>
            </div>
            <div className="identity-pin-actions">
              <ActionButton
                type="button"
                tone="quiet"
                disabled={busy}
                onClick={() => void copyCertificateRequest()}
              >
                Copy PEM
              </ActionButton>
            </div>
            <StatusNotice kind={csrError ? "error" : "success"}>
              {csrError ?? csrCopyStatus}
            </StatusNotice>
          </>
        )}
      </section>
      <section className="identity-pin" aria-labelledby="identity-pin-title">
        <h3 id="identity-pin-title">Pin a peer identity</h3>
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
              <FormField
                label="Public bundle (65 bytes, 130 hex characters)"
                htmlFor="peer-pin-public-bundle"
                error={invalidField === "bundle" ? (error ?? undefined) : undefined}
              >
                <input
                  id="peer-pin-public-bundle"
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
              </FormField>
              <FormField
                label="Full fingerprint (32 bytes, 64 hex characters)"
                htmlFor="peer-pin-fingerprint"
                error={invalidField === "fingerprint" ? (error ?? undefined) : undefined}
              >
                <input
                  id="peer-pin-fingerprint"
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
              </FormField>
            </div>
            {!identityReady && (
              <p>
                Initialize or open the protected device identity before saving or looking up pins.
              </p>
            )}
            <div className="identity-pin-actions">
              <ActionButton type="submit" tone="primary" disabled={busy || !identityReady}>
                {activeTask === "pin" ? "Saving…" : "Pin exact identity"}
              </ActionButton>
              <ActionButton
                type="button"
                tone="quiet"
                disabled={busy || !identityReady}
                onClick={() => void lookUpPin()}
              >
                {activeTask === "lookup" ? "Looking up…" : "Look up saved pin"}
              </ActionButton>
              {pinned && (
                <ActionButton
                  type="button"
                  tone="danger"
                  disabled={busy || !identityReady}
                  onClick={() => void unpinIdentity()}
                >
                  {activeTask === "unpin" ? "Removing local pin…" : "Remove local pin"}
                </ActionButton>
              )}
            </div>
          </form>
        ) : (
          <p>Open the Tauri desktop app to save or look up a local pin.</p>
        )}
        {error && <StatusNotice kind="error">{error}</StatusNotice>}
        <StatusNotice kind={status ? "success" : "info"}>{status}</StatusNotice>
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
