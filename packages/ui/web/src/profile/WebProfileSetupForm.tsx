import { ActionButton, FormField, StatusNotice } from "@lattice/ui-shared";

export function WebProfileSetupForm({
  profileId,
  rootCertificate,
  rootFingerprint,
  busy,
  error,
  onProfileIdChange,
  onRootCertificateChange,
  onRootFingerprintChange,
  onOpenSavedProfile,
  onCreateWithPinnedRoot,
}: {
  profileId: string;
  rootCertificate: string;
  rootFingerprint: string;
  busy: boolean;
  error: string | null;
  onProfileIdChange: (value: string) => void;
  onRootCertificateChange: (value: string) => void;
  onRootFingerprintChange: (value: string) => void;
  onOpenSavedProfile: () => void;
  onCreateWithPinnedRoot: () => void;
}) {
  return (
    <section className="setup-grid" aria-labelledby="setup-title">
      <div className="setup-lead">
        <p className="eyebrow">Start on this device</p>
        <h2 id="setup-title">Open a local profile</h2>
        <p>
          A profile uses a dedicated worker, one SQLite connection and an exclusive same-origin
          lock. Unsupported storage fails closed; there is no memory-only fallback.
        </p>
        <div className="boundary-note">
          <span className="boundary-mark" aria-hidden="true" />
          <p>
            The issuer root is pinned when a profile is created. The exact certificate and
            fingerprint stay inside this browser profile.
          </p>
        </div>
      </div>
      <form
        className="profile-form"
        onSubmit={(event) => {
          event.preventDefault();
          onOpenSavedProfile();
        }}
      >
        <FormField
          label="Profile label"
          htmlFor="profile-id"
          hint="A local name only. It is not an account or a network identity."
        >
          <input
            autoComplete="off"
            id="profile-id"
            maxLength={128}
            onChange={(event) => onProfileIdChange(event.target.value)}
            required
            value={profileId}
          />
        </FormField>
        <details className="pin-details">
          <summary>Create with a confirmed issuer root</summary>
          <div className="pin-fields">
            <FormField label="Issuer root certificate · DER hex" htmlFor="root-certificate">
              <textarea
                autoCapitalize="off"
                autoComplete="off"
                id="root-certificate"
                onChange={(event) => onRootCertificateChange(event.target.value)}
                placeholder="Paste the complete DER certificate in hexadecimal"
                spellCheck={false}
                value={rootCertificate}
              />
            </FormField>
            <FormField
              label="Confirmed SHA-256 fingerprint"
              htmlFor="root-fingerprint"
              hint="Verify this fingerprint through a trusted out-of-band source before creating the profile."
            >
              <input
                autoCapitalize="characters"
                autoComplete="off"
                id="root-fingerprint"
                onChange={(event) => onRootFingerprintChange(event.target.value)}
                placeholder="64 hexadecimal characters"
                spellCheck={false}
                value={rootFingerprint}
              />
            </FormField>
            <ActionButton
              className="button button-primary"
              disabled={
                busy ||
                profileId.trim().length === 0 ||
                rootCertificate.length === 0 ||
                rootFingerprint.length === 0
              }
              onClick={(event) => {
                event.preventDefault();
                onCreateWithPinnedRoot();
              }}
              type="button"
            >
              {busy ? "Opening profile…" : "Create profile with this pin"}
            </ActionButton>
          </div>
        </details>
        <ActionButton
          className="button button-primary"
          disabled={busy || profileId.trim().length === 0}
          type="submit"
        >
          {busy ? "Opening profile…" : "Open saved profile"}
        </ActionButton>
        {error && <StatusNotice kind="error">{error}</StatusNotice>}
      </form>
    </section>
  );
}
