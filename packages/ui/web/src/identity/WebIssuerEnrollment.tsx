import { ActionButton, FormField } from "@lattice/ui-shared";

export function WebIssuerEnrollment({
  busy,
  csrPem,
  certificateHex,
  onCreateCsr,
  onCertificateChange,
}: {
  busy: boolean;
  csrPem: string;
  certificateHex: string;
  onCreateCsr: () => void;
  onCertificateChange: (value: string) => void;
}) {
  return (
    <section className="web-controls" aria-labelledby="credential-title">
      <div className="control-heading">
        <p className="eyebrow">Issuer enrollment</p>
        <h2 id="credential-title">Issue this device certificate</h2>
      </div>
      <p className="field-hint">
        Core creates the private key and CSR. Have the issuer pinned at profile creation sign the
        CSR, then paste only the issued leaf certificate DER here.
      </p>
      <ActionButton
        className="button button-quiet"
        type="button"
        onClick={onCreateCsr}
        disabled={busy}
      >
        Create certificate signing request
      </ActionButton>
      {csrPem && <textarea aria-label="Certificate signing request PEM" readOnly value={csrPem} />}
      <FormField label="Issued device certificate · DER hex" htmlFor="device-certificate">
        <textarea
          id="device-certificate"
          value={certificateHex}
          onChange={(event) => onCertificateChange(event.target.value)}
          placeholder="Paste the issued leaf certificate in hexadecimal"
          spellCheck={false}
          autoComplete="off"
        />
      </FormField>
    </section>
  );
}
