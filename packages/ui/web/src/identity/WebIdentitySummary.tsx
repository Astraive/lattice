import { Panel } from "@lattice/ui-shared";

export function WebIdentitySummary({
  profileId,
  fingerprint,
}: {
  profileId: string;
  fingerprint: string;
}) {
  return (
    <Panel className="lattice-web-identity-summary">
      <dl className="identity-data">
        <div className="identity-row">
          <dt>Profile label</dt>
          <dd>{profileId}</dd>
        </div>
        <div className="identity-row">
          <dt>Identity fingerprint</dt>
          <dd className="fingerprint">{fingerprint}</dd>
        </div>
        <div className="identity-row">
          <dt>Storage</dt>
          <dd>SQLite in this browser&apos;s Origin Private File System</dd>
        </div>
        <div className="identity-row">
          <dt>Key protection</dt>
          <dd>Non-extractable Web Crypto key, scoped to this origin and profile</dd>
        </div>
      </dl>
      <p className="protection-note">
        Protection is browser-origin scoped. It is not equivalent to a hardware-backed mobile key or
        an operating-system keychain.
      </p>
    </Panel>
  );
}
