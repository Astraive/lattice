import { ActionButton, EmptyState, FormField } from "@lattice/ui-shared";
import type { ReactNode } from "react";

export function WebSpaceManagement({
  children,
  busy,
  hasSelectedSpace,
  certificateHex,
  onCreateSpace,
  keyPackageHex,
  onPublishKeyPackage,
  targetKeyPackageHex,
  onTargetKeyPackageChange,
  onCreateInvite,
  welcomeHex,
  onWelcomeChange,
  inviterFingerprintHex,
  onInviterFingerprintChange,
  inviterBundleHex,
  onInviterBundleChange,
  inviterPinned,
  onPinInviter,
  onJoinSpace,
  ownFingerprint,
  ownPublicBundle,
}: {
  children: ReactNode;
  busy: boolean;
  hasSelectedSpace: boolean;
  certificateHex: string;
  onCreateSpace: () => void;
  keyPackageHex: string;
  onPublishKeyPackage: () => void;
  targetKeyPackageHex: string;
  onTargetKeyPackageChange: (value: string) => void;
  onCreateInvite: () => void;
  welcomeHex: string;
  onWelcomeChange: (value: string) => void;
  inviterFingerprintHex: string;
  onInviterFingerprintChange: (value: string) => void;
  inviterBundleHex: string;
  onInviterBundleChange: (value: string) => void;
  inviterPinned: boolean;
  onPinInviter: () => void;
  onJoinSpace: () => void;
  ownFingerprint: string;
  ownPublicBundle: string;
}) {
  return (
    <>
      <section className="web-controls" aria-labelledby="spaces-title">
        <div className="control-heading">
          <p className="eyebrow">Spaces on this profile</p>
          <h2 id="spaces-title">Create or join a Space</h2>
        </div>
        <ActionButton
          className="button button-primary"
          type="button"
          onClick={onCreateSpace}
          disabled={busy || !certificateHex.trim()}
        >
          Create a Space with #general
        </ActionButton>
        {children}
        {!hasSelectedSpace && (
          <EmptyState
            title="No Space selected"
            body="Create or join a Space to see its channels and locally accepted message history."
          />
        )}
      </section>
      <section className="web-controls" aria-labelledby="invite-title">
        <div className="control-heading">
          <p className="eyebrow">Manual offline transfer</p>
          <h2 id="invite-title">Invite a profile</h2>
        </div>
        <p className="field-hint">
          Transfer KeyPackages, signed Welcome bootstraps, and inviter identity details out of band.
          Verify the full fingerprint through an independent trusted channel before pinning.
        </p>
        <ActionButton
          className="button button-quiet"
          type="button"
          onClick={onPublishKeyPackage}
          disabled={busy || !certificateHex.trim()}
        >
          Publish my KeyPackage
        </ActionButton>
        {keyPackageHex && (
          <FormField label="My KeyPackage · copy to inviter" htmlFor="own-key-package">
            <textarea id="own-key-package" readOnly value={keyPackageHex} spellCheck={false} />
          </FormField>
        )}
        <FormField label="Invited KeyPackage · hex" htmlFor="target-package">
          <textarea
            id="target-package"
            value={targetKeyPackageHex}
            onChange={(event) => onTargetKeyPackageChange(event.target.value)}
            spellCheck={false}
          />
        </FormField>
        <ActionButton
          className="button button-primary"
          type="button"
          onClick={onCreateInvite}
          disabled={
            busy || !hasSelectedSpace || !certificateHex.trim() || !targetKeyPackageHex.trim()
          }
        >
          Commit invite and create Welcome
        </ActionButton>
        {welcomeHex && (
          <>
            <FormField
              label="Welcome bootstrap · copy to invited profile"
              htmlFor="welcome-bootstrap"
            >
              <textarea id="welcome-bootstrap" readOnly value={welcomeHex} spellCheck={false} />
            </FormField>
            <FormField
              label="Inviter identity fingerprint · transfer, then verify out of band"
              htmlFor="inviter-fingerprint-export"
            >
              <textarea
                id="inviter-fingerprint-export"
                readOnly
                value={ownFingerprint}
                spellCheck={false}
              />
            </FormField>
            <FormField
              label="Inviter public identity bundle · copy to invited profile"
              htmlFor="inviter-bundle-export"
            >
              <textarea
                id="inviter-bundle-export"
                readOnly
                value={ownPublicBundle}
                spellCheck={false}
              />
            </FormField>
          </>
        )}
        <FormField label="Join using Welcome bootstrap · hex" htmlFor="join-welcome">
          <textarea
            id="join-welcome"
            value={welcomeHex}
            onChange={(event) => onWelcomeChange(event.target.value)}
            spellCheck={false}
          />
        </FormField>
        <FormField label="Expected inviter fingerprint · hex" htmlFor="join-inviter">
          <input
            id="join-inviter"
            value={inviterFingerprintHex}
            onChange={(event) => onInviterFingerprintChange(event.target.value)}
            spellCheck={false}
          />
        </FormField>
        <FormField label="Inviter public identity bundle · hex" htmlFor="join-inviter-bundle">
          <textarea
            id="join-inviter-bundle"
            value={inviterBundleHex}
            onChange={(event) => onInviterBundleChange(event.target.value)}
            spellCheck={false}
          />
        </FormField>
        <p className="field-hint">
          Pinning records trust only after you compare the full fingerprint with the inviter through
          an independent trusted channel.
        </p>
        <ActionButton
          className="button button-quiet"
          type="button"
          onClick={onPinInviter}
          disabled={busy || !inviterBundleHex.trim() || !inviterFingerprintHex.trim()}
        >
          Verify bundle against fingerprint and pin
        </ActionButton>
        <ActionButton
          className="button button-quiet"
          type="button"
          onClick={onJoinSpace}
          disabled={
            busy ||
            !inviterPinned ||
            !certificateHex.trim() ||
            !welcomeHex.trim() ||
            !inviterFingerprintHex.trim()
          }
        >
          Validate Welcome and join
        </ActionButton>
      </section>
    </>
  );
}
