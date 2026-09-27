import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

type LocalSpaceCreation = {
  state: "local_genesis_created";
  spaceId: string;
  groupReference: string;
  genesisEventId: string;
  creatorFingerprint: string;
  localSnapshotPersisted: boolean;
  membershipClaimed: boolean;
  networkContacted: boolean;
};

type LocalSpaceCreatorProps = {
  runtimeAvailable: boolean;
  identityReady: boolean;
};

const MAX_CREDENTIAL_HEX_LENGTH = 32_768;
const MAX_CHANNEL_NAME_UTF8_BYTES = 128;

function isCredentialVectorHex(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_CREDENTIAL_HEX_LENGTH &&
    value.length % 2 === 0 &&
    /^[\da-f]+$/i.test(value)
  );
}

function isValidChannelName(value: string): boolean {
  return (
    value.trim().length > 0 &&
    value.length <= MAX_CHANNEL_NAME_UTF8_BYTES &&
    !value.includes("\0") &&
    new TextEncoder().encode(value).byteLength <= MAX_CHANNEL_NAME_UTF8_BYTES
  );
}

export function LocalSpaceCreator({ runtimeAvailable, identityReady }: LocalSpaceCreatorProps) {
  const [credentialVectorHex, setCredentialVectorHex] = useState("");
  const [channelName, setChannelName] = useState("general");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<LocalSpaceCreation | null>(null);

  async function createLocalSpace() {
    setBusy(true);
    setError(null);
    setCreated(null);
    try {
      const result = await invoke<LocalSpaceCreation>("create_local_space", {
        credentialVectorHex,
        channelNames: [channelName],
      });
      setCreated(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="space-browser" aria-labelledby="space-create-title" aria-busy={busy}>
      <div className="space-browser-heading">
        <div>
          <h3 id="space-create-title">Create a local Space</h3>
          <p>
            Supply the exact RFC 9420 TLS X.509 credential vector in hex. The OS trust store and
            local identity are checked before the Genesis transaction; this does not join another
            member.
          </p>
        </div>
      </div>
      {!runtimeAvailable && (
        <p>Open the desktop app to create a Space in its protected local store.</p>
      )}
      {runtimeAvailable && !identityReady && (
        <p>Initialize or reopen the protected device identity before creating a local Space.</p>
      )}
      <div className="identity-pin-fields">
        <label htmlFor="space-credential-vector">Trusted X.509 credential vector (hex)</label>
        <textarea
          id="space-credential-vector"
          autoComplete="off"
          maxLength={MAX_CREDENTIAL_HEX_LENGTH}
          disabled={!runtimeAvailable || !identityReady || busy}
          value={credentialVectorHex}
          onChange={(event) => {
            setCredentialVectorHex(event.currentTarget.value);
            setError(null);
            setCreated(null);
          }}
          spellCheck={false}
          aria-describedby="space-credential-help"
        />
        <p id="space-credential-help">
          Maximum 16 KiB before hex encoding. The leaf certificate must match this device's signing
          key and full identity fingerprint.
        </p>
        <label htmlFor="space-channel-name">Initial text channel name</label>
        <input
          id="space-channel-name"
          autoComplete="off"
          maxLength={MAX_CHANNEL_NAME_UTF8_BYTES}
          disabled={!runtimeAvailable || !identityReady || busy}
          value={channelName}
          onChange={(event) => {
            setChannelName(event.currentTarget.value);
            setError(null);
            setCreated(null);
          }}
        />
        <p>Channel names must be nonblank, contain no NUL, and fit in 128 UTF-8 bytes.</p>
        <div className="identity-actions">
          <button
            type="button"
            disabled={
              !runtimeAvailable ||
              !identityReady ||
              busy ||
              !isCredentialVectorHex(credentialVectorHex) ||
              !isValidChannelName(channelName)
            }
            onClick={() => void createLocalSpace()}
          >
            {busy ? "Creating…" : "Create local Space"}
          </button>
        </div>
      </div>
      {busy && <p role="status">Validating the credential and committing local MLS state…</p>}
      {error && <p role="alert">Could not create the local Space: {error}</p>}
      {created && (
        <div className="identity-status" role="status" aria-live="polite">
          <p>A local Genesis and initial text channel were committed; no network was contacted.</p>
          <p>
            Space ID: <code>{created.spaceId}</code>
          </p>
          <p>
            MLS group reference: <code>{created.groupReference}</code>
          </p>
          <p>
            Genesis event ID: <code>{created.genesisEventId}</code>
          </p>
          <p>
            Creator fingerprint: <code>{created.creatorFingerprint}</code>
          </p>
          <p>Remote membership is not established.</p>
        </div>
      )}
    </section>
  );
}
