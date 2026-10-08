import { DesktopPage, DesktopWorkspaceShell } from "@lattice/ui-desktop";
import { ActionButton, LatticeLogo, StatusNotice, type WorkspaceChannel } from "@lattice/ui-shared";
import { ArrowsLeftRight, ChatCircle, Fingerprint, SquaresFour } from "@phosphor-icons/react";
import { invoke } from "@tauri-apps/api/core";
import { useCallback, useState } from "react";
import { DirectMessagePanel } from "./features/identity/DirectMessagePanel";
import { PeerIdentityPinPanel } from "./features/identity/PeerIdentityPinPanel";
import { LocalNetworkSettings } from "./features/network/LocalNetworkSettings";
import { PersistentPeerMode } from "./features/network/PersistentPeerMode";
import type { WorkspaceSpaceSnapshot } from "./features/spaces/LocalSpaceBrowser";
import { LocalSpaceBrowser } from "./features/spaces/LocalSpaceBrowser";
import { LocalSpaceCreator } from "./features/spaces/LocalSpaceCreator";
import "./App.css";

type Destination = "spaces" | "direct-messages" | "connections" | "identity";

const destinations = [
  { id: "spaces", label: "Spaces", icon: <SquaresFour size={20} weight="regular" /> },
  {
    id: "direct-messages",
    label: "Direct messages",
    icon: <ChatCircle size={20} weight="regular" />,
  },
  {
    id: "connections",
    label: "Connections",
    icon: <ArrowsLeftRight size={20} weight="regular" />,
  },
  { id: "identity", label: "Identity", icon: <Fingerprint size={20} weight="regular" /> },
] as const;

type IdentityStatus = {
  fingerprint: string;
  public_bundle: string;
  next_author_sequence: number;
};

function App() {
  const [destination, setDestination] = useState<Destination>("spaces");
  const [identity, setIdentity] = useState<IdentityStatus | null>(null);
  const [spaces, setSpaces] = useState<WorkspaceSpaceSnapshot[]>([]);
  const [activeSpace, setActiveSpace] = useState<string | null>(null);
  const [activeChannel, setActiveChannel] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  const [copyError, setCopyError] = useState<string | null>(null);
  const runtimeAvailable = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

  async function runIdentityCommand(command: "initialize_device_identity" | "get_device_identity") {
    setBusy(true);
    setError(null);
    try {
      setIdentity(await invoke<IdentityStatus>(command));
    } catch (cause) {
      setIdentity(null);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function copyIdentityValue(label: string, value: string) {
    setCopyStatus("");
    setCopyError(null);
    try {
      await navigator.clipboard.writeText(value);
      setCopyStatus(`${label} copied to the clipboard.`);
    } catch (cause) {
      setCopyError(
        cause instanceof Error
          ? `Could not copy ${label.toLowerCase()}: ${cause.message}. Select the value and copy it instead.`
          : `Could not copy ${label.toLowerCase()}. Select the value and copy it instead.`,
      );
    }
  }

  const handleSpacesChange = useCallback(
    (items: WorkspaceSpaceSnapshot[]) => {
      setSpaces(items);
      setActiveSpace((current) =>
        current && items.some((space) => space.id === current) ? current : (items[0]?.id ?? null),
      );
      setActiveChannel((current) => {
        const selected = items.find((space) => space.id === activeSpace) ?? items[0];
        return current && selected?.channels.some((channel) => channel.id === current)
          ? current
          : (selected?.channels[0]?.id ?? null);
      });
    },
    [activeSpace],
  );

  const channels: readonly WorkspaceChannel[] =
    spaces.find((space) => space.id === activeSpace)?.channels ?? [];
  const navigation = {
    destinations,
    activeDestination: destination,
    onDestinationChange: (id: string) => {
      if (destinations.some((item) => item.id === id)) setDestination(id as Destination);
    },
    spaces,
    activeSpace,
    onSpaceChange: (id: string) => {
      setActiveSpace(id);
      const selected = spaces.find((space) => space.id === id);
      setActiveChannel(selected?.channels[0]?.id ?? null);
    },
    channels,
    activeChannel,
    onChannelChange: setActiveChannel,
  } as const;
  return (
    <div className="desktop-app">
      <header className="desktop-topbar">
        <a className="brand" href="/" aria-label="Lattice home">
          <LatticeLogo />
        </a>
        <span className="stage">Local client</span>
      </header>
      <DesktopWorkspaceShell {...navigation}>
        <div className="workspace-pages">
          <div className="workspace-page" hidden={destination !== "spaces"}>
            <DesktopPage
              id="spaces"
              title="Spaces"
              description="Local Space snapshots, channels, and message history. Membership and message state remain local until an explicit authenticated exchange."
            >
              <div className="workspace-content">
                <LocalSpaceCreator
                  runtimeAvailable={runtimeAvailable}
                  identityReady={identity !== null}
                />
                <LocalSpaceBrowser
                  runtimeAvailable={runtimeAvailable}
                  onSpacesChange={handleSpacesChange}
                  activeSpace={activeSpace}
                  activeChannel={activeChannel}
                  onChannelChange={setActiveChannel}
                />
              </div>
            </DesktopPage>
          </div>
          <div className="workspace-page" hidden={destination !== "direct-messages"}>
            <DesktopPage
              id="direct-messages"
              title="Direct messages"
              description="Pairwise messages use the existing pinned-peer workflow. All data stays local to this device."
            >
              <DirectMessagePanel
                runtimeAvailable={runtimeAvailable}
                identityReady={identity !== null}
              />
            </DesktopPage>
          </div>
          <div className="workspace-page" hidden={destination !== "connections"}>
            <DesktopPage
              id="connections"
              title="Connections"
              description="Configure local network paths and peer courier behavior."
            >
              <div className="destination-layout">
                <LocalNetworkSettings runtimeAvailable={runtimeAvailable} />
                <PersistentPeerMode runtimeAvailable={runtimeAvailable} />
              </div>
            </DesktopPage>
          </div>
          <div className="workspace-page" hidden={destination !== "identity"}>
            <DesktopPage
              id="identity"
              title="Identity"
              description="Manage this device's protected identity and exact peer pins."
            >
              <section className="identity-section" aria-labelledby="identity-title">
                <h2 id="identity-title">Device identity</h2>
                <p>
                  Private keys are never displayed. Initializing uses the OS credential store and
                  persists only protected key material in the local database.
                </p>
                {runtimeAvailable ? (
                  <div className="identity-actions">
                    <ActionButton
                      tone="primary"
                      disabled={busy}
                      onClick={() => void runIdentityCommand("initialize_device_identity")}
                    >
                      {busy ? "Working…" : "Initialize or reopen identity"}
                    </ActionButton>
                    <ActionButton
                      tone="quiet"
                      disabled={busy}
                      onClick={() => void runIdentityCommand("get_device_identity")}
                    >
                      Show existing identity
                    </ActionButton>
                  </div>
                ) : (
                  <p>Open the Tauri desktop app to use its native OS-keyring commands.</p>
                )}
                {busy && (
                  <StatusNotice kind="info">Opening the protected local identity…</StatusNotice>
                )}
                {error && <StatusNotice kind="error">{error}</StatusNotice>}
                {identity && (
                  <div className="identity-status" aria-live="polite">
                    <p>
                      Local identity fingerprint: <code>{identity.fingerprint}</code>
                    </p>
                    <div className="identity-actions">
                      <ActionButton
                        tone="quiet"
                        onClick={() => void copyIdentityValue("Fingerprint", identity.fingerprint)}
                      >
                        Copy fingerprint
                      </ActionButton>
                    </div>
                    <p>Next local author sequence: {identity.next_author_sequence}</p>
                    <details>
                      <summary>Public identity bundle</summary>
                      <code>{identity.public_bundle}</code>
                      <div className="identity-actions">
                        <ActionButton
                          tone="quiet"
                          onClick={() =>
                            void copyIdentityValue("Public bundle", identity.public_bundle)
                          }
                        >
                          Copy public bundle
                        </ActionButton>
                      </div>
                    </details>
                    <p role="status" aria-live="polite">
                      {copyStatus}
                    </p>
                    {copyError && <StatusNotice kind="error">{copyError}</StatusNotice>}
                  </div>
                )}
                <PeerIdentityPinPanel
                  runtimeAvailable={runtimeAvailable}
                  identityReady={identity !== null}
                />
              </section>
            </DesktopPage>
          </div>
        </div>
      </DesktopWorkspaceShell>
      <footer className="desktop-footer">
        <span>No project cloud is required.</span>
        <span>Capabilities appear only when implemented and verified.</span>
      </footer>
    </div>
  );
}

export default App;
