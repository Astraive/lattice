import { EmptyState, StatusNotice } from "@lattice/ui-shared";
import {
  WebCliLoopbackControls,
  WebConnectionDisclosure,
  WebConnectionsPage,
  WebIdentityPage,
  WebIdentitySummary,
  WebIssuerEnrollment,
  WebMessageHistory,
  WebProfileGate,
  WebProfileSetupForm,
  WebSetupPage,
  WebSpaceManagement,
  WebSpacesPage,
  WebWebRtcControls,
  WebWorkspaceShell,
} from "@lattice/ui-web";
import { ArrowsLeftRight, Fingerprint, SquaresFour } from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type HistoryMessage,
  type InviteArtifact,
  parseIceServers,
  type SpaceRecord,
  spaceKey,
  toHex,
  toPem,
} from "./app-utils";
import { CliLoopbackEventLink } from "./cli-loopback-link";
import { messagesForScope, type ScopedHistory } from "./history-scope";
import { formatFingerprint, parseHexBytes } from "./identity";
import { WebRtcEventLink } from "./webrtc-event-link";
import { type OpenedProfile, ProfileWorkerClient } from "./worker-client";

export default function App() {
  const worker = useRef<ProfileWorkerClient | null>(null);
  const messageHistoryRequestId = useRef(0);
  const broadcast = useRef<BroadcastChannel | null>(null);
  const rtcLink = useRef<WebRtcEventLink | null>(null);
  const [signalText, setSignalText] = useState("");
  const [rtcStatus, setRtcStatus] = useState("Not connected");
  const [profileId, setProfileId] = useState("local-profile");
  const [rootDerText, setRootDerText] = useState("");
  const [rootPinText, setRootPinText] = useState("");
  const [openedProfile, setOpenedProfile] = useState<OpenedProfile | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [iceServersText, setIceServersText] = useState("");
  const [cliBridgeUrl, setCliBridgeUrl] = useState("ws://127.0.0.1:7448/lattice-sync");
  const [cliBridgeToken, setCliBridgeToken] = useState("");
  const [cliBridgeStatus, setCliBridgeStatus] = useState("Not connected");
  const [certificateHex, setCertificateHex] = useState("");
  const [csrPem, setCsrPem] = useState("");
  const [spaces, setSpaces] = useState<SpaceRecord[]>([]);
  const [selectedSpaceKey, setSelectedSpaceKey] = useState("");
  const [keyPackageHex, setKeyPackageHex] = useState("");
  const [targetKeyPackageHex, setTargetKeyPackageHex] = useState("");
  const [welcomeHex, setWelcomeHex] = useState("");
  const [inviterFingerprintHex, setInviterFingerprintHex] = useState("");
  const [inviterBundleHex, setInviterBundleHex] = useState("");
  const [inviterPinned, setInviterPinned] = useState(false);
  const [messageDraft, setMessageDraft] = useState("");
  const [messageHistory, setMessageHistory] = useState<ScopedHistory<HistoryMessage>>(null);
  const [activeDestination, setActiveDestination] = useState("spaces");
  const [selectedChannelId, setSelectedChannelId] = useState("");

  const selectedSpace = spaces.find((space) => spaceKey(space) === selectedSpaceKey);
  const selectedChannel =
    selectedSpace?.channels.find((channel) => toHex(channel.id) === selectedChannelId) ??
    selectedSpace?.channels.find((channel) => channel.channel_type === "text");
  const activeHistoryScope =
    selectedSpace && selectedChannel
      ? `${spaceKey(selectedSpace)}:${toHex(selectedChannel.id)}`
      : "";
  const activeHistoryScopeRef = useRef(activeHistoryScope);
  activeHistoryScopeRef.current = activeHistoryScope;
  const messages = messagesForScope(activeHistoryScope, messageHistory);
  const historyLoading =
    Boolean(openedProfile && selectedSpace && selectedChannel) &&
    (!messageHistory || messageHistory.scope !== activeHistoryScope || messageHistory.loading);

  function closePeerConnection() {
    rtcLink.current?.close();
    rtcLink.current = null;
  }

  function currentRtcLink(): WebRtcEventLink {
    if (!worker.current || !selectedSpace) {
      throw new Error("Open a profile and select a Space before starting WebRTC.");
    }
    if (!rtcLink.current) {
      const space = selectedSpace;
      rtcLink.current = new WebRtcEventLink(
        worker.current,
        space,
        setRtcStatus,
        () => refreshHistory(space, selectedChannel),
        { iceServers: parseIceServers(iceServersText) },
      );
    }
    return rtcLink.current;
  }
  async function syncWithCli() {
    const profile = worker.current;
    const space = selectedSpace;
    if (!profile || !space) {
      setError("Open a profile and select a Space before connecting the CLI.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const link = new CliLoopbackEventLink(profile, space, setCliBridgeStatus, () =>
        refreshHistory(space, selectedChannel),
      );
      await link.reconcile(cliBridgeUrl, cliBridgeToken);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not sync with the CLI.");
    } finally {
      setBusy(false);
    }
  }
  const refreshHistory = useCallback(
    async (space: SpaceRecord | undefined = selectedSpace, channel = selectedChannel) => {
      const scope = space && channel ? `${spaceKey(space)}:${toHex(channel.id)}` : "";
      if (scope !== activeHistoryScopeRef.current) return;
      const requestId = ++messageHistoryRequestId.current;
      if (!openedProfile || !space || !channel) {
        setMessageHistory(null);
        return;
      }
      setMessageHistory({ scope, messages: [], loading: true });
      try {
        const result = await worker.current?.run<string>({
          operation: "message-history",
          spaceId: space.space_id,
          groupReference: space.group_reference,
          channelId: channel.id,
        });
        if (
          requestId !== messageHistoryRequestId.current ||
          scope !== activeHistoryScopeRef.current
        ) {
          return;
        }
        setMessageHistory({
          scope,
          messages: result ? (JSON.parse(result) as HistoryMessage[]) : [],
          loading: false,
        });
      } catch (cause) {
        if (
          requestId !== messageHistoryRequestId.current ||
          scope !== activeHistoryScopeRef.current
        ) {
          return;
        }
        setMessageHistory({ scope, messages: [], loading: false });
        throw cause;
      }
    },
    [openedProfile, selectedSpace, selectedChannel],
  );
  useEffect(
    () => () => {
      rtcLink.current?.close();
      broadcast.current?.close();
      void worker.current?.closeProfile();
    },
    [],
  );

  useEffect(() => {
    rtcLink.current?.close();
    rtcLink.current = null;
    broadcast.current?.close();
    broadcast.current = null;
    if (!openedProfile || !selectedSpace) return;

    const channelName = `lattice-space:${spaceKey(selectedSpace)}`;
    const channel = new BroadcastChannel(channelName);
    broadcast.current = channel;
    channel.addEventListener("message", (event: MessageEvent<unknown>) => {
      const value = event.data as { type?: unknown; canonicalEvent?: unknown };
      if (value?.type !== "signed-message-event" || !Array.isArray(value.canonicalEvent)) return;
      const canonicalEvent = value.canonicalEvent as number[];
      void worker.current
        ?.run({ operation: "accept-synced-event", canonicalEvent })
        .then(async () => {
          await refreshHistory(selectedSpace, selectedChannel);
        })
        .catch((cause: unknown) => {
          setError(cause instanceof Error ? cause.message : "A peer event was rejected.");
        });
    });
    return () => {
      channel.close();
      if (broadcast.current === channel) broadcast.current = null;
    };
  }, [openedProfile, selectedSpace, selectedChannel, refreshHistory]);

  useEffect(() => {
    void refreshHistory(selectedSpace, selectedChannel).catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : "Could not load message history.");
    });
  }, [refreshHistory, selectedSpace, selectedChannel]);

  async function openProfile(create: boolean) {
    setBusy(true);
    setError(null);
    setNotice(null);
    const client = new ProfileWorkerClient();
    try {
      const confirmedRoot = create
        ? {
            der: parseHexBytes(rootDerText),
            sha256: parseHexBytes(rootPinText, 32),
          }
        : undefined;
      const response = await client.openProfile(profileId.trim(), confirmedRoot);
      worker.current = client;
      setOpenedProfile(response);
      const spacesJson = await client.run<string>({ operation: "list-spaces" });
      const storedSpaces = JSON.parse(spacesJson) as SpaceRecord[];
      setSpaces(storedSpaces);
      setSelectedSpaceKey(storedSpaces[0] ? spaceKey(storedSpaces[0]) : "");
    } catch (cause) {
      await client.closeProfile().catch(() => undefined);
      if (worker.current === client) worker.current = null;
      setOpenedProfile(null);
      setError(cause instanceof Error ? cause.message : "The browser profile could not be opened.");
    } finally {
      setBusy(false);
    }
  }

  async function closeProfile() {
    setBusy(true);
    try {
      closePeerConnection();
      setIceServersText("");
      setCliBridgeToken("");
      setSignalText("");
      broadcast.current?.close();
      broadcast.current = null;
      await worker.current?.closeProfile();
      worker.current = null;
      setOpenedProfile(null);
      setSpaces([]);
      setSelectedSpaceKey("");
      setSelectedChannelId("");
      setActiveDestination("spaces");
      messageHistoryRequestId.current += 1;
      setMessageHistory(null);
      setMessageDraft("");
      setCertificateHex("");
      setCsrPem("");
      setKeyPackageHex("");
      setTargetKeyPackageHex("");
      setWelcomeHex("");
      setInviterFingerprintHex("");
      setInviterBundleHex("");
      setInviterPinned(false);
      setRootDerText("");
      setRootPinText("");
      setRtcStatus("Not connected");
      setCliBridgeStatus("Not connected");
      setError(null);
      setNotice(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The browser profile could not be closed.");
    } finally {
      setBusy(false);
    }
  }

  async function exportCsr() {
    setError(null);
    try {
      const der = await worker.current?.run<number[]>({ operation: "certificate-request" });
      if (!der) throw new Error("The signing request was not created.");
      setCsrPem(toPem(der, "CERTIFICATE REQUEST"));
      setNotice(
        "CSR created. Have the pinned issuer sign it, then paste the issued leaf certificate DER below.",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create a signing request.");
    }
  }

  async function createSpace() {
    setBusy(true);
    setError(null);
    try {
      const result = await worker.current?.run<string>({
        operation: "create-space",
        certificateDer: [...parseHexBytes(certificateHex)],
      });
      if (!result) throw new Error("Space creation returned no result.");
      const space = JSON.parse(result) as SpaceRecord;
      setSpaces((previous) => [...previous, space]);
      setSelectedSpaceKey(spaceKey(space));
      setNotice("Space created locally. Its signed Genesis is stored in this profile.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create the Space.");
    } finally {
      setBusy(false);
    }
  }

  async function publishKeyPackage() {
    setBusy(true);
    setError(null);
    try {
      const keyPackage = await worker.current?.run<number[]>({
        operation: "publish-key-package",
        certificateDer: [...parseHexBytes(certificateHex)],
      });
      if (!keyPackage) throw new Error("KeyPackage creation returned no result.");
      setKeyPackageHex(toHex(keyPackage));
      setNotice("A tracked one-time KeyPackage was published for manual invite transfer.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not publish a KeyPackage.");
    } finally {
      setBusy(false);
    }
  }

  async function createInvite() {
    if (!selectedSpace) return;
    setBusy(true);
    setError(null);
    try {
      const result = await worker.current?.run<string>({
        operation: "create-invite",
        spaceId: selectedSpace.space_id,
        groupReference: selectedSpace.group_reference,
        certificateDer: [...parseHexBytes(certificateHex)],
        keyPackage: [...parseHexBytes(targetKeyPackageHex)],
      });
      if (!result) throw new Error("Invite creation returned no result.");
      const invite = JSON.parse(result) as InviteArtifact;
      setWelcomeHex(toHex(invite.welcome_bootstrap));
      setInviterFingerprintHex(toHex(openedProfile?.identity.fingerprint ?? []));
      setNotice(
        "Invite committed. Transfer the signed Welcome bootstrap and inviter fingerprint to the invited profile.",
      );
      const updated = await worker.current?.run<string>({ operation: "list-spaces" });
      if (updated) setSpaces(JSON.parse(updated) as SpaceRecord[]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create the invite.");
    } finally {
      setBusy(false);
    }
  }

  async function pinInviterIdentity() {
    setBusy(true);
    setError(null);
    try {
      await worker.current?.run({
        operation: "pin-identity",
        publicBundle: [...parseHexBytes(inviterBundleHex, 65)],
        fingerprint: [...parseHexBytes(inviterFingerprintHex, 32)],
      });
      setInviterPinned(true);
      setNotice("Inviter bundle matches the supplied fingerprint and is pinned in this profile.");
    } catch (cause) {
      setInviterPinned(false);
      setError(cause instanceof Error ? cause.message : "Could not pin the inviter identity.");
    } finally {
      setBusy(false);
    }
  }

  async function joinSpace() {
    if (!inviterPinned) {
      setError("Pin the inviter identity after verifying its fingerprint out of band.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await worker.current?.run<string>({
        operation: "join-space",
        welcomeBootstrap: [...parseHexBytes(welcomeHex)],
        inviterFingerprint: [...parseHexBytes(inviterFingerprintHex, 32)],
        certificateDer: [...parseHexBytes(certificateHex)],
      });
      if (!result) throw new Error("Join returned no Space details.");
      const space = JSON.parse(result) as SpaceRecord;
      setSpaces((previous) => [...previous, space]);
      setSelectedSpaceKey(spaceKey(space));
      setNotice("Welcome validated and imported. This profile is now a member of the Space.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not join the Space.");
    } finally {
      setBusy(false);
    }
  }

  async function broadcastOutbox(space: SpaceRecord) {
    const channel = broadcast.current;
    if (!channel) return;
    let cursor: number[] | undefined;
    do {
      const page = await worker.current?.run<{ events: number[][]; nextCursor: number[] | null }>({
        operation: "outbox-message-page",
        spaceId: space.space_id,
        groupReference: space.group_reference,
        ...(cursor ? { afterEventId: cursor } : {}),
      });
      if (!page) return;
      for (const canonicalEvent of page.events) {
        channel.postMessage({ type: "signed-message-event", canonicalEvent });
      }
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
  }
  async function createRtcOffer(restart = false) {
    setError(null);
    try {
      setSignalText(await currentRtcLink().createOffer(restart));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create a WebRTC offer.");
    }
  }

  async function acceptRtcOffer() {
    setError(null);
    try {
      setSignalText(await currentRtcLink().acceptOffer(signalText));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not accept the WebRTC offer.");
    }
  }

  async function acceptRtcAnswer() {
    setError(null);
    try {
      await currentRtcLink().acceptAnswer(signalText);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not accept the WebRTC answer.");
    }
  }

  async function sendMessage() {
    if (!selectedSpace || !selectedChannel || messageDraft.trim().length === 0) return;
    setBusy(true);
    setError(null);
    try {
      await worker.current?.run({
        operation: "send-text-message",
        spaceId: selectedSpace.space_id,
        groupReference: selectedSpace.group_reference,
        channelId: selectedChannel.id,
        certificateDer: [...parseHexBytes(certificateHex)],
        content: messageDraft,
      });
      setMessageDraft("");
      await refreshHistory(selectedSpace, selectedChannel);
      await broadcastOutbox(selectedSpace);
      await rtcLink.current?.sendPending();
      setNotice(
        "Encrypted message committed locally. It was offered to connected same-origin and WebRTC peers; recipient delivery is not guaranteed.",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not send the message.");
    } finally {
      setBusy(false);
    }
  }

  const destinations = [
    { id: "spaces", label: "Spaces", icon: <SquaresFour size={20} weight="regular" /> },
    {
      id: "connections",
      label: "Connections",
      icon: <ArrowsLeftRight size={20} weight="regular" />,
    },
    { id: "identity", label: "Identity", icon: <Fingerprint size={20} weight="regular" /> },
  ] as const;

  return (
    <div className="workspace">
      {openedProfile ? (
        <WebWorkspaceShell
          destinations={destinations}
          activeDestination={activeDestination}
          onDestinationChange={setActiveDestination}
          spaces={spaces.map((space) => ({
            id: spaceKey(space),
            label: `Space ${toHex(space.space_id).slice(0, 8)}`,
          }))}
          activeSpace={selectedSpaceKey || null}
          onSpaceChange={(id) => {
            setSelectedSpaceKey(id);
            setSelectedChannelId("");
          }}
          channels={(selectedSpace?.channels ?? []).map((channel) => ({
            id: toHex(channel.id),
            label: channel.name,
            kind: channel.channel_type === "announcement" ? "announcement" : "text",
          }))}
          activeChannel={selectedChannel ? toHex(selectedChannel.id) : null}
          onChannelChange={setSelectedChannelId}
          onLockProfile={() => {
            if (!busy) void closeProfile();
          }}
        >
          <div className="profile-panel">
            <div
              hidden={activeDestination !== "identity"}
              className="workspace-page"
              data-destination="identity"
            >
              <WebIdentityPage>
                <WebIdentitySummary
                  profileId={openedProfile.profileId}
                  fingerprint={formatFingerprint(openedProfile.identity.fingerprint)}
                />
                <WebIssuerEnrollment
                  busy={busy}
                  csrPem={csrPem}
                  certificateHex={certificateHex}
                  onCreateCsr={() => void exportCsr()}
                  onCertificateChange={setCertificateHex}
                />
              </WebIdentityPage>
            </div>
            <div
              hidden={activeDestination !== "spaces"}
              className="workspace-page"
              data-destination="spaces"
            >
              <WebSpacesPage>
                <WebSpaceManagement
                  busy={busy}
                  hasSelectedSpace={Boolean(selectedSpace)}
                  certificateHex={certificateHex}
                  onCreateSpace={() => void createSpace()}
                  keyPackageHex={keyPackageHex}
                  onPublishKeyPackage={() => void publishKeyPackage()}
                  targetKeyPackageHex={targetKeyPackageHex}
                  onTargetKeyPackageChange={setTargetKeyPackageHex}
                  onCreateInvite={() => void createInvite()}
                  welcomeHex={welcomeHex}
                  onWelcomeChange={setWelcomeHex}
                  inviterFingerprintHex={inviterFingerprintHex}
                  onInviterFingerprintChange={(value) => {
                    setInviterFingerprintHex(value);
                    setInviterPinned(false);
                  }}
                  inviterBundleHex={inviterBundleHex}
                  onInviterBundleChange={(value) => {
                    setInviterBundleHex(value);
                    setInviterPinned(false);
                  }}
                  inviterPinned={inviterPinned}
                  onPinInviter={() => void pinInviterIdentity()}
                  onJoinSpace={() => void joinSpace()}
                  ownFingerprint={toHex(openedProfile.identity.fingerprint)}
                  ownPublicBundle={toHex(openedProfile.identity.public_bundle)}
                >
                  {selectedSpace && selectedChannel ? (
                    <WebMessageHistory
                      key={`${spaceKey(selectedSpace)}:${toHex(selectedChannel.id)}`}
                      channelName={selectedChannel.name}
                      messages={messages.map((message) => ({
                        id: toHex(message.event_id),
                        author: toHex(message.author_id).slice(0, 12),
                        content: message.content,
                      }))}
                      loading={historyLoading}
                      draft={messageDraft}
                      onDraftChange={setMessageDraft}
                      onSend={() => void sendMessage()}
                      disabled={busy || !certificateHex.trim()}
                    />
                  ) : null}
                </WebSpaceManagement>
              </WebSpacesPage>
            </div>
            <div
              hidden={activeDestination !== "connections"}
              className="workspace-page"
              data-destination="connections"
            >
              <WebConnectionsPage>
                {selectedSpace && selectedChannel ? (
                  <section className="message-workspace">
                    <WebWebRtcControls
                      status={rtcStatus}
                      iceServers={iceServersText}
                      signal={signalText}
                      onIceServersChange={setIceServersText}
                      onSignalChange={setSignalText}
                      onCreateOffer={() => void createRtcOffer()}
                      onRestartIce={() => void createRtcOffer(true)}
                      onAcceptOffer={() => void acceptRtcOffer()}
                      onAcceptAnswer={() => void acceptRtcAnswer()}
                      onDisconnect={closePeerConnection}
                    />
                    <WebCliLoopbackControls
                      status={cliBridgeStatus}
                      url={cliBridgeUrl}
                      token={cliBridgeToken}
                      busy={busy}
                      onUrlChange={setCliBridgeUrl}
                      onTokenChange={setCliBridgeToken}
                      onReconcile={() => void syncWithCli()}
                    />
                    <WebConnectionDisclosure />
                  </section>
                ) : (
                  <EmptyState
                    title="Select a Space"
                    body="Choose a Space with a text channel to configure its peer transports."
                  />
                )}
              </WebConnectionsPage>
            </div>
            {notice && <StatusNotice kind="success">{notice}</StatusNotice>}
            {error && <StatusNotice kind="error">{error}</StatusNotice>}
          </div>
          <footer className="page-footer">
            <span>Local profile · no volatile storage fallback</span>
            <span>Browser security context required</span>
          </footer>
        </WebWorkspaceShell>
      ) : (
        <main className="workspace-setup">
          <WebProfileGate
            isOpen={false}
            setup={
              <WebSetupPage>
                <WebProfileSetupForm
                  profileId={profileId}
                  rootCertificate={rootDerText}
                  rootFingerprint={rootPinText}
                  busy={busy}
                  error={error}
                  onProfileIdChange={setProfileId}
                  onRootCertificateChange={setRootDerText}
                  onRootFingerprintChange={setRootPinText}
                  onOpenSavedProfile={() => void openProfile(false)}
                  onCreateWithPinnedRoot={() => void openProfile(true)}
                />
                <footer className="page-footer">
                  <span>Local profile · no volatile storage fallback</span>
                  <span>Browser security context required</span>
                </footer>
              </WebSetupPage>
            }
            workspace={null}
          />
        </main>
      )}
    </div>
  );
}
