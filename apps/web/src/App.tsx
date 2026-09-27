import { useEffect, useRef, useState } from "react";
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
import { formatFingerprint, parseHexBytes } from "./identity";
import { WebRtcEventLink } from "./webrtc-event-link";
import { type OpenedProfile, ProfileWorkerClient } from "./worker-client";
import "./app.css";

export default function App() {
  const worker = useRef<ProfileWorkerClient | null>(null);
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
  const [messages, setMessages] = useState<HistoryMessage[]>([]);

  const selectedSpace = spaces.find((space) => spaceKey(space) === selectedSpaceKey);
  const selectedChannel = selectedSpace?.channels.find(
    (channel) => channel.channel_type === "text",
  );

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
        () => refreshHistory(space),
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
        refreshHistory(space),
      );
      await link.reconcile(cliBridgeUrl, cliBridgeToken);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not sync with the CLI.");
    } finally {
      setBusy(false);
    }
  }
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
          if (!selectedChannel) return;
          const result = await worker.current?.run<string>({
            operation: "message-history",
            spaceId: selectedSpace.space_id,
            groupReference: selectedSpace.group_reference,
            channelId: selectedChannel.id,
          });
          if (result) setMessages(JSON.parse(result) as HistoryMessage[]);
        })
        .catch((cause: unknown) => {
          setError(cause instanceof Error ? cause.message : "A peer event was rejected.");
        });
    });
    return () => {
      channel.close();
      if (broadcast.current === channel) broadcast.current = null;
    };
  }, [openedProfile, selectedSpace, selectedChannel]);

  useEffect(() => {
    if (!openedProfile || !selectedSpace || !selectedChannel) {
      setMessages([]);
      return;
    }
    void worker.current
      ?.run<string>({
        operation: "message-history",
        spaceId: selectedSpace.space_id,
        groupReference: selectedSpace.group_reference,
        channelId: selectedChannel.id,
      })
      .then((result) => {
        if (result) setMessages(JSON.parse(result) as HistoryMessage[]);
      })
      .catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : "Could not load message history.");
      });
  }, [openedProfile, selectedSpace, selectedChannel]);

  async function refreshHistory(space: SpaceRecord | undefined = selectedSpace) {
    if (!space) {
      setMessages([]);
      return;
    }
    const channel = space.channels.find((item) => item.channel_type === "text");
    if (!channel) {
      setMessages([]);
      return;
    }
    const result = await worker.current?.run<string>({
      operation: "message-history",
      spaceId: space.space_id,
      groupReference: space.group_reference,
      channelId: channel.id,
    });
    if (result) setMessages(JSON.parse(result) as HistoryMessage[]);
  }

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
      setMessages([]);
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
      await refreshHistory(selectedSpace);
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

  return (
    <main className="workspace">
      <header className="masthead">
        <a className="wordmark" href="/" aria-label="Lattice Web home">
          <span className="wordmark-mark" aria-hidden="true" />
          <span>Lattice</span>
        </a>
        <span className="masthead-note">Web profile</span>
      </header>

      <section className="intro" aria-labelledby="page-title">
        <div className="intro-copy">
          <p className="eyebrow">Private by ownership</p>
          <h1 id="page-title">A profile that stays in this browser.</h1>
          <p className="intro-summary">
            Your identity and local data belong to this origin. No account server holds your
            profile.
          </p>
        </div>
        <fieldset className="ownership-flow">
          <legend className="visually-hidden">Profile ownership flow</legend>
          <div className="flow-node">
            <span className="flow-dot flow-dot-ui" aria-hidden="true" />
            <span>Browser view</span>
          </div>
          <span className="flow-line" aria-hidden="true" />
          <div className="flow-node flow-node-active">
            <span className="flow-dot flow-dot-worker" aria-hidden="true" />
            <span>Private worker</span>
          </div>
          <span className="flow-line" aria-hidden="true" />
          <div className="flow-node">
            <span className="flow-dot flow-dot-store" aria-hidden="true" />
            <span>Local OPFS</span>
          </div>
        </fieldset>
      </section>

      {openedProfile ? (
        <section className="profile-panel" aria-labelledby="profile-title">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Profile is open</p>
              <h2 id="profile-title">Your local identity</h2>
            </div>
            <button
              className="button button-quiet"
              type="button"
              onClick={closeProfile}
              disabled={busy}
            >
              Lock profile
            </button>
          </div>
          <dl className="identity-data">
            <div className="identity-row">
              <dt>Profile label</dt>
              <dd>{openedProfile.profileId}</dd>
            </div>
            <div className="identity-row">
              <dt>Identity fingerprint</dt>
              <dd className="fingerprint">
                {formatFingerprint(openedProfile.identity.fingerprint)}
              </dd>
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
            Protection is browser-origin scoped. It is not equivalent to a hardware-backed mobile
            key or an operating-system keychain.
          </p>

          <section className="web-controls" aria-labelledby="credential-title">
            <div className="control-heading">
              <p className="eyebrow">Issuer enrollment</p>
              <h3 id="credential-title">Issue this device certificate</h3>
            </div>
            <p className="field-hint">
              Core creates the private key and CSR. Have the issuer pinned at profile creation sign
              the CSR, then paste only the issued leaf certificate DER here.
            </p>
            <button
              className="button button-quiet"
              type="button"
              onClick={() => void exportCsr()}
              disabled={busy}
            >
              Create certificate signing request
            </button>
            {csrPem && (
              <textarea aria-label="Certificate signing request PEM" readOnly value={csrPem} />
            )}
            <label htmlFor="device-certificate">Issued device certificate · DER hex</label>
            <textarea
              id="device-certificate"
              value={certificateHex}
              onChange={(event) => setCertificateHex(event.target.value)}
              placeholder="Paste the issued leaf certificate in hexadecimal"
              spellCheck={false}
              autoComplete="off"
            />
          </section>

          <section className="web-controls" aria-labelledby="spaces-title">
            <div className="control-heading">
              <p className="eyebrow">Spaces on this profile</p>
              <h3 id="spaces-title">Create or join a Space</h3>
            </div>
            <button
              className="button button-primary"
              type="button"
              onClick={() => void createSpace()}
              disabled={busy || !certificateHex.trim()}
            >
              Create a Space with #general
            </button>
            <div className="space-picker">
              <label htmlFor="space-select">Current Space</label>
              <select
                id="space-select"
                value={selectedSpaceKey}
                onChange={(event) => setSelectedSpaceKey(event.target.value)}
              >
                <option value="">Select a Space</option>
                {spaces.map((space) => (
                  <option key={spaceKey(space)} value={spaceKey(space)}>
                    {space.channels[0]?.name ?? "Untitled Space"} ·{" "}
                    {toHex(space.space_id).slice(0, 8)}
                  </option>
                ))}
              </select>
            </div>
            {selectedSpace && selectedChannel && (
              <div className="message-workspace">
                <div className="control-heading">
                  <p className="eyebrow">#{selectedChannel.name}</p>
                  <h3>Messages</h3>
                </div>
                <ol className="message-list" aria-live="polite">
                  {messages.map((message) => (
                    <li key={toHex(message.event_id)}>
                      <code>{toHex(message.author_id).slice(0, 12)}</code>
                      <p>{message.content}</p>
                    </li>
                  ))}
                  {messages.length === 0 && (
                    <li className="empty-state">No locally accepted messages yet.</li>
                  )}
                </ol>
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    void sendMessage();
                  }}
                >
                  <label htmlFor="message-draft">New message</label>
                  <textarea
                    id="message-draft"
                    value={messageDraft}
                    onChange={(event) => setMessageDraft(event.target.value)}
                    maxLength={4096}
                  />
                  <button
                    className="button button-primary"
                    type="submit"
                    disabled={busy || !certificateHex.trim() || !messageDraft.trim()}
                  >
                    Encrypt and send
                  </button>
                </form>
                <section className="web-controls" aria-labelledby="webrtc-title">
                  <div className="control-heading">
                    <p className="eyebrow">Direct peer transport</p>
                    <h3 id="webrtc-title">WebRTC event sync</h3>
                  </div>
                  <p className="field-hint" role="status">
                    {rtcStatus}
                  </p>
                  <label htmlFor="webrtc-ice-servers">Optional ICE servers · JSON</label>
                  <textarea
                    id="webrtc-ice-servers"
                    value={iceServersText}
                    onChange={(event) => setIceServersText(event.target.value)}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder='[{"urls":"stun:stun.example.net:3478"}]'
                  />
                  <div className="button-row">
                    <button
                      className="button button-quiet"
                      type="button"
                      onClick={() => void createRtcOffer()}
                    >
                      Create offer
                    </button>
                    <button
                      className="button button-quiet"
                      type="button"
                      onClick={() => void createRtcOffer(true)}
                    >
                      Restart ICE
                    </button>
                    <button
                      className="button button-quiet"
                      type="button"
                      onClick={() => void acceptRtcOffer()}
                    >
                      Accept offer
                    </button>
                    <button
                      className="button button-quiet"
                      type="button"
                      onClick={() => void acceptRtcAnswer()}
                    >
                      Accept answer
                    </button>
                    <button
                      className="button button-quiet"
                      type="button"
                      onClick={closePeerConnection}
                    >
                      Disconnect
                    </button>
                  </div>
                  <label htmlFor="webrtc-signal">
                    WebRTC offer or answer · transfer out of band
                  </label>
                  <textarea
                    id="webrtc-signal"
                    value={signalText}
                    onChange={(event) => setSignalText(event.target.value)}
                    spellCheck={false}
                    autoComplete="off"
                  />
                  <p className="field-hint">
                    One side creates an offer and transfers it to the other side, which accepts it
                    and returns the answer. No signaling service or ICE server is configured; direct
                    connectivity depends on browser/network support. SDP reveals candidate network
                    addresses, so transfer it only through a channel you trust. Core verifies signed
                    events and current membership independently of the connection.
                  </p>
                </section>
                <section className="web-controls" aria-labelledby="cli-bridge-title">
                  <div className="control-heading">
                    <p className="eyebrow">Local command-line peer</p>
                    <h3 id="cli-bridge-title">CLI loopback sync</h3>
                  </div>
                  <p className="field-hint" role="status">
                    {cliBridgeStatus}
                  </p>
                  <label htmlFor="cli-bridge-url">CLI loopback WebSocket URL</label>
                  <input
                    id="cli-bridge-url"
                    type="url"
                    value={cliBridgeUrl}
                    onChange={(event) => setCliBridgeUrl(event.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <label htmlFor="cli-bridge-token">One-session pairing token</label>
                  <input
                    id="cli-bridge-token"
                    type="password"
                    value={cliBridgeToken}
                    onChange={(event) => setCliBridgeToken(event.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <button
                    className="button button-quiet"
                    type="button"
                    disabled={busy || !cliBridgeToken.trim()}
                    onClick={() => void syncWithCli()}
                  >
                    Reconcile with CLI
                  </button>
                  <p className="field-hint">
                    This bridge is loopback-only. Start <code>lattice sync web-serve-once</code> in
                    the CLI with this browser Origin, then enter its one-time token. Canonical
                    signed event bytes are transferred unchanged and validated by both profiles'
                    Core. HTTPS-hosted pages cannot use this plaintext loopback socket.
                  </p>
                </section>
                <p className="field-hint">
                  BroadcastChannel is limited to same-origin open tabs. WebRTC sends signed event
                  bytes directly between browsers; every received event still passes Core
                  authorization, signature, MLS and generation checks. Transport acceptance is not
                  recipient delivery.
                </p>
              </div>
            )}
          </section>

          <section className="web-controls" aria-labelledby="invite-title">
            <div className="control-heading">
              <p className="eyebrow">Manual offline transfer</p>
              <h3 id="invite-title">Invite a profile</h3>
            </div>
            <p className="field-hint">
              The invited profile publishes a one-time KeyPackage using its issued certificate.
              Transfer that KeyPackage here; then transfer the signed Welcome bootstrap, inviter
              fingerprint, and inviter public identity bundle. Verify the full fingerprint through
              an independent trusted channel before pinning.
            </p>
            <button
              className="button button-quiet"
              type="button"
              onClick={() => void publishKeyPackage()}
              disabled={busy || !certificateHex.trim()}
            >
              Publish my KeyPackage
            </button>
            {keyPackageHex && (
              <label htmlFor="own-key-package">My KeyPackage · copy to inviter</label>
            )}
            {keyPackageHex && (
              <textarea id="own-key-package" readOnly value={keyPackageHex} spellCheck={false} />
            )}
            <label htmlFor="target-package">Invited KeyPackage · hex</label>
            <textarea
              id="target-package"
              value={targetKeyPackageHex}
              onChange={(event) => setTargetKeyPackageHex(event.target.value)}
              spellCheck={false}
            />
            <button
              className="button button-primary"
              type="button"
              onClick={() => void createInvite()}
              disabled={
                busy || !selectedSpace || !certificateHex.trim() || !targetKeyPackageHex.trim()
              }
            >
              Commit invite and create Welcome
            </button>
            {welcomeHex && (
              <>
                <label htmlFor="welcome-bootstrap">
                  Welcome bootstrap · copy to invited profile
                </label>
                <textarea id="welcome-bootstrap" readOnly value={welcomeHex} spellCheck={false} />
                <label htmlFor="inviter-fingerprint-export">
                  Inviter identity fingerprint · transfer, then verify out of band
                </label>
                <textarea
                  id="inviter-fingerprint-export"
                  readOnly
                  value={toHex(openedProfile?.identity.fingerprint ?? [])}
                  spellCheck={false}
                />
                <label htmlFor="inviter-bundle-export">
                  Inviter public identity bundle · copy to invited profile
                </label>
                <textarea
                  id="inviter-bundle-export"
                  readOnly
                  value={toHex(openedProfile?.identity.public_bundle ?? [])}
                  spellCheck={false}
                />
              </>
            )}
            <label htmlFor="join-welcome">Join using Welcome bootstrap · hex</label>
            <textarea
              id="join-welcome"
              value={welcomeHex}
              onChange={(event) => setWelcomeHex(event.target.value)}
              spellCheck={false}
            />
            <label htmlFor="join-inviter">Expected inviter fingerprint · hex</label>
            <input
              id="join-inviter"
              value={inviterFingerprintHex}
              onChange={(event) => {
                setInviterFingerprintHex(event.target.value);
                setInviterPinned(false);
              }}
              spellCheck={false}
            />
            <label htmlFor="join-inviter-bundle">Inviter public identity bundle · hex</label>
            <textarea
              id="join-inviter-bundle"
              value={inviterBundleHex}
              onChange={(event) => {
                setInviterBundleHex(event.target.value);
                setInviterPinned(false);
              }}
              spellCheck={false}
            />
            <p className="field-hint">
              Pinning records trust only after you compare the full fingerprint with the inviter
              through an independent trusted channel.
            </p>
            <button
              className="button button-quiet"
              type="button"
              onClick={() => void pinInviterIdentity()}
              disabled={busy || !inviterBundleHex.trim() || !inviterFingerprintHex.trim()}
            >
              Verify bundle against fingerprint and pin
            </button>
            <button
              className="button button-quiet"
              type="button"
              onClick={() => void joinSpace()}
              disabled={
                busy ||
                !inviterPinned ||
                !certificateHex.trim() ||
                !welcomeHex.trim() ||
                !inviterFingerprintHex.trim()
              }
            >
              Validate Welcome and join
            </button>
          </section>
          {notice && (
            <p className="operation-note" role="status">
              {notice}
            </p>
          )}
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
        </section>
      ) : (
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
              void openProfile(false);
            }}
          >
            <label htmlFor="profile-id">Profile label</label>
            <input
              autoComplete="off"
              id="profile-id"
              maxLength={128}
              onChange={(event) => setProfileId(event.target.value)}
              required
              value={profileId}
            />
            <p className="field-hint">
              A local name only. It is not an account or a network identity.
            </p>
            <details className="pin-details">
              <summary>Create with a confirmed issuer root</summary>
              <div className="pin-fields">
                <label htmlFor="root-certificate">Issuer root certificate · DER hex</label>
                <textarea
                  autoCapitalize="off"
                  autoComplete="off"
                  id="root-certificate"
                  onChange={(event) => setRootDerText(event.target.value)}
                  placeholder="Paste the complete DER certificate in hexadecimal"
                  spellCheck={false}
                  value={rootDerText}
                />
                <label htmlFor="root-fingerprint">Confirmed SHA-256 fingerprint</label>
                <input
                  autoCapitalize="characters"
                  autoComplete="off"
                  id="root-fingerprint"
                  onChange={(event) => setRootPinText(event.target.value)}
                  placeholder="64 hexadecimal characters"
                  spellCheck={false}
                  value={rootPinText}
                />
                <p className="field-hint">
                  Verify this fingerprint through a trusted out-of-band source before creating the
                  profile.
                </p>
                <button
                  className="button button-primary"
                  disabled={
                    busy ||
                    profileId.trim().length === 0 ||
                    rootDerText.length === 0 ||
                    rootPinText.length === 0
                  }
                  onClick={(event) => {
                    event.preventDefault();
                    void openProfile(true);
                  }}
                  type="button"
                >
                  {busy ? "Opening profile…" : "Create profile with this pin"}
                </button>
              </div>
            </details>
            <button
              className="button button-primary"
              disabled={busy || profileId.trim().length === 0}
              type="submit"
            >
              {busy ? "Opening profile…" : "Open saved profile"}
            </button>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
          </form>
        </section>
      )}

      <footer className="page-footer">
        <span>Local profile · no volatile storage fallback</span>
        <span>Browser security context required</span>
      </footer>
    </main>
  );
}
