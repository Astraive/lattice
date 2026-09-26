import { invoke } from "@tauri-apps/api/core";
import { type FormEvent, useState } from "react";

type LocalChannelSummary = {
  id: string;
  channelType: "text" | "announcement" | "voice";
  name: string;
  archived: boolean;
};

type LocalSpaceSummary = {
  spaceId: string;
  groupReference: string;
  channels: LocalChannelSummary[];
};

type LocalSpacePage = {
  spaces: LocalSpaceSummary[];
  nextCursor: string | null;
};

type LocalSpaceRecoveryResult = {
  state: "one_member_recovery_generation_created";
  spaceId: string;
  priorGroupReference: string;
  groupReference: string;
  genesisEventId: string;
  channels: LocalChannelSummary[];
  priorMembersRejoined: false;
  networkContacted: false;
};

type QueuedLocalMessage = {
  state: "queued";
  eventId: string;
};

type QueuedLocalFileAttachment = {
  state: "queued_locally";
  eventId: string;
  fileName: string;
  fileSize: number;
  fileHash: string;
  chunkCount: number;
  sourceRetainedLocally: true;
  networkContacted: false;
  recipientDeliveryClaimed: false;
};

type AttachmentSource = { hash: string; name: string; size: number };
type AttachmentCacheStatus = {
  sources: AttachmentSource[];
  storedBytes: number;
  storedFiles: number;
};
type AttachmentTransferSummary = {
  state: "peer_integrity_verified" | "received_and_exported";
  eventId: string;
  authenticatedPeerFingerprint: string;
  fileName: string;
  fileSize: number;
  chunksTransferred: number;
  integrityVerified: boolean;
  exportedLocally: boolean;
  stagingRemoved: boolean;
  cleanupWarning: string | null;
  recipientDeliveryClaimed: false;
  networkContacted: true;
};

type LocalTextMessage = {
  eventId: string;
  authorId: string;
  authorSequence: number;
  lamport: number;
  content: string;
  outboxState: "queued" | "forwarded" | "delivered" | "failed" | null;
};

type LocalTextMessageSearch = {
  messages: LocalTextMessage[];
  totalMatches: number;
  scannedMessages: number;
};

type LocalSpaceImport = {
  state: "local_welcome_checkpoint_imported";
  spaceId: string;
  groupReference: string;
  localCheckpointImported: true;
  networkContacted: false;
};

const MAX_BOOTSTRAP_HEX_LENGTH = 1024 * 1024 * 2;
const INVITER_FINGERPRINT_HEX_LENGTH = 32 * 2;

function localOutboxLabel(state: LocalTextMessage["outboxState"]): string {
  if (state === "queued") return "queued locally · no network delivery";
  if (state === null) return "retained locally · no outbox status";
  return "local outbox marker recorded · transport and recipient delivery unavailable";
}

type LocalSpaceBrowserProps = {
  runtimeAvailable: boolean;
};

const MAX_CREDENTIAL_HEX_LENGTH = 16 * 1024 * 2;
const MAX_MESSAGE_BYTES = 64 * 1024;

function LocalMessageComposer({ space }: { space: LocalSpaceSummary }) {
  const channels = space.channels.filter(
    (channel) => !channel.archived && channel.channelType !== "voice",
  );
  const [channelId, setChannelId] = useState(channels[0]?.id ?? "");
  const [credentialVectorHex, setCredentialVectorHex] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [editTarget, setEditTarget] = useState<string | null>(null);
  const [eventId, setEventId] = useState<string | null>(null);
  const [history, setHistory] = useState<LocalTextMessage[]>([]);
  const [historyChannelId, setHistoryChannelId] = useState<string | null>(null);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyQuery, setHistoryQuery] = useState("");
  const [historySearchSummary, setHistorySearchSummary] = useState<Pick<
    LocalTextMessageSearch,
    "totalMatches" | "scannedMessages"
  > | null>(null);
  const visibleHistory = historyChannelId === channelId ? history : [];
  const [attachmentSources, setAttachmentSources] = useState<AttachmentSource[]>([]);
  const [attachmentCacheBytes, setAttachmentCacheBytes] = useState<number | null>(null);
  const [attachmentCacheBusy, setAttachmentCacheBusy] = useState(false);
  const [attachmentCacheError, setAttachmentCacheError] = useState<string | null>(null);
  const [attachmentEventId, setAttachmentEventId] = useState("");
  const [attachmentPeerFingerprint, setAttachmentPeerFingerprint] = useState("");
  const [attachmentConnectAddress, setAttachmentConnectAddress] = useState("");
  const [attachmentListenAddress, setAttachmentListenAddress] = useState("127.0.0.1:7332");
  const [attachmentTransferBusy, setAttachmentTransferBusy] = useState(false);
  const [attachmentTransferNotice, setAttachmentTransferNotice] = useState<{
    kind: "status" | "error";
    message: string;
  } | null>(null);
  async function loadHistory() {
    const requestedChannel = channelId;
    setHistoryBusy(true);
    setHistoryError(null);
    try {
      const messages = await invoke<LocalTextMessage[]>("list_local_text_messages", {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        channelIdHex: requestedChannel,
      });
      setHistory(messages);
      setHistoryChannelId(requestedChannel);
      setHistoryQuery("");
      setHistorySearchSummary(null);
    } catch (cause) {
      setHistoryError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setHistoryBusy(false);
    }
  }

  async function searchHistory() {
    const requestedChannel = channelId;
    const query = historyQuery;
    if (!query.trim()) return;
    setHistoryBusy(true);
    setHistoryError(null);
    try {
      const result = await invoke<LocalTextMessageSearch>("search_local_text_messages", {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        channelIdHex: requestedChannel,
        query,
      });
      setHistory(result.messages);
      setHistoryChannelId(requestedChannel);
      setHistorySearchSummary({
        totalMatches: result.totalMatches,
        scannedMessages: result.scannedMessages,
      });
    } catch (cause) {
      setHistoryError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setHistoryBusy(false);
    }
  }
  const credentialIsValid =
    credentialVectorHex.length > 0 &&
    credentialVectorHex.length <= MAX_CREDENTIAL_HEX_LENGTH &&
    credentialVectorHex.length % 2 === 0 &&
    /^[0-9a-f]+$/i.test(credentialVectorHex);
  const contentIsValid = new TextEncoder().encode(content).length <= MAX_MESSAGE_BYTES;

  async function queueMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setFeedback(null);
    setEventId(null);
    try {
      const args: Record<string, string> = {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex,
        channelIdHex: channelId,
        content,
      };
      if (editTarget) args.targetMessageIdHex = editTarget;
      const queued = await invoke<QueuedLocalMessage>(
        editTarget ? "queue_local_text_message_edit" : "queue_local_text_message",
        args,
      );
      setEventId(queued.eventId);
      setFeedback(
        editTarget
          ? "Edit committed locally. Network forwarding and recipient delivery are unknown."
          : "Committed locally. Network forwarding and recipient delivery are unknown.",
      );
      setEditTarget(null);
      setContent("");
      await loadHistory();
    } catch (cause) {
      setFeedback(
        `Message was not queued: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    } finally {
      setBusy(false);
    }
  }

  async function queueFileAttachment() {
    setBusy(true);
    setAttachmentEventId("");
    setFeedback(null);
    setEventId(null);
    try {
      const queued = await invoke<QueuedLocalFileAttachment | null>("queue_local_file_attachment", {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex,
        channelIdHex: channelId,
      });
      if (!queued) return;
      setAttachmentEventId(queued.eventId);
      setEventId(queued.eventId);
      setFeedback(
        `${queued.fileName} (${queued.fileSize} bytes, ${queued.chunkCount} chunks) was queued locally. Its content-addressed source copy is retained; use the transfer panel with the event ID and exact peer pin to send it. No network or recipient delivery was attempted yet.`,
      );
    } catch (cause) {
      setFeedback(
        `File attachment was not queued: ${cause instanceof Error ? cause.message : String(cause)}. A staged source copy may remain in the local cache; inspect or remove it below.`,
      );
    } finally {
      setBusy(false);
    }
  }

  async function refreshAttachmentSources() {
    setAttachmentCacheBusy(true);
    setAttachmentCacheError(null);
    try {
      const result = await invoke<AttachmentCacheStatus>("list_local_attachment_sources");
      setAttachmentSources(result.sources);
      setAttachmentCacheBytes(result.storedBytes);
    } catch (cause) {
      setAttachmentCacheError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setAttachmentCacheBusy(false);
    }
  }

  async function removeAttachmentSource(fileHash: string) {
    if (
      !window.confirm(
        "Remove this retained source copy? Its queued manifest remains, but it cannot be transferred without the file bytes.",
      )
    ) {
      return;
    }
    setAttachmentCacheBusy(true);
    setAttachmentCacheError(null);
    try {
      const result = await invoke<{ removed: boolean }>("remove_local_attachment_source", {
        fileHashHex: fileHash,
      });
      if (result.removed) {
        setAttachmentSources((current) => current.filter((source) => source.hash !== fileHash));
        setAttachmentCacheBytes((current) =>
          current === null
            ? current
            : Math.max(
                0,
                current - (attachmentSources.find((source) => source.hash === fileHash)?.size ?? 0),
              ),
        );
      }
    } catch (cause) {
      setAttachmentCacheError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setAttachmentCacheBusy(false);
    }
  }

  async function sendAttachment() {
    setAttachmentTransferBusy(true);
    setAttachmentTransferNotice(null);
    try {
      const result = await invoke<AttachmentTransferSummary>("send_authorized_attachment_once", {
        connectAddress: attachmentConnectAddress,
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        eventIdHex: attachmentEventId.trim(),
        peerFingerprintHex: attachmentPeerFingerprint.trim(),
      });
      setAttachmentTransferNotice({
        kind: "status",
        message: `Pinned peer ${result.authenticatedPeerFingerprint} verified ${result.fileName} (${result.fileSize} bytes) across ${result.chunksTransferred} chunk(s). This is not recipient-delivery proof.`,
      });
    } catch (cause) {
      setAttachmentTransferNotice({
        kind: "error",
        message: `Attachment send failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    } finally {
      setAttachmentTransferBusy(false);
    }
  }

  async function receiveAttachment() {
    setAttachmentTransferBusy(true);
    setAttachmentTransferNotice(null);
    try {
      const result = await invoke<AttachmentTransferSummary | null>(
        "receive_authorized_attachment_once",
        {
          listenAddress: attachmentListenAddress,
          spaceIdHex: space.spaceId,
          groupReferenceHex: space.groupReference,
          eventIdHex: attachmentEventId.trim(),
          peerFingerprintHex: attachmentPeerFingerprint.trim(),
        },
      );
      setAttachmentTransferNotice({
        kind: "status",
        message: result
          ? `${result.fileName} (${result.fileSize} bytes) was integrity-verified and exported locally. No remote receipt or recipient delivery is claimed.${result.cleanupWarning ? ` ${result.cleanupWarning}` : ""}`
          : "Export selection cancelled; no attachment connection was opened.",
      });
    } catch (cause) {
      setAttachmentTransferNotice({
        kind: "error",
        message: `Attachment receive failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    } finally {
      setAttachmentTransferBusy(false);
    }
  }

  function beginEdit(message: LocalTextMessage) {
    setEditTarget(message.eventId);
    setContent(message.content);
    setFeedback(`Editing message ${message.eventId}. The original event remains immutable.`);
    setEventId(null);
  }

  return (
    <form className="local-message-composer" onSubmit={(event) => void queueMessage(event)}>
      <h4>{editTarget ? "Edit a text message" : "Queue a text message"}</h4>
      <p>
        {editTarget
          ? "The edit is a new encrypted event; the original event remains unchanged."
          : "Local encrypted commit only. No network send or delivery claim."}
      </p>
      {channels.length === 0 ? (
        <p>This Space has no active text or announcement channels.</p>
      ) : (
        <>
          <label>
            Channel
            <select value={channelId} onChange={(event) => setChannelId(event.target.value)}>
              {channels.map((channel) => (
                <option key={channel.id} value={channel.id}>
                  {channel.name} · {channel.channelType}
                </option>
              ))}
            </select>
          </label>
          <label>
            RFC 9420 X.509 credential vector (hex)
            <textarea
              autoComplete="off"
              maxLength={MAX_CREDENTIAL_HEX_LENGTH}
              rows={3}
              value={credentialVectorHex}
              onChange={(event) => setCredentialVectorHex(event.target.value.trim())}
              spellCheck={false}
            />
          </label>
          <label>
            {editTarget ? "Replacement text" : "Message"}
            <textarea
              maxLength={MAX_MESSAGE_BYTES}
              rows={3}
              value={content}
              onChange={(event) => setContent(event.target.value)}
            />
          </label>
          <button
            type="submit"
            disabled={busy || !channelId || !credentialIsValid || !contentIsValid}
          >
            {busy ? "Committing…" : editTarget ? "Queue edit" : "Queue locally"}
          </button>
          {!editTarget && (
            <button
              type="button"
              disabled={busy || !channelId || !credentialIsValid}
              onClick={() => void queueFileAttachment()}
            >
              {busy ? "Queuing file…" : "Choose file and queue attachment"}
            </button>
          )}
          <p>
            Attachments are capped at 128 MiB per file and 512 MiB in the local source cache.
            The selected file is retained locally; send/receive requires an exact pinned peer and
            an already authorized manifest on both devices.
          </p>
          <section className="local-message-history" aria-label="Retained attachment source cache">
            <div>
              <h4>Retained attachment source files</h4>
              <p>
                Source copies are ordinary local files in your OS user profile and are not encrypted
                at rest by this feature. Removing one does not delete its queued manifest, but
                leaves that manifest without source bytes for future transfer.
              </p>
            </div>
            <button
              type="button"
              disabled={attachmentCacheBusy}
              onClick={() => void refreshAttachmentSources()}
            >
              {attachmentCacheBusy ? "Working…" : "Load or refresh retained files"}
            </button>
            {attachmentCacheBytes !== null && (
              <p>
                {attachmentSources.length} retained file
                {attachmentSources.length === 1 ? "" : "s"} · {attachmentCacheBytes} of 536870912
                bytes used
              </p>
            )}
            {attachmentCacheError && <p role="alert">{attachmentCacheError}</p>}
            {attachmentSources.length > 0 && (
              <ul>
                {attachmentSources.map((source) => (
                  <li key={source.hash}>
                    <span>
                      {source.name} · {source.size} bytes
                    </span>
                    <button
                      type="button"
                      disabled={attachmentCacheBusy}
                      onClick={() => void removeAttachmentSource(source.hash)}
                    >
                      Remove source copy
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="local-message-history" aria-label="Authenticated attachment transfer">
            <h4>Authenticated attachment transfer</h4>
            <p>
              The sender and receiver must already have this authorized manifest in the same Space
              generation and must pin each other’s exact device fingerprint. Run the receiver first.
              The receiver selects an export path, authenticates the sender, then asks for consent
              before accepting bytes. Transfers time out after 30 minutes.
            </p>
            <label htmlFor="attachment-transfer-event-id">Authorized attachment event ID</label>
            <input
              autoComplete="off"
              id="attachment-transfer-event-id"
              maxLength={64}
              onChange={(event) => setAttachmentEventId(event.target.value.trim())}
              spellCheck={false}
              value={attachmentEventId}
            />
            <label htmlFor="attachment-transfer-peer-pin">
              Exact pinned peer fingerprint (64 hex characters)
            </label>
            <input
              autoComplete="off"
              id="attachment-transfer-peer-pin"
              maxLength={64}
              onChange={(event) => setAttachmentPeerFingerprint(event.target.value.trim())}
              spellCheck={false}
              value={attachmentPeerFingerprint}
            />
            <label htmlFor="attachment-transfer-connect-address">Peer TCP address</label>
            <input
              autoComplete="off"
              id="attachment-transfer-connect-address"
              maxLength={128}
              onChange={(event) => setAttachmentConnectAddress(event.target.value.trim())}
              placeholder="192.168.1.20:7332"
              spellCheck={false}
              value={attachmentConnectAddress}
            />
            <button
              type="button"
              disabled={
                attachmentTransferBusy ||
                attachmentEventId.length !== 64 ||
                attachmentPeerFingerprint.length !== 64 ||
                attachmentConnectAddress.length === 0
              }
              onClick={() => void sendAttachment()}
            >
              {attachmentTransferBusy ? "Transferring…" : "Send authorized attachment"}
            </button>
            <label htmlFor="attachment-transfer-listen-address">Local TCP listen address</label>
            <input
              autoComplete="off"
              id="attachment-transfer-listen-address"
              maxLength={128}
              onChange={(event) => setAttachmentListenAddress(event.target.value.trim())}
              spellCheck={false}
              value={attachmentListenAddress}
            />
            <button
              type="button"
              disabled={
                attachmentTransferBusy ||
                attachmentEventId.length !== 64 ||
                attachmentPeerFingerprint.length !== 64 ||
                attachmentListenAddress.length === 0
              }
              onClick={() => void receiveAttachment()}
            >
              {attachmentTransferBusy ? "Transferring…" : "Receive and export attachment"}
            </button>
            <p>
              The local address must be reachable by the sender; firewall and network reachability
              are not tested. Source bytes stay local on send; received bytes are staged privately
              and exported only after chunk and whole-file integrity verification.
            </p>
            {attachmentTransferNotice && (
              <p role={attachmentTransferNotice.kind === "status" ? "status" : "alert"}>
                {attachmentTransferNotice.message}
              </p>
            )}
          </section>
          {editTarget && (
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setEditTarget(null);
                setContent("");
                setFeedback(null);
              }}
            >
              Cancel edit
            </button>
          )}
          <section className="local-message-history" aria-label="Recent local message history">
            <div>
              <h4>Recent local messages</h4>
              <p>
                Newest 100 locally retained messages for this channel, including authorized incoming
                messages. Outbox markers describe local state only; this client has no network
                forwarding or recipient-delivery engine.
              </p>
            </div>
            <button type="button" disabled={historyBusy} onClick={() => void loadHistory()}>
              {historyBusy ? "Loading…" : "Load recent history"}
            </button>
            <label>
              Search all locally retained messages
              <input
                type="search"
                value={historyQuery}
                onChange={(event) => {
                  setHistoryQuery(event.target.value);
                  setHistoryChannelId(null);
                  setHistorySearchSummary(null);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void searchHistory();
                  }
                }}
                aria-label="Search all locally retained messages"
                disabled={historyBusy}
              />
            </label>
            <button
              type="button"
              disabled={historyBusy || !historyQuery.trim()}
              onClick={() => void searchHistory()}
            >
              {historyBusy ? "Searching…" : "Search history"}
            </button>
            <p aria-live="polite">
              {historyChannelId === channelId
                ? historySearchSummary
                  ? `${history.length} of ${historySearchSummary.totalMatches} matches across ${historySearchSummary.scannedMessages} locally retained messages.`
                  : `${history.length} recent locally cached messages shown.`
                : "Search scans all locally retained messages in the selected channel without contacting the network."}
            </p>
            {historyError && <p role="alert">History unavailable: {historyError}</p>}
            {historyChannelId === channelId && history.length === 0 && (
              <p role="status">
                {historySearchSummary
                  ? "No locally retained messages match this search."
                  : "No locally retained messages."}
              </p>
            )}
            {historyChannelId === channelId && visibleHistory.length > 0 && (
              <ol>
                {visibleHistory.map((message) => (
                  <li key={message.eventId}>
                    <p>{message.content}</p>
                    <small>
                      {localOutboxLabel(message.outboxState)} · event {message.eventId}
                    </small>
                    {message.outboxState !== null && (
                      <button type="button" disabled={busy} onClick={() => beginEdit(message)}>
                        Edit locally
                      </button>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </section>
        </>
      )}
      {feedback && <p role={eventId ? "status" : "alert"}>{feedback}</p>}
      {eventId && (
        <p>
          Event ID <code>{eventId}</code>
        </p>
      )}
    </form>
  );
}

function LocalSpaceRecovery({ space }: { space: LocalSpaceSummary }) {
  const [credentialVectorHex, setCredentialVectorHex] = useState("");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function recover(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const credential = credentialVectorHex.trim();
    if (
      credential.length === 0 ||
      credential.length > MAX_CREDENTIAL_HEX_LENGTH ||
      credential.length % 2 !== 0 ||
      !/^[0-9a-f]+$/i.test(credential)
    ) {
      setError("Enter a bounded, even-length hexadecimal X.509 credential vector.");
      setFeedback(null);
      return;
    }
    setBusy(true);
    setError(null);
    setFeedback(null);
    try {
      const result = await invoke<LocalSpaceRecoveryResult>("recover_local_space_generation", {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex: credential,
      });
      setCredentialVectorHex("");
      setFeedback(
        `Created recovery group ${result.groupReference}. Existing members did not rejoin; no network was contacted.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="local-recovery-form" onSubmit={(event) => void recover(event)}>
      <label>
        Recovery credential vector (hex)
        <textarea
          aria-label={`Recovery credential vector for Space ${space.spaceId}`}
          autoComplete="off"
          inputMode="text"
          maxLength={MAX_CREDENTIAL_HEX_LENGTH}
          onChange={(event) => setCredentialVectorHex(event.currentTarget.value)}
          spellCheck={false}
          value={credentialVectorHex}
        />
      </label>
      <button type="submit" disabled={busy}>
        {busy ? "Recovering locally…" : "Create one-member recovery generation"}
      </button>
      {feedback && <p role="status">{feedback}</p>}
      {error && <p role="alert">Recovery failed: {error}</p>}
    </form>
  );
}

export function LocalSpaceBrowser({ runtimeAvailable }: LocalSpaceBrowserProps) {
  const [spaces, setSpaces] = useState<LocalSpaceSummary[]>([]);
  const [spaceCursor, setSpaceCursor] = useState<string | null>(null);
  const [spaceError, setSpaceError] = useState<string | null>(null);
  const [spacesBusy, setSpacesBusy] = useState(false);
  const [spacesLoaded, setSpacesLoaded] = useState(false);
  const [packageHex, setPackageHex] = useState("");
  const [inviterFingerprintHex, setInviterFingerprintHex] = useState("");
  const [credentialVectorHex, setCredentialVectorHex] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [imported, setImported] = useState<LocalSpaceImport | null>(null);

  async function runSpacesCommand(after: string | null = null) {
    setSpacesBusy(true);
    setSpaceError(null);
    try {
      const page = await invoke<LocalSpacePage>("list_local_spaces", { after });
      setSpaces((current) => (after ? [...current, ...page.spaces] : page.spaces));
      setSpaceCursor(page.nextCursor);
      setSpacesLoaded(true);
    } catch (cause) {
      setSpaceError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSpacesBusy(false);
    }
  }

  async function importWelcomeBootstrap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      packageHex.length === 0 ||
      packageHex.length > MAX_BOOTSTRAP_HEX_LENGTH ||
      packageHex.length % 2 !== 0 ||
      !/^[\da-f]+$/i.test(packageHex) ||
      inviterFingerprintHex.length !== INVITER_FINGERPRINT_HEX_LENGTH ||
      !/^[\da-f]+$/i.test(inviterFingerprintHex) ||
      credentialVectorHex.length === 0 ||
      credentialVectorHex.length > MAX_CREDENTIAL_HEX_LENGTH ||
      credentialVectorHex.length % 2 !== 0 ||
      !/^[\da-f]+$/i.test(credentialVectorHex)
    ) {
      return;
    }
    setImportBusy(true);
    setImportError(null);
    setImported(null);
    try {
      const result = await invoke<LocalSpaceImport>("import_local_space_welcome_bootstrap", {
        packageHex,
        expectedInviterFingerprintHex: inviterFingerprintHex,
        credentialVectorHex,
      });
      setImported(result);
      await runSpacesCommand(null);
    } catch (cause) {
      setImportError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setImportBusy(false);
    }
  }

  return (
    <section
      className="space-browser"
      aria-labelledby="spaces-title"
      aria-busy={spacesBusy || importBusy}
    >
      <div className="space-browser-heading">
        <div>
          <h3 id="spaces-title">Local Space snapshots</h3>
          <p>
            Locally integrity-checked Genesis snapshots and imported signed policy checkpoints. A
            snapshot is not proof of current Space membership.
          </p>
        </div>
        {runtimeAvailable && (
          <button
            type="button"
            disabled={spacesBusy || importBusy}
            onClick={() => void runSpacesCommand(spacesLoaded ? spaceCursor : null)}
          >
            {spacesBusy
              ? "Loading…"
              : spaceCursor
                ? "Load next page"
                : spacesLoaded
                  ? "Refresh snapshots"
                  : "Load snapshots"}
          </button>
        )}
      </div>
      {runtimeAvailable && (
        <form
          className="identity-pin-fields"
          onSubmit={(event) => void importWelcomeBootstrap(event)}
        >
          <h4>Import a pinned-inviter Welcome bootstrap</h4>
          <p>
            Imports a signed local policy checkpoint and validated MLS Welcome into this protected
            profile. It does not prove package delivery or independently replay historical events.
            No relay or network is contacted.
          </p>
          <label htmlFor="space-welcome-package">Versioned Welcome bootstrap package (hex)</label>
          <textarea
            id="space-welcome-package"
            autoComplete="off"
            maxLength={MAX_BOOTSTRAP_HEX_LENGTH}
            disabled={importBusy}
            value={packageHex}
            onChange={(event) => {
              const value = event.currentTarget.value;
              if (value.length <= MAX_BOOTSTRAP_HEX_LENGTH) setPackageHex(value);
              setImported(null);
              setImportError(null);
            }}
            spellCheck={false}
            aria-describedby="space-welcome-package-help"
          />
          <p id="space-welcome-package-help">Maximum package size: 1 MiB before hex encoding.</p>
          <label htmlFor="space-welcome-inviter">Pinned inviter's full fingerprint (hex)</label>
          <input
            id="space-welcome-inviter"
            autoComplete="off"
            maxLength={INVITER_FINGERPRINT_HEX_LENGTH}
            disabled={importBusy}
            value={inviterFingerprintHex}
            onChange={(event) => {
              setInviterFingerprintHex(event.currentTarget.value);
              setImported(null);
              setImportError(null);
            }}
            spellCheck={false}
          />
          <label htmlFor="space-welcome-credential">X.509 credential vector content (hex)</label>
          <textarea
            id="space-welcome-credential"
            autoComplete="off"
            maxLength={MAX_CREDENTIAL_HEX_LENGTH}
            disabled={importBusy}
            value={credentialVectorHex}
            onChange={(event) => {
              const value = event.currentTarget.value;
              if (value.length <= MAX_CREDENTIAL_HEX_LENGTH) setCredentialVectorHex(value);
              setImported(null);
              setImportError(null);
            }}
            spellCheck={false}
          />
          <p>Maximum credential size: 16 KiB before hex encoding.</p>
          <button
            type="submit"
            disabled={
              importBusy ||
              packageHex.length === 0 ||
              packageHex.length > MAX_BOOTSTRAP_HEX_LENGTH ||
              packageHex.length % 2 !== 0 ||
              !/^[\da-f]+$/i.test(packageHex) ||
              inviterFingerprintHex.length !== INVITER_FINGERPRINT_HEX_LENGTH ||
              !/^[\da-f]+$/i.test(inviterFingerprintHex) ||
              credentialVectorHex.length === 0 ||
              credentialVectorHex.length > MAX_CREDENTIAL_HEX_LENGTH ||
              credentialVectorHex.length % 2 !== 0 ||
              !/^[\da-f]+$/i.test(credentialVectorHex)
            }
          >
            {importBusy ? "Importing locally…" : "Import Welcome bootstrap"}
          </button>
        </form>
      )}
      {importBusy && (
        <p role="status">
          Validating the pinned inviter, credential, Welcome, and signed checkpoint…
        </p>
      )}
      {importError && <p role="alert">Could not import the Welcome bootstrap: {importError}</p>}
      {imported && (
        <p role="status">
          Signed policy checkpoint and Welcome imported locally for Space {imported.spaceId}. No
          network was contacted; delivery and independent historical replay are not established.
        </p>
      )}
      {!runtimeAvailable && <p>Open the desktop app to inspect its protected local Space store.</p>}
      {spacesBusy && <p role="status">Checking local Space snapshots…</p>}
      {spaceError && (
        <p role="alert">
          Could not load local Space snapshots: {spaceError}
          {spacesLoaded && " Previously loaded results are still shown."}
        </p>
      )}
      {spacesLoaded && spaces.length === 0 && <p>No local Space snapshots were found.</p>}
      {spaces.length > 0 && (
        <ul id="local-space-results" className="space-list" aria-live="polite">
          {spaces.map((space) => (
            <li key={`${space.spaceId}:${space.groupReference}`}>
              <span>Space ID</span>
              <code>{space.spaceId}</code>
              <span>MLS group</span>
              <code>{space.groupReference}</code>
              <span>Channels</span>
              <div className="local-channel-list">
                {space.channels.map((channel) => (
                  <div key={channel.id}>
                    <span>
                      {channel.name} · {channel.channelType}
                      {channel.archived ? " · archived" : ""}
                    </span>
                    <code>{channel.id}</code>
                  </div>
                ))}
              </div>
              {runtimeAvailable && <LocalMessageComposer space={space} />}
              {runtimeAvailable && <LocalSpaceRecovery space={space} />}
            </li>
          ))}
        </ul>
      )}
      {spacesLoaded && spaces.length > 0 && (
        <p role="status" aria-live="polite">
          {spaces.length} locally verified snapshot{spaces.length === 1 ? "" : "s"} loaded. Current
          membership has not been checked.
        </p>
      )}
    </section>
  );
}
