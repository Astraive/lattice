import { ActionButton, EmptyState, FormField, StatusNotice } from "@lattice/ui-shared";
import { invoke } from "@tauri-apps/api/core";
import { type FormEvent, useEffect, useState } from "react";
import { DesktopWebRtcEventPanel } from "./DesktopWebRtcEventPanel";
import { LocalSyncPanel } from "./LocalSyncPanel";

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
  outboxState:
    | "queued"
    | "forwarding"
    | "forwarded"
    | "peer_ingress_accepted"
    | "delivered"
    | "failed"
    | null;
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

type LocalSpaceKeyPackage = {
  state: "one_time_key_package_published";
  keyPackageHex: string;
  privateKeyPackageRetainedLocally: true;
  networkContacted: false;
};

const MAX_BOOTSTRAP_HEX_LENGTH = 1024 * 1024 * 2;
const INVITER_FINGERPRINT_HEX_LENGTH = 32 * 2;
const MAX_KEY_PACKAGE_HEX_LENGTH = 1024 * 1024 * 2;

function localOutboxLabel(state: LocalTextMessage["outboxState"]): string {
  if (state === "queued") return "queued locally · not yet sent";
  if (state === "forwarding") return "forwarding attempt recorded · recipient delivery unconfirmed";
  if (state === "forwarded") return "next hop accepted · recipient delivery unconfirmed";
  if (state === "peer_ingress_accepted")
    return "authenticated peer accepted bounded ingress · not recipient delivery";
  if (state === "delivered") return "verified destination receipt recorded";
  if (state === "failed") return "failed or expired · retained locally";
  return "retained locally · no outbox status";
}

type LocalSpaceBrowserProps = {
  runtimeAvailable: boolean;
  onSpacesChange?: (spaces: WorkspaceSpaceSnapshot[]) => void;
  activeSpace?: string | null;
  activeChannel?: string | null;
  onChannelChange?: (id: string) => void;
};

export type WorkspaceSpaceSnapshot = {
  id: string;
  label: string;
  channels: { id: string; label: string; kind: "text" | "announcement" }[];
};

const MAX_CREDENTIAL_HEX_LENGTH = 16 * 1024 * 2;
const MAX_MESSAGE_BYTES = 64 * 1024;

function LocalMessageComposer({
  space,
  activeChannel,
  onChannelChange,
}: {
  space: LocalSpaceSummary;
  activeChannel?: string | null;
  onChannelChange?: (id: string) => void;
}) {
  const channels = space.channels.filter(
    (channel) => !channel.archived && channel.channelType !== "voice",
  );
  const [channelId, setChannelId] = useState(activeChannel ?? channels[0]?.id ?? "");
  useEffect(() => {
    if (activeChannel && channels.some((channel) => channel.id === activeChannel))
      setChannelId(activeChannel);
  }, [activeChannel, channels]);
  const [credentialVectorHex, setCredentialVectorHex] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [editTarget, setEditTarget] = useState<string | null>(null);
  const [replyTarget, setReplyTarget] = useState<string | null>(null);
  const [reactionToken, setReactionToken] = useState("👍");
  const [mutationTag, setMutationTag] = useState("");
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
      const args: Record<string, unknown> = {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex,
        channelIdHex: channelId,
        content,
      };
      if (editTarget) args.targetMessageIdHex = editTarget;
      if (replyTarget) args.threadRootHex = replyTarget;
      const command = editTarget
        ? "queue_local_text_message_edit"
        : replyTarget
          ? "queue_local_text_message_reply"
          : "queue_local_text_message";
      const queued = await invoke<QueuedLocalMessage>(command, args);
      setEventId(queued.eventId);
      setFeedback(
        editTarget
          ? "Edit committed locally. Network forwarding and recipient delivery are unknown."
          : replyTarget
            ? "Reply committed locally. Network forwarding and recipient delivery are unknown."
            : "Committed locally. Network forwarding and recipient delivery are unknown.",
      );
      setEditTarget(null);
      setReplyTarget(null);
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
    setReplyTarget(null);
    setContent(message.content);
    setFeedback(`Editing message ${message.eventId}. The original event remains immutable.`);
    setEventId(null);
  }

  function beginReply(message: LocalTextMessage) {
    setEditTarget(null);
    setReplyTarget(message.eventId);
    setContent("");
    setFeedback(`Replying in the thread rooted at ${message.eventId}.`);
    setEventId(null);
  }

  async function tombstoneMessage(message: LocalTextMessage) {
    if (
      busy ||
      !credentialIsValid ||
      !window.confirm(
        "Queue a signed tombstone for this message? It hides the content in compliant local projections but cannot erase copies already received.",
      )
    ) {
      return;
    }
    setBusy(true);
    setFeedback(null);
    setEventId(null);
    try {
      const queued = await invoke<QueuedLocalMessage>("queue_local_text_message_tombstone", {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex,
        channelIdHex: channelId,
        targetMessageIdHex: message.eventId,
      });
      setEventId(queued.eventId);
      setFeedback(
        "Tombstone committed locally. Forwarding and remote display changes are unknown.",
      );
      await loadHistory();
    } catch (cause) {
      setFeedback(
        `Tombstone was not queued: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    } finally {
      setBusy(false);
    }
  }
  async function queueTaggedMutation(
    message: LocalTextMessage,
    kind: "reaction" | "pin",
    add: boolean,
  ) {
    if (busy || !credentialIsValid) return;
    if (!add && !/^[\da-f]{64}$/i.test(mutationTag)) {
      setFeedback("Enter the 32-byte add-event ID to remove that reaction or pin.");
      return;
    }
    setBusy(true);
    setFeedback(null);
    setEventId(null);
    try {
      const args: Record<string, unknown> = {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex,
        channelIdHex: channelId,
        targetMessageIdHex: message.eventId,
        add,
      };
      if (!add) args.tagHex = mutationTag;
      if (kind === "reaction") args.token = reactionToken.trim();
      const queued = await invoke<QueuedLocalMessage>(
        kind === "reaction" ? "queue_local_text_message_reaction" : "queue_local_text_message_pin",
        args,
      );
      setEventId(queued.eventId);
      if (add) setMutationTag(queued.eventId);
      setFeedback(
        `${kind === "reaction" ? "Reaction" : "Pin"} ${add ? "add" : "removal"} committed locally. Forwarding and recipient delivery are unknown.`,
      );
      await loadHistory();
    } catch (cause) {
      setFeedback(
        `Message update was not queued: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="local-message-composer" onSubmit={(event) => void queueMessage(event)}>
      <h4>
        {editTarget
          ? "Edit a text message"
          : replyTarget
            ? "Reply in a thread"
            : "Queue a text message"}
      </h4>
      <p>
        {editTarget
          ? "The edit is a new encrypted event; the original event remains unchanged."
          : replyTarget
            ? `This creates a reply rooted at ${replyTarget}.`
            : "Local encrypted commit only. Explicit pinned-peer sync below exchanges event history; there is no recipient-delivery receipt."}
      </p>
      {channels.length === 0 ? (
        <p>This Space has no active text or announcement channels.</p>
      ) : (
        <>
          <FormField label="Channel" htmlFor="message-channel">
            <select
              id="message-channel"
              value={channelId}
              onChange={(event) => {
                setChannelId(event.target.value);
                onChannelChange?.(event.target.value);
                setEditTarget(null);
                setReplyTarget(null);
                setContent("");
              }}
            >
              {channels.map((channel) => (
                <option key={channel.id} value={channel.id}>
                  {channel.name} · {channel.channelType}
                </option>
              ))}
            </select>
          </FormField>
          <FormField
            label="RFC 9420 X.509 credential vector (hex)"
            htmlFor="message-credential-vector"
          >
            <textarea
              id="message-credential-vector"
              autoComplete="off"
              maxLength={MAX_CREDENTIAL_HEX_LENGTH}
              rows={3}
              value={credentialVectorHex}
              onChange={(event) => setCredentialVectorHex(event.target.value.trim())}
              spellCheck={false}
            />
          </FormField>
          <FormField
            label={editTarget ? "Replacement text" : replyTarget ? "Reply" : "Message"}
            htmlFor="message-content"
          >
            <textarea
              id="message-content"
              maxLength={MAX_MESSAGE_BYTES}
              rows={3}
              value={content}
              onChange={(event) => setContent(event.target.value)}
            />
          </FormField>
          <FormField label="Reaction token" htmlFor="message-reaction-token">
            <input
              id="message-reaction-token"
              maxLength={64}
              value={reactionToken}
              onChange={(event) => setReactionToken(event.target.value)}
              disabled={busy}
            />
          </FormField>
          <FormField
            label="Reaction or pin add-event ID for removal (32-byte hex)"
            htmlFor="message-mutation-tag"
          >
            <input
              id="message-mutation-tag"
              maxLength={64}
              value={mutationTag}
              onChange={(event) => setMutationTag(event.target.value.trim())}
              disabled={busy}
            />
          </FormField>
          <ActionButton
            type="submit"
            tone="primary"
            disabled={busy || !channelId || !credentialIsValid || !contentIsValid}
          >
            {busy
              ? "Committing…"
              : editTarget
                ? "Queue edit"
                : replyTarget
                  ? "Queue reply"
                  : "Queue locally"}
          </ActionButton>
          {!editTarget && (
            <ActionButton
              type="button"
              tone="quiet"
              disabled={busy || !channelId || !credentialIsValid}
              onClick={() => void queueFileAttachment()}
            >
              {busy ? "Queuing file…" : "Choose file and queue attachment"}
            </ActionButton>
          )}
          <p>
            Attachments are capped at 128 MiB per file and 512 MiB in the local source cache. The
            selected file is retained locally; send/receive requires an exact pinned peer and an
            already authorized manifest on both devices.
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
            <ActionButton
              type="button"
              tone="quiet"
              disabled={attachmentCacheBusy}
              onClick={() => void refreshAttachmentSources()}
            >
              {attachmentCacheBusy ? "Working…" : "Load or refresh retained files"}
            </ActionButton>
            {attachmentCacheBytes !== null && (
              <p>
                {attachmentSources.length} retained file
                {attachmentSources.length === 1 ? "" : "s"} · {attachmentCacheBytes} of 536870912
                bytes used
              </p>
            )}
            {attachmentCacheError && (
              <StatusNotice kind="error">{attachmentCacheError}</StatusNotice>
            )}
            {attachmentSources.length > 0 && (
              <ul>
                {attachmentSources.map((source) => (
                  <li key={source.hash}>
                    <span>
                      {source.name} · {source.size} bytes
                    </span>
                    <ActionButton
                      type="button"
                      tone="danger"
                      disabled={attachmentCacheBusy}
                      onClick={() => void removeAttachmentSource(source.hash)}
                    >
                      Remove source copy
                    </ActionButton>
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
            <FormField
              label="Authorized attachment event ID"
              htmlFor="attachment-transfer-event-id"
            >
              <input
                autoComplete="off"
                id="attachment-transfer-event-id"
                maxLength={64}
                onChange={(event) => setAttachmentEventId(event.target.value.trim())}
                spellCheck={false}
                value={attachmentEventId}
              />
            </FormField>
            <FormField
              label="Exact pinned peer fingerprint (64 hex characters)"
              htmlFor="attachment-transfer-peer-pin"
            >
              <input
                autoComplete="off"
                id="attachment-transfer-peer-pin"
                maxLength={64}
                onChange={(event) => setAttachmentPeerFingerprint(event.target.value.trim())}
                spellCheck={false}
                value={attachmentPeerFingerprint}
              />
            </FormField>
            <FormField label="Peer TCP address" htmlFor="attachment-transfer-connect-address">
              <input
                autoComplete="off"
                id="attachment-transfer-connect-address"
                maxLength={128}
                onChange={(event) => setAttachmentConnectAddress(event.target.value.trim())}
                placeholder="192.168.1.20:7332"
                spellCheck={false}
                value={attachmentConnectAddress}
              />
            </FormField>
            <ActionButton
              type="button"
              tone="primary"
              disabled={
                attachmentTransferBusy ||
                attachmentEventId.length !== 64 ||
                attachmentPeerFingerprint.length !== 64 ||
                attachmentConnectAddress.length === 0
              }
              onClick={() => void sendAttachment()}
            >
              {attachmentTransferBusy ? "Transferring…" : "Send authorized attachment"}
            </ActionButton>
            <FormField
              label="Local TCP listen address"
              htmlFor="attachment-transfer-listen-address"
            >
              <input
                autoComplete="off"
                id="attachment-transfer-listen-address"
                maxLength={128}
                onChange={(event) => setAttachmentListenAddress(event.target.value.trim())}
                spellCheck={false}
                value={attachmentListenAddress}
              />
            </FormField>
            <ActionButton
              type="button"
              tone="primary"
              disabled={
                attachmentTransferBusy ||
                attachmentEventId.length !== 64 ||
                attachmentPeerFingerprint.length !== 64 ||
                attachmentListenAddress.length === 0
              }
              onClick={() => void receiveAttachment()}
            >
              {attachmentTransferBusy ? "Transferring…" : "Receive and export attachment"}
            </ActionButton>
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
            <ActionButton
              type="button"
              tone="quiet"
              disabled={busy}
              onClick={() => {
                setEditTarget(null);
                setContent("");
                setFeedback(null);
              }}
            >
              Cancel edit
            </ActionButton>
          )}
          {replyTarget && (
            <ActionButton
              type="button"
              tone="quiet"
              disabled={busy}
              onClick={() => {
                setReplyTarget(null);
                setContent("");
                setFeedback(null);
              }}
            >
              Cancel reply
            </ActionButton>
          )}
          <section className="local-message-history" aria-label="Recent local message history">
            <div>
              <h4>Recent local messages</h4>
              <p>
                Newest 100 locally retained messages for this channel, including authorized incoming
                events. Browser WebRTC can exchange bounded signed message events without
                authenticating the peer identity; pinned TCP sync below authenticates the peer.
                Neither path proves destination delivery.
              </p>
            </div>
            <ActionButton
              type="button"
              tone="quiet"
              disabled={historyBusy}
              onClick={() => void loadHistory()}
            >
              {historyBusy ? "Loading…" : "Load recent history"}
            </ActionButton>
            <FormField label="Search all locally retained messages" htmlFor="local-history-search">
              <input
                id="local-history-search"
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
            </FormField>
            <ActionButton
              type="button"
              tone="primary"
              disabled={historyBusy || !historyQuery.trim()}
              onClick={() => void searchHistory()}
            >
              {historyBusy ? "Searching…" : "Search history"}
            </ActionButton>
            <StatusNotice kind="info">
              {historyChannelId === channelId
                ? historySearchSummary
                  ? `${history.length} of ${historySearchSummary.totalMatches} matches across ${historySearchSummary.scannedMessages} locally retained messages.`
                  : `${history.length} recent locally cached messages shown.`
                : "Search scans all locally retained messages in the selected channel without contacting the network."}
            </StatusNotice>
            {historyError && (
              <StatusNotice kind="error">History unavailable: {historyError}</StatusNotice>
            )}
            {historyChannelId === channelId && history.length === 0 && (
              <StatusNotice kind="info">
                {historySearchSummary
                  ? "No locally retained messages match this search."
                  : "No locally retained messages."}
              </StatusNotice>
            )}
            {historyChannelId === channelId && visibleHistory.length > 0 && (
              <ol>
                {visibleHistory.map((message) => (
                  <li key={message.eventId}>
                    <p>{message.content}</p>
                    <small>
                      {localOutboxLabel(message.outboxState)} · event {message.eventId}
                    </small>
                    <ActionButton
                      type="button"
                      tone="quiet"
                      disabled={busy}
                      onClick={() => beginReply(message)}
                    >
                      Reply in thread
                    </ActionButton>
                    <ActionButton
                      type="button"
                      tone="quiet"
                      disabled={busy || !credentialIsValid || !reactionToken.trim()}
                      onClick={() => void queueTaggedMutation(message, "reaction", true)}
                    >
                      Add reaction
                    </ActionButton>
                    <ActionButton
                      type="button"
                      tone="quiet"
                      disabled={busy || !credentialIsValid || !/^[\da-f]{64}$/i.test(mutationTag)}
                      onClick={() => void queueTaggedMutation(message, "reaction", false)}
                    >
                      Remove reaction by tag
                    </ActionButton>
                    <ActionButton
                      type="button"
                      tone="quiet"
                      disabled={busy || !credentialIsValid}
                      onClick={() => void queueTaggedMutation(message, "pin", true)}
                    >
                      Pin
                    </ActionButton>
                    <ActionButton
                      type="button"
                      tone="quiet"
                      disabled={busy || !credentialIsValid || !/^[\da-f]{64}$/i.test(mutationTag)}
                      onClick={() => void queueTaggedMutation(message, "pin", false)}
                    >
                      Remove pin by tag
                    </ActionButton>
                    {message.outboxState !== null && (
                      <>
                        <ActionButton
                          type="button"
                          tone="quiet"
                          disabled={busy}
                          onClick={() => beginEdit(message)}
                        >
                          Edit locally
                        </ActionButton>
                        <ActionButton
                          type="button"
                          tone="danger"
                          disabled={busy || !credentialIsValid}
                          onClick={() => void tombstoneMessage(message)}
                        >
                          Queue delete tombstone
                        </ActionButton>
                      </>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </section>
          <DesktopWebRtcEventPanel
            spaceId={space.spaceId}
            groupReference={space.groupReference}
            onEventAccepted={loadHistory}
          />
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
      <FormField
        label="Recovery credential vector (hex)"
        htmlFor={`space-recovery-credential-${space.spaceId}`}
      >
        <textarea
          id={`space-recovery-credential-${space.spaceId}`}
          aria-label={`Recovery credential vector for Space ${space.spaceId}`}
          autoComplete="off"
          inputMode="text"
          maxLength={MAX_CREDENTIAL_HEX_LENGTH}
          onChange={(event) => setCredentialVectorHex(event.currentTarget.value)}
          spellCheck={false}
          value={credentialVectorHex}
        />
      </FormField>
      <ActionButton type="submit" tone="primary" disabled={busy}>
        {busy ? "Recovering locally…" : "Create one-member recovery generation"}
      </ActionButton>
      {feedback && <StatusNotice kind="success">{feedback}</StatusNotice>}
      {error && <StatusNotice kind="error">Recovery failed: {error}</StatusNotice>}
    </form>
  );
}

export function LocalSpaceBrowser({
  runtimeAvailable,
  onSpacesChange,
  activeSpace,
  activeChannel,
  onChannelChange,
}: LocalSpaceBrowserProps) {
  const [spaces, setSpaces] = useState<LocalSpaceSummary[]>([]);
  useEffect(() => {
    onSpacesChange?.(
      spaces.map((space) => ({
        id: `${space.spaceId}:${space.groupReference}`,
        label: `Space ${space.spaceId.slice(0, 8)}`,
        channels: space.channels
          .filter((channel) => !channel.archived && channel.channelType !== "voice")
          .map((channel) => ({
            id: channel.id,
            label: channel.name,
            kind: channel.channelType as "text" | "announcement",
          })),
      })),
    );
  }, [spaces, onSpacesChange]);
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
  const [keyPackageCredentialHex, setKeyPackageCredentialHex] = useState("");
  const [keyPackageBusy, setKeyPackageBusy] = useState(false);
  const [keyPackageError, setKeyPackageError] = useState<string | null>(null);
  const [keyPackageResult, setKeyPackageResult] = useState<LocalSpaceKeyPackage | null>(null);
  const [keyPackageCopyStatus, setKeyPackageCopyStatus] = useState("");

  async function publishKeyPackage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const credential = keyPackageCredentialHex.trim();
    if (
      credential.length === 0 ||
      credential.length > MAX_CREDENTIAL_HEX_LENGTH ||
      credential.length % 2 !== 0 ||
      !/^[\da-f]+$/i.test(credential)
    ) {
      setKeyPackageError("Enter a bounded, even-length hexadecimal X.509 credential vector.");
      setKeyPackageResult(null);
      return;
    }
    setKeyPackageBusy(true);
    setKeyPackageError(null);
    setKeyPackageResult(null);
    setKeyPackageCopyStatus("");
    try {
      const result = await invoke<LocalSpaceKeyPackage>("publish_local_space_key_package", {
        credentialVectorHex: credential,
      });
      setKeyPackageResult(result);
    } catch (cause) {
      setKeyPackageError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setKeyPackageBusy(false);
    }
  }

  async function copyPublishedKeyPackage() {
    if (!keyPackageResult) return;
    try {
      await navigator.clipboard.writeText(keyPackageResult.keyPackageHex);
      setKeyPackageCopyStatus("KeyPackage copied. Its private package remains in this profile.");
    } catch (cause) {
      setKeyPackageCopyStatus(
        cause instanceof Error
          ? `Copy failed: ${cause.message}. Select and copy the public KeyPackage bytes.`
          : "Copy failed. Select and copy the public KeyPackage bytes.",
      );
    }
  }

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
      aria-busy={spacesBusy || importBusy || keyPackageBusy}
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
          <ActionButton
            tone="quiet"
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
          </ActionButton>
        )}
      </div>
      {runtimeAvailable && (
        <form className="identity-pin-fields" onSubmit={(event) => void publishKeyPackage(event)}>
          <h4>Publish a one-time KeyPackage</h4>
          <p>
            The validated package can be given to an inviter. Its matching private material stays in
            this protected profile; publishing it does not contact a peer or join a Space.
          </p>
          <FormField
            label="Local X.509 credential vector (hex)"
            htmlFor="space-key-package-credential"
            hint="Maximum credential size: 16 KiB before hex encoding."
          >
            <textarea
              id="space-key-package-credential"
              autoComplete="off"
              maxLength={MAX_CREDENTIAL_HEX_LENGTH}
              disabled={keyPackageBusy}
              value={keyPackageCredentialHex}
              onChange={(event) => {
                setKeyPackageCredentialHex(event.currentTarget.value);
                setKeyPackageError(null);
                setKeyPackageResult(null);
              }}
              spellCheck={false}
            />
          </FormField>
          <ActionButton
            type="submit"
            tone="primary"
            disabled={
              keyPackageBusy ||
              keyPackageCredentialHex.trim().length === 0 ||
              keyPackageCredentialHex.trim().length > MAX_CREDENTIAL_HEX_LENGTH ||
              keyPackageCredentialHex.trim().length % 2 !== 0 ||
              !/^[\da-f]+$/i.test(keyPackageCredentialHex.trim())
            }
          >
            {keyPackageBusy ? "Publishing locally…" : "Publish one-time KeyPackage"}
          </ActionButton>
          {keyPackageError && (
            <StatusNotice kind="error">
              Could not publish KeyPackage: {keyPackageError}
            </StatusNotice>
          )}
          {keyPackageResult && (
            <div className="identity-status" role="status" aria-live="polite">
              <p>
                One-time KeyPackage published locally. Share these public bytes with the inviter; no
                network was contacted.
              </p>
              <FormField
                label="Published public KeyPackage bytes in hexadecimal"
                htmlFor="published-key-package-hex"
              >
                <textarea
                  id="published-key-package-hex"
                  maxLength={MAX_KEY_PACKAGE_HEX_LENGTH}
                  onFocus={(event) => event.currentTarget.select()}
                  readOnly
                  spellCheck={false}
                  value={keyPackageResult.keyPackageHex}
                  aria-label="Published public KeyPackage bytes in hexadecimal"
                />
              </FormField>
              <ActionButton
                type="button"
                tone="quiet"
                onClick={() => void copyPublishedKeyPackage()}
              >
                Copy KeyPackage
              </ActionButton>
              <p>{keyPackageCopyStatus}</p>
            </div>
          )}
        </form>
      )}
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
          <FormField
            label="Versioned Welcome bootstrap package (hex)"
            htmlFor="space-welcome-package"
            hint="Maximum package size: 1 MiB before hex encoding."
          >
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
            />
          </FormField>
          <FormField
            label="Pinned inviter's full fingerprint (hex)"
            htmlFor="space-welcome-inviter"
          >
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
          </FormField>
          <FormField
            label="Joining device's X.509 credential vector (hex)"
            htmlFor="space-welcome-credential"
            hint="Supply this profile's credential vector, not the inviter's. Maximum credential size: 16 KiB before hex encoding."
          >
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
          </FormField>
          <ActionButton
            type="submit"
            tone="primary"
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
          </ActionButton>
        </form>
      )}
      {importBusy && (
        <StatusNotice kind="info">
          Validating the pinned inviter, credential, Welcome, and signed checkpoint…
        </StatusNotice>
      )}
      {importError && (
        <StatusNotice kind="error">
          Could not import the Welcome bootstrap: {importError}
        </StatusNotice>
      )}
      {imported && (
        <StatusNotice kind="success">
          Signed policy checkpoint and Welcome imported locally for Space {imported.spaceId}. No
          network was contacted; delivery and independent historical replay are not established.
        </StatusNotice>
      )}
      {!runtimeAvailable && <p>Open the desktop app to inspect its protected local Space store.</p>}
      {spacesBusy && <StatusNotice kind="info">Checking local Space snapshots…</StatusNotice>}
      {spaceError && (
        <StatusNotice kind="error">
          Could not load local Space snapshots: {spaceError}
          {spacesLoaded && " Previously loaded results are still shown."}
        </StatusNotice>
      )}
      {spacesLoaded && spaces.length === 0 && (
        <EmptyState
          title="No local Spaces found"
          body="Create a local Space or import an existing Welcome from a pinned inviter. No network is contacted by these local operations."
          action={<a href="#space-create-title">Create a local Space</a>}
        />
      )}
      {spaces.length > 0 && (
        <ul id="local-space-results" className="space-list" aria-live="polite">
          {spaces.map((space) => (
            <li
              key={`${space.spaceId}:${space.groupReference}`}
              hidden={
                activeSpace !== null && activeSpace !== `${space.spaceId}:${space.groupReference}`
              }
            >
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
              {runtimeAvailable && (
                <LocalMessageComposer
                  space={space}
                  activeChannel={
                    (activeSpace === `${space.spaceId}:${space.groupReference}`
                      ? activeChannel
                      : null) ?? null
                  }
                  {...(onChannelChange ? { onChannelChange } : {})}
                />
              )}
              {runtimeAvailable && (
                <LocalSyncPanel spaceId={space.spaceId} groupReference={space.groupReference} />
              )}
              {runtimeAvailable && <LocalSpaceRecovery space={space} />}
            </li>
          ))}
        </ul>
      )}
      {spacesLoaded && spaces.length > 0 && (
        <StatusNotice kind="success">
          {spaces.length} locally verified snapshot{spaces.length === 1 ? "" : "s"} loaded. Current
          membership has not been checked.
        </StatusNotice>
      )}
    </section>
  );
}
