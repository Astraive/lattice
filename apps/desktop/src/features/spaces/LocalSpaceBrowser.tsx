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

type QueuedLocalMessage = {
  state: "queued";
  eventId: string;
};
type LocalTextMessage = {
  eventId: string;
  authorId: string;
  authorSequence: number;
  lamport: number;
  content: string;
  outboxState: "queued" | "forwarded" | "delivered" | "failed" | null;
};

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
  const [eventId, setEventId] = useState<string | null>(null);
  const [history, setHistory] = useState<LocalTextMessage[]>([]);
  const [historyChannelId, setHistoryChannelId] = useState<string | null>(null);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
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
      const queued = await invoke<QueuedLocalMessage>("queue_local_text_message", {
        spaceIdHex: space.spaceId,
        groupReferenceHex: space.groupReference,
        credentialVectorHex,
        channelIdHex: channelId,
        content,
      });
      setEventId(queued.eventId);
      setFeedback("Committed locally. Network forwarding and recipient delivery are unknown.");
    } catch (cause) {
      setFeedback(
        `Message was not queued: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="local-message-composer" onSubmit={(event) => void queueMessage(event)}>
      <h4>Queue a text message</h4>
      <p>Local encrypted commit only. No network send or delivery claim.</p>
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
            Message
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
            {busy ? "Committing…" : "Queue locally"}
          </button>
          <section className="local-message-history" aria-label="Recent local message history">
            <div>
              <h4>Recent outgoing messages</h4>
              <p>
                Newest 100 locally retained messages for this channel. Incoming messages are not
                shown.
              </p>
            </div>
            <button type="button" disabled={historyBusy} onClick={() => void loadHistory()}>
              {historyBusy ? "Loading…" : "Load recent history"}
            </button>
            {historyError && <p role="alert">History unavailable: {historyError}</p>}
            {historyChannelId === channelId && history.length === 0 && (
              <p role="status">No locally retained outgoing messages.</p>
            )}
            {historyChannelId === channelId && history.length > 0 && (
              <ol>
                {history.map((message) => (
                  <li key={message.eventId}>
                    <p>{message.content}</p>
                    <small>
                      {message.outboxState ?? "retained locally"} · event {message.eventId}
                    </small>
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

export function LocalSpaceBrowser({ runtimeAvailable }: LocalSpaceBrowserProps) {
  const [spaces, setSpaces] = useState<LocalSpaceSummary[]>([]);
  const [spaceCursor, setSpaceCursor] = useState<string | null>(null);
  const [spaceError, setSpaceError] = useState<string | null>(null);
  const [spacesBusy, setSpacesBusy] = useState(false);
  const [spacesLoaded, setSpacesLoaded] = useState(false);

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

  return (
    <section className="space-browser" aria-labelledby="spaces-title" aria-busy={spacesBusy}>
      <div className="space-browser-heading">
        <div>
          <h3 id="spaces-title">Local Space snapshots</h3>
          <p>
            Integrity-checked local Genesis snapshots only. A snapshot is not proof of current Space
            membership.
          </p>
        </div>
        {runtimeAvailable && (
          <button
            type="button"
            disabled={spacesBusy}
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
