import { invoke } from "@tauri-apps/api/core";
import { type FormEvent, useCallback, useEffect, useState } from "react";

type PersistentPeerModeStatus = {
  enabled: boolean;
  running: boolean;
  listenAddress: string | null;
  peerFingerprint: string | null;
  boundAddress: string | null;
  queuedItems: number;
  queuedBytes: number;
  maxQueuedItems: number;
  maxQueuedBytes: number;
  error: string | null;
};

type RetainedCourierItem = {
  localEnvelopeId: string;
  eventId: string;
};

type RetainedCourierQueue = {
  enabled: boolean;
  items: RetainedCourierItem[];
};

type CourierForwardResult = {
  state: "accepted_by_pinned_peer";
  destinationFingerprint: string;
  eventId: string;
  bytesSent: number;
  sourceRetained: boolean;
  recipientDeliveryClaimed: boolean;
};

type Props = { runtimeAvailable: boolean };

const EMPTY_STATUS: PersistentPeerModeStatus = {
  enabled: false,
  running: false,
  listenAddress: null,
  peerFingerprint: null,
  boundAddress: null,
  queuedItems: 0,
  queuedBytes: 0,
  maxQueuedItems: 0,
  maxQueuedBytes: 0,
  error: null,
};
const LOOPBACK_DEFAULT = "127.0.0.1:7331";
const FINGERPRINT_HEX_LENGTH = 64;

export function PersistentPeerMode({ runtimeAvailable }: Props) {
  const [status, setStatus] = useState<PersistentPeerModeStatus>(EMPTY_STATUS);
  const [queue, setQueue] = useState<RetainedCourierQueue | null>(null);
  const [listenAddress, setListenAddress] = useState(LOOPBACK_DEFAULT);
  const [peerFingerprint, setPeerFingerprint] = useState("");
  const [outboundAddress, setOutboundAddress] = useState("");
  const [outboundFingerprint, setOutboundFingerprint] = useState("");
  const [selectedLocalEnvelopeId, setSelectedLocalEnvelopeId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState("");

  const loadPeerState = useCallback(async () => {
    const nextQueue = await invoke<RetainedCourierQueue>("list_retained_courier_items");
    const nextStatus = await invoke<PersistentPeerModeStatus>("get_persistent_peer_mode_status");
    setStatus(nextStatus);
    setQueue(nextQueue);
    setListenAddress(nextStatus.listenAddress ?? LOOPBACK_DEFAULT);
    setPeerFingerprint(nextStatus.peerFingerprint ?? "");
    setSelectedLocalEnvelopeId((current) =>
      nextQueue.items.some((item) => item.localEnvelopeId === current)
        ? current
        : (nextQueue.items[0]?.localEnvelopeId ?? ""),
    );
  }, []);

  const refresh = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await loadPeerState();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, [loadPeerState]);

  useEffect(() => {
    if (runtimeAvailable) void refresh();
  }, [refresh, runtimeAvailable]);

  async function configure(enabled: boolean, event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (
      !enabled &&
      !window.confirm(
        "Turn off persistent peer mode? This disables and clears the bounded opaque courier queue.",
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    setFeedback("");
    try {
      const result = await invoke<PersistentPeerModeStatus>("configure_persistent_peer_mode", {
        enabled,
        listenAddress: listenAddress.trim(),
        peerFingerprint: peerFingerprint.trim(),
      });
      await loadPeerState();
      setStatus(result);
      if (result.listenAddress) setListenAddress(result.listenAddress);
      if (result.peerFingerprint) setPeerFingerprint(result.peerFingerprint);
      setFeedback(
        enabled
          ? result.running
            ? "Persistent courier listener is running. Local queue retention is not recipient delivery."
            : `Persistent courier mode was saved, but its listener is not running${result.error ? `: ${result.error}` : "."}`
          : "Persistent courier mode is disabled and its queued opaque envelopes were cleared.",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  const selectedItem = queue?.items.find(
    (item) => item.localEnvelopeId === selectedLocalEnvelopeId,
  );
  const canForward =
    runtimeAvailable &&
    queue?.enabled === true &&
    selectedItem !== undefined &&
    outboundAddress.trim().length > 0 &&
    /^[\da-f]{64}$/i.test(outboundFingerprint.trim()) &&
    !busy;

  async function forwardSelectedItem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedItem || !canForward) return;
    const connectAddress = outboundAddress.trim();
    const destinationFingerprint = outboundFingerprint.trim();
    if (
      !window.confirm(
        `Forward event ${selectedItem.eventId} to pinned peer ${destinationFingerprint} at ${connectAddress}? The source copy may be consumed after peer authentication. Peer acceptance is not recipient delivery.`,
      )
    ) {
      return;
    }

    setBusy(true);
    setError(null);
    setFeedback("");
    try {
      const result = await invoke<CourierForwardResult>("forward_queued_courier_item", {
        connectAddress,
        peerFingerprint: destinationFingerprint,
        localEnvelopeId: selectedItem.localEnvelopeId,
        eventId: selectedItem.eventId,
      });
      if (
        result.state !== "accepted_by_pinned_peer" ||
        result.sourceRetained ||
        result.recipientDeliveryClaimed
      ) {
        throw new Error("The desktop returned an unexpected courier-forwarding result.");
      }
      setFeedback(
        `Peer ${result.destinationFingerprint} accepted event ${result.eventId} (${result.bytesSent} bytes). The source copy was consumed before transfer; this does not confirm recipient delivery.`,
      );
    } catch (cause) {
      setError(
        `Forward failed: ${cause instanceof Error ? cause.message : String(cause)}. The source copy may have been consumed after peer authentication to prevent duplication.`,
      );
    } finally {
      setQueue(null);
      setSelectedLocalEnvelopeId("");
      try {
        await loadPeerState();
      } catch (cause) {
        setError((current) =>
          `${current ? `${current} ` : ""}Courier queue status could not be refreshed: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
      setBusy(false);
    }
  }

  const canEnable =
    listenAddress.trim().length > 0 && /^[\da-f]{64}$/i.test(peerFingerprint.trim()) && !busy;

  return (
    <section className="local-network-settings" aria-labelledby="persistent-peer-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Optional background service</p>
          <h3 id="persistent-peer-title">Persistent peer mode</h3>
        </div>
        {runtimeAvailable && (
          <button type="button" disabled={busy} onClick={() => void refresh()}>
            Refresh peer status
          </button>
        )}
      </div>
      {!runtimeAvailable ? (
        <p>Open the Tauri desktop app to configure its opt-in pinned-peer courier listener.</p>
      ) : (
        <>
          <div className="local-path-status" aria-live="polite">
            <strong>
              {status.running
                ? `Listening at ${status.boundAddress ?? status.listenAddress ?? "configured address"}`
                : status.enabled
                  ? "Enabled; listener is not running"
                  : "Disabled"}
            </strong>
            <span>
              {status.queuedItems} of {status.maxQueuedItems} opaque envelopes ·{" "}
              {status.queuedBytes} of {status.maxQueuedBytes} bytes
            </span>
            <span>
              One exact pinned peer is accepted. Opaque envelopes are not decrypted or authorized as
              Space content, and queue retention is not recipient delivery.
            </span>
            <span>
              A non-loopback listener attempts a temporary generic mDNS announcement without peer
              or Space identity; discovery does not prove reachability.
            </span>
          </div>
          <form className="relay-settings-form" onSubmit={(event) => void configure(true, event)}>
            <label htmlFor="persistent-peer-listen-address">TCP listen address</label>
            <input
              autoComplete="off"
              id="persistent-peer-listen-address"
              maxLength={128}
              onChange={(event) => setListenAddress(event.target.value)}
              placeholder="192.168.1.20:7331"
              spellCheck={false}
              value={listenAddress}
            />
            <small>
              Default is loopback only. Enter a local interface address to accept connections from
              other devices; binding is not a reachability test.
            </small>
            <label htmlFor="persistent-peer-fingerprint">
              Pinned peer fingerprint (64 hex characters)
            </label>
            <input
              autoComplete="off"
              id="persistent-peer-fingerprint"
              maxLength={FINGERPRINT_HEX_LENGTH}
              onChange={(event) => setPeerFingerprint(event.target.value.trim())}
              spellCheck={false}
              value={peerFingerprint}
            />
            <div className="identity-actions">
              <button type="submit" disabled={!canEnable}>
                {busy
                  ? "Updating…"
                  : status.enabled
                    ? "Save and restart listener"
                    : "Enable persistent peer mode"}
              </button>
              {status.enabled && (
                <button type="button" disabled={busy} onClick={() => void configure(false)}>
                  Disable and clear queue
                </button>
              )}
            </div>
          </form>
          <div className="relay-settings">
            <div className="relay-settings-heading">
              <div>
                <h4>Forward a retained item</h4>
                <p>
                  Send one queued envelope to a TCP listener you choose. The destination
                  fingerprint must already be pinned in this profile.
                </p>
              </div>
            </div>
            {queue === null ? (
              <p>Courier queue status is not available. Refresh peer status to try again.</p>
            ) : !queue.enabled ? (
              <p>Courier queue retention is disabled. Enable persistent peer mode to opt in.</p>
            ) : queue.items.length === 0 ? (
              <p>No courier items are currently retained in the local queue.</p>
            ) : (
              <form
                className="relay-settings-form"
                onSubmit={(event) => void forwardSelectedItem(event)}
              >
                <label htmlFor="courier-selected-item">Retained event</label>
                <select
                  id="courier-selected-item"
                  onChange={(event) => setSelectedLocalEnvelopeId(event.target.value)}
                  value={selectedLocalEnvelopeId}
                  disabled={busy}
                  required
                >
                  <option value="">Choose a retained event</option>
                  {queue.items.map((item) => (
                    <option key={item.localEnvelopeId} value={item.localEnvelopeId}>
                      Event {item.eventId} · local item {item.localEnvelopeId}
                    </option>
                  ))}
                </select>
                {selectedItem && (
                  <p aria-live="polite">
                    Selected event ID: <code>{selectedItem.eventId}</code>
                  </p>
                )}
                <label htmlFor="courier-outbound-address">Peer TCP listener address</label>
                <input
                  autoComplete="off"
                  id="courier-outbound-address"
                  maxLength={128}
                  onChange={(event) => setOutboundAddress(event.target.value)}
                  placeholder="192.168.1.20:7331"
                  spellCheck={false}
                  value={outboundAddress}
                  disabled={busy}
                />
                <label htmlFor="courier-outbound-fingerprint">
                  Exact pinned peer fingerprint (64 hex characters)
                </label>
                <input
                  autoComplete="off"
                  id="courier-outbound-fingerprint"
                  maxLength={FINGERPRINT_HEX_LENGTH}
                  onChange={(event) => setOutboundFingerprint(event.target.value.trim())}
                  spellCheck={false}
                  value={outboundFingerprint}
                  disabled={busy}
                />
                <small>
                  Use the peer fingerprint already pinned in this profile. No peers are discovered
                  automatically. Peer acceptance does not confirm recipient delivery.
                </small>
                <div className="identity-actions">
                  <button type="submit" disabled={!canForward}>
                    {busy ? "Forwarding…" : "Review and forward event"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </>
      )}
      {busy && <p role="status">Working with peer mode or courier queue…</p>}
      {feedback && <p role="status">{feedback}</p>}
      {error && <p role="alert">{error}</p>}
      {status.error && <p role="alert">Listener status: {status.error}</p>}
    </section>
  );
}
