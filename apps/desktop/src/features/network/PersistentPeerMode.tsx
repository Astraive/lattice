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
  const [listenAddress, setListenAddress] = useState(LOOPBACK_DEFAULT);
  const [peerFingerprint, setPeerFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState("");

  const refresh = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<PersistentPeerModeStatus>("get_persistent_peer_mode_status");
      setStatus(result);
      if (result.listenAddress) setListenAddress(result.listenAddress);
      if (result.peerFingerprint) setPeerFingerprint(result.peerFingerprint);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

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
        </>
      )}
      {busy && <p role="status">Updating persistent peer mode…</p>}
      {feedback && <p role="status">{feedback}</p>}
      {error && <p role="alert">{error}</p>}
      {status.error && <p role="alert">Listener status: {status.error}</p>}
    </section>
  );
}
