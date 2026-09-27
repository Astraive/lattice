import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

type DesktopSyncResult = {
  state: "bounded_sync_round_completed";
  listenAddress: string;
  peerFingerprint: string;
  acceptedEvents: number;
  pendingEvents: number;
  duplicateEvents: number;
  checkpointExcludedEvents: number;
  offeredEvents: number;
  networkContacted: true;
  converged: false;
};

type Props = {
  spaceId: string;
  groupReference: string;
};

export function LocalSyncPanel({ spaceId, groupReference }: Props) {
  const [connectAddress, setConnectAddress] = useState("");
  const [listenAddress, setListenAddress] = useState("127.0.0.1:7331");
  const [peerFingerprint, setPeerFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DesktopSyncResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canSync =
    connectAddress.trim().length > 0 &&
    listenAddress.trim().length > 0 &&
    /^[\da-f]{64}$/i.test(peerFingerprint.trim()) &&
    !busy;

  async function syncOnce() {
    if (!canSync) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const next = await invoke<DesktopSyncResult>("sync_local_space_once", {
        connectAddress: connectAddress.trim(),
        listenAddress: listenAddress.trim(),
        spaceIdHex: spaceId,
        groupReferenceHex: groupReference,
        peerFingerprintHex: peerFingerprint.trim(),
      });
      if (
        next.state !== "bounded_sync_round_completed" ||
        next.networkContacted !== true ||
        next.converged !== false
      ) {
        throw new Error("Desktop returned an invalid bounded-sync result.");
      }
      setResult(next);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="local-network-settings" aria-label="Authenticated Space synchronization">
      <h4>Authenticated Space sync</h4>
      <p>
        Run once on both pinned peers at the same time. Each run exchanges one bounded v2 history
        round and applies received events through Core; it does not claim full convergence.
      </p>
      <label>
        Peer listener address
        <input
          autoComplete="off"
          onChange={(event) => setConnectAddress(event.target.value)}
          placeholder="192.168.1.20:7331"
          spellCheck={false}
          value={connectAddress}
        />
      </label>
      <label>
        Local sync listen address
        <input
          autoComplete="off"
          onChange={(event) => setListenAddress(event.target.value)}
          spellCheck={false}
          value={listenAddress}
        />
      </label>
      <p>
        The listener defaults to loopback and accepts only the exact pinned identity. On the same
        machine, use a different listen port in each profile; for another device, bind a local
        interface address explicitly.
      </p>
      <label>
        Exact pinned peer fingerprint (64 hex characters)
        <input
          autoComplete="off"
          maxLength={64}
          onChange={(event) => setPeerFingerprint(event.target.value.trim())}
          spellCheck={false}
          value={peerFingerprint}
        />
      </label>
      <button type="button" disabled={!canSync} onClick={() => void syncOnce()}>
        {busy ? "Synchronizing…" : "Run one authenticated sync round"}
      </button>
      {error && <p role="alert">Sync failed: {error}</p>}
      {result && (
        <p role="status" aria-live="polite">
          Round completed with {result.peerFingerprint} via {result.listenAddress}: accepted{" "}
          {result.acceptedEvents}, pending {result.pendingEvents}, duplicates{" "}
          {result.duplicateEvents}, checkpoint-excluded {result.checkpointExcludedEvents}, offered{" "}
          {result.offeredEvents}. Run additional rounds if history remains incomplete. Load recent
          history to view accepted events.
        </p>
      )}
    </section>
  );
}
