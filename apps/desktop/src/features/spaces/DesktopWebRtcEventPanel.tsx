import { ActionButton, FormField, StatusNotice } from "@lattice/ui-shared";
import { invoke } from "@tauri-apps/api/core";
import { useEffect, useRef, useState } from "react";

const MAX_EVENT_BYTES = 256 * 1024;
const MAX_SESSION_BYTES = 16 * 1024 * 1024;
const MAX_BUFFERED_BYTES = 1024 * 1024;
const MAX_ICE_SIGNAL_BYTES = 256 * 1024;

type DesktopWebEventPage = {
  events: number[][];
  nextCursor: string | null;
};

type DesktopWebIngressResult = {
  state: "accepted" | "duplicate" | "checkpoint_excluded" | "pending";
  eventId: string;
  missingDependencies: string[];
};

type Props = {
  spaceId: string;
  groupReference: string;
  onEventAccepted: () => Promise<void>;
};

function parseSignal(text: string, type: RTCSdpType): RTCSessionDescriptionInit {
  if (new TextEncoder().encode(text).length > MAX_ICE_SIGNAL_BYTES) {
    throw new Error("WebRTC session description exceeds the 256 KiB limit.");
  }
  const value: unknown = JSON.parse(text);
  if (
    !value ||
    typeof value !== "object" ||
    !("type" in value) ||
    value.type !== type ||
    !("sdp" in value) ||
    typeof value.sdp !== "string"
  ) {
    throw new Error(`Expected a WebRTC ${type} session description.`);
  }
  return { type, sdp: value.sdp };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function gatherComplete(peer: RTCPeerConnection): Promise<void> {
  if (peer.iceGatheringState === "complete") return Promise.resolve();
  const { promise, resolve, reject } = deferred<void>();
  const finish = () => {
    clearTimeout(timeout);
    peer.removeEventListener("icegatheringstatechange", check);
    peer.removeEventListener("signalingstatechange", check);
  };
  const check = () => {
    if (peer.iceGatheringState === "complete") {
      finish();
      resolve(undefined);
    } else if (peer.signalingState === "closed") {
      finish();
      reject(new Error("WebRTC closed before ICE gathering completed."));
    }
  };
  const timeout = setTimeout(() => {
    finish();
    reject(new Error("ICE gathering did not complete within 20 seconds."));
  }, 20_000);
  peer.addEventListener("icegatheringstatechange", check);
  peer.addEventListener("signalingstatechange", check);
  check();
  return promise;
}

function waitForConnection(peer: RTCPeerConnection): Promise<void> {
  if (peer.connectionState === "connected") return Promise.resolve();
  const { promise, resolve, reject } = deferred<void>();
  const finish = () => {
    clearTimeout(timeout);
    peer.removeEventListener("connectionstatechange", check);
  };
  const check = () => {
    if (peer.connectionState === "connected") {
      finish();
      resolve(undefined);
    } else if (["failed", "closed"].includes(peer.connectionState)) {
      finish();
      reject(new Error(`WebRTC connection ${peer.connectionState}.`));
    }
  };
  const timeout = setTimeout(() => {
    finish();
    reject(new Error("WebRTC connection did not establish within 30 seconds."));
  }, 30_000);
  peer.addEventListener("connectionstatechange", check);
  check();
  return promise;
}
function maxFrameBytes(peer: RTCPeerConnection | null): number {
  const negotiated = peer?.sctp?.maxMessageSize;
  return negotiated && negotiated > 0 ? Math.min(MAX_EVENT_BYTES, negotiated) : MAX_EVENT_BYTES;
}

export function DesktopWebRtcEventPanel({ spaceId, groupReference, onEventAccepted }: Props) {
  const peer = useRef<RTCPeerConnection | null>(null);
  const channel = useRef<RTCDataChannel | null>(null);
  const receiveTail = useRef(Promise.resolve());
  const receiveBytes = useRef(0);
  const syncTask = useRef<Promise<void> | null>(null);
  const [signal, setSignal] = useState("");
  const [iceServersText, setIceServersText] = useState("");
  const [status, setStatus] = useState("Not connected");
  const [error, setError] = useState<string | null>(null);

  function ensurePeer(): RTCPeerConnection {
    if (peer.current) return peer.current;
    const iceText = iceServersText.trim();
    if (new TextEncoder().encode(iceText).length > 4_096) {
      throw new Error("ICE server configuration exceeds 4 KiB.");
    }
    const iceServers: RTCIceServer[] = iceText ? (JSON.parse(iceText) as RTCIceServer[]) : [];
    if (!Array.isArray(iceServers) || iceServers.length > 8) {
      throw new Error("Provide at most eight ICE server entries.");
    }
    const connection = new RTCPeerConnection({ iceServers });
    peer.current = connection;
    connection.addEventListener("datachannel", (event) => attachChannel(event.channel));
    connection.addEventListener("connectionstatechange", () => {
      setStatus(
        connection.connectionState === "connected"
          ? "Encrypted WebRTC transport connected; peer identity is not authenticated. Core still validates each signed event."
          : `WebRTC ${connection.connectionState}; incoming events remain untrusted until Core acceptance.`,
      );
    });
    return connection;
  }

  function attachChannel(dataChannel: RTCDataChannel): void {
    channel.current = dataChannel;
    dataChannel.binaryType = "arraybuffer";
    dataChannel.bufferedAmountLowThreshold = MAX_BUFFERED_BYTES / 2;
    dataChannel.addEventListener("open", () => {
      receiveBytes.current = 0;
      setStatus(
        "Connected; exchanging bounded local message outboxes. Event sync is not delivery confirmation.",
      );
      void sendPending().catch(reportError);
    });
    dataChannel.addEventListener("close", () => {
      if (channel.current === dataChannel) setStatus("Data channel closed.");
    });
    dataChannel.addEventListener("message", (event) => {
      if (
        !(event.data instanceof ArrayBuffer) ||
        event.data.byteLength === 0 ||
        event.data.byteLength > maxFrameBytes(peer.current)
      ) {
        setStatus("Rejected a non-binary, empty, or oversized event frame.");
        return;
      }
      receiveBytes.current += event.data.byteLength;
      if (receiveBytes.current > MAX_SESSION_BYTES) {
        setStatus("Rejected event bytes beyond the 16 MiB receive-session bound.");
        dataChannel.close();
        return;
      }
      receiveTail.current = receiveTail.current
        .then(async () => {
          const result = await invoke<DesktopWebIngressResult>("accept_local_web_event", {
            spaceIdHex: spaceId,
            groupReferenceHex: groupReference,
            canonicalEvent: [...new Uint8Array(event.data as ArrayBuffer)],
          });
          setStatus(
            result.state === "accepted"
              ? `Core accepted event ${result.eventId}; refreshing local projection.`
              : result.state === "pending"
                ? `Core retained event ${result.eventId} pending ${result.missingDependencies.length} dependency(ies).`
                : `Core classified event ${result.eventId} as ${result.state}.`,
          );
          if (result.state === "accepted") await onEventAccepted();
        })
        .catch(reportError);
    });
  }

  async function createOffer(): Promise<void> {
    setError(null);
    const connection = ensurePeer();
    if (!channel.current || channel.current.readyState === "closed") {
      attachChannel(connection.createDataChannel("lattice-events", { ordered: true }));
    }
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    await gatherComplete(connection);
    if (!connection.localDescription) throw new Error("WebRTC did not produce an offer.");
    setSignal(
      JSON.stringify({
        type: connection.localDescription.type,
        sdp: connection.localDescription.sdp,
      }),
    );
    setStatus(
      "Offer ready; transfer it out of band. The signaling data does not authenticate the peer.",
    );
  }

  async function acceptOffer(): Promise<void> {
    setError(null);
    const connection = ensurePeer();
    await connection.setRemoteDescription(parseSignal(signal, "offer"));
    const answer = await connection.createAnswer();
    await connection.setLocalDescription(answer);
    await gatherComplete(connection);
    if (!connection.localDescription) throw new Error("WebRTC did not produce an answer.");
    setSignal(
      JSON.stringify({
        type: connection.localDescription.type,
        sdp: connection.localDescription.sdp,
      }),
    );
    setStatus("Answer ready; transfer it out of band.");
  }

  async function acceptAnswer(): Promise<void> {
    setError(null);
    if (!peer.current) throw new Error("Create an offer before accepting an answer.");
    await peer.current.setRemoteDescription(parseSignal(signal, "answer"));
    await waitForConnection(peer.current);
    setStatus("Connected; exchanging bounded event pages.");
    await sendPending();
  }

  async function sendPending(): Promise<void> {
    if (syncTask.current) return syncTask.current;
    const task = sendPendingPages();
    syncTask.current = task;
    try {
      await task;
    } finally {
      if (syncTask.current === task) syncTask.current = null;
    }
  }

  async function sendPendingPages(): Promise<void> {
    const dataChannel = channel.current;
    if (dataChannel?.readyState !== "open") return;
    let cursor: string | undefined;
    let sentBytes = 0;
    let sentEvents = 0;
    do {
      const page = await invoke<DesktopWebEventPage>("list_local_web_event_page", {
        spaceIdHex: spaceId,
        groupReferenceHex: groupReference,
        ...(cursor ? { afterEventIdHex: cursor } : {}),
      });
      for (const eventBytes of page.events) {
        const canonicalEvent = Uint8Array.from(eventBytes);
        if (
          canonicalEvent.byteLength === 0 ||
          canonicalEvent.byteLength > maxFrameBytes(peer.current)
        ) {
          throw new Error("Desktop Core returned an event outside the 256 KiB frame limit.");
        }
        sentBytes += canonicalEvent.byteLength;
        if (sentBytes > MAX_SESSION_BYTES) {
          throw new Error("Desktop event exchange exceeded the 16 MiB per-session bound.");
        }
        await waitForBuffer(dataChannel);
        if (dataChannel.readyState !== "open") return;
        dataChannel.send(canonicalEvent.buffer);
        sentEvents += 1;
      }
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    setStatus(
      `Offered ${sentEvents} signed message event(s) (${sentBytes} bytes); no recipient-delivery claim is made.`,
    );
  }

  async function waitForBuffer(dataChannel: RTCDataChannel): Promise<void> {
    if (dataChannel.bufferedAmount <= MAX_BUFFERED_BYTES) return;
    const { promise, resolve, reject } = deferred<void>();
    const finish = () => {
      clearTimeout(timeout);
      dataChannel.removeEventListener("bufferedamountlow", check);
      dataChannel.removeEventListener("close", closed);
    };
    const check = () => {
      if (dataChannel.bufferedAmount <= MAX_BUFFERED_BYTES) {
        finish();
        resolve(undefined);
      }
    };
    const closed = () => {
      finish();
      reject(new Error("Data channel closed during outbox exchange."));
    };
    const timeout = setTimeout(() => {
      finish();
      reject(new Error("WebRTC backpressure did not clear within 20 seconds."));
    }, 20_000);
    dataChannel.addEventListener("bufferedamountlow", check);
    dataChannel.addEventListener("close", closed);
    check();
    return promise;
  }

  function reportError(cause: unknown): void {
    const message = cause instanceof Error ? cause.message : String(cause);
    setError(message);
    setStatus(`WebRTC event exchange failed: ${message}`);
  }

  useEffect(
    () => () => {
      channel.current?.close();
      peer.current?.close();
    },
    [],
  );

  return (
    <section className="local-network-settings" aria-label="Desktop to WebRTC event exchange">
      <h4>Browser peer event exchange</h4>
      <StatusNotice kind={error ? "error" : "info"}>{error ?? status}</StatusNotice>
      <p>
        Manually transfer the offer and answer. This carries bounded signed message events only; it
        does not carry membership transitions or authenticate the remote device identity.
      </p>
      <FormField label="Optional ICE servers · JSON" htmlFor="desktop-webrtc-ice-servers">
        <textarea
          id="desktop-webrtc-ice-servers"
          value={iceServersText}
          onChange={(event) => setIceServersText(event.target.value)}
          maxLength={4_096}
          spellCheck={false}
        />
      </FormField>
      <div>
        <ActionButton
          type="button"
          tone="primary"
          onClick={() => void createOffer().catch(reportError)}
        >
          Create offer
        </ActionButton>
        <ActionButton
          type="button"
          tone="primary"
          onClick={() => void acceptOffer().catch(reportError)}
        >
          Accept offer
        </ActionButton>
        <ActionButton
          type="button"
          tone="primary"
          onClick={() => void acceptAnswer().catch(reportError)}
        >
          Accept answer
        </ActionButton>
        <ActionButton
          type="button"
          tone="primary"
          onClick={() => void sendPending().catch(reportError)}
        >
          Send pending now
        </ActionButton>
        <ActionButton
          type="button"
          tone="danger"
          onClick={() => {
            channel.current?.close();
            peer.current?.close();
            channel.current = null;
            peer.current = null;
            setStatus("Not connected");
          }}
        >
          Disconnect
        </ActionButton>
      </div>
      <FormField
        label="WebRTC offer or answer · transfer out of band"
        htmlFor="desktop-webrtc-signal"
      >
        <textarea
          id="desktop-webrtc-signal"
          value={signal}
          onChange={(event) => setSignal(event.target.value)}
          spellCheck={false}
        />
      </FormField>
      {error && <StatusNotice kind="error">{error}</StatusNotice>}
    </section>
  );
}
