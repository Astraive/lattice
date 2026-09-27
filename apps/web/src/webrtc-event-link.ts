import type { ProfileWorkerClient } from "./worker-client";

const MAX_SIGNAL_BYTES = 256 * 1024;
const MAX_EVENT_BYTES = 256 * 1024;
const MAX_SYNC_BYTES = 16 * 1024 * 1024;
const MAX_BUFFERED_BYTES = 1024 * 1024;

export interface WebRtcSpace {
  space_id: number[];
  group_reference: number[];
}

interface OutboxPage {
  events: number[][];
  nextCursor: number[] | null;
}

function parseDescription(text: string, type: RTCSdpType): RTCSessionDescriptionInit {
  if (new TextEncoder().encode(text).length > MAX_SIGNAL_BYTES) {
    throw new Error("Session description exceeds the 256 KiB limit.");
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

function gatherComplete(peer: RTCPeerConnection): Promise<void> {
  if (peer.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve, reject) => {
    const finish = () => {
      clearTimeout(timeout);
      peer.removeEventListener("icegatheringstatechange", check);
    };
    const check = () => {
      if (peer.iceGatheringState === "complete") {
        finish();
        resolve();
      }
    };
    const timeout = setTimeout(() => {
      finish();
      reject(new Error("ICE candidate gathering timed out."));
    }, 20_000);
    peer.addEventListener("icegatheringstatechange", check);
    check();
  });
}

function waitForConnection(peer: RTCPeerConnection): Promise<void> {
  if (peer.connectionState === "connected") return Promise.resolve();
  return new Promise((resolve, reject) => {
    const finish = () => {
      clearTimeout(timeout);
      peer.removeEventListener("connectionstatechange", check);
    };
    const check = () => {
      if (peer.connectionState === "connected") {
        finish();
        resolve();
      } else if (peer.connectionState === "failed" || peer.connectionState === "closed") {
        finish();
        reject(new Error(`WebRTC connection entered ${peer.connectionState}.`));
      }
    };
    const timeout = setTimeout(() => {
      finish();
      reject(new Error("WebRTC did not reconnect within 20 seconds."));
    }, 20_000);
    peer.addEventListener("connectionstatechange", check);
    check();
  });
}

export class WebRtcEventLink {
  readonly #profile: ProfileWorkerClient;
  readonly #space: WebRtcSpace;
  readonly #onStatus: (status: string) => void;
  readonly #onEvent: () => Promise<void>;
  readonly #configuration: RTCConfiguration;
  #peer: RTCPeerConnection | null = null;
  #channel: RTCDataChannel | null = null;
  #sync: Promise<void> | null = null;
  #sentEventDigests = new Set<string>();
  #hasConnected = false;

  constructor(
    profile: ProfileWorkerClient,
    space: WebRtcSpace,
    onStatus: (status: string) => void,
    onEvent: () => Promise<void>,
    configuration: RTCConfiguration,
  ) {
    this.#profile = profile;
    this.#space = space;
    this.#onStatus = onStatus;
    this.#onEvent = onEvent;
    this.#configuration = configuration;
  }

  async createOffer(restart = false): Promise<string> {
    const peer = this.#ensurePeer();
    if (restart) peer.restartIce();
    if (!this.#channel || this.#channel.readyState === "closed") {
      this.#attachChannel(peer.createDataChannel("lattice-events", { ordered: true }));
    }
    const offer = await peer.createOffer(restart ? { iceRestart: true } : undefined);
    await peer.setLocalDescription(offer);
    await gatherComplete(peer);
    if (!peer.localDescription) throw new Error("WebRTC did not produce a local offer.");
    this.#onStatus(
      restart
        ? "ICE restart offer ready; transfer it to the peer."
        : "Offer ready; transfer it to the peer.",
    );
    return JSON.stringify({ type: peer.localDescription.type, sdp: peer.localDescription.sdp });
  }

  async acceptOffer(text: string): Promise<string> {
    const peer = this.#ensurePeer();
    await peer.setRemoteDescription(parseDescription(text, "offer"));
    const answer = await peer.createAnswer();
    await peer.setLocalDescription(answer);
    await gatherComplete(peer);
    if (!peer.localDescription) throw new Error("WebRTC did not produce a local answer.");
    this.#onStatus("Answer ready; transfer it to the peer.");
    return JSON.stringify({ type: peer.localDescription.type, sdp: peer.localDescription.sdp });
  }

  async acceptAnswer(text: string): Promise<void> {
    const peer = this.#peer;
    if (!peer) throw new Error("Create an offer before accepting an answer.");
    await peer.setRemoteDescription(parseDescription(text, "answer"));
    this.#onStatus("Answer accepted; establishing the peer connection.");
    await waitForConnection(peer);
    this.#onStatus("Connected; bounded outbox reconciliation is active.");
    this.#sentEventDigests.clear();
    await this.sendPending();
  }

  close(): void {
    this.#channel?.close();
    this.#peer?.close();
    this.#channel = null;
    this.#peer = null;
    this.#sync = null;
    this.#onStatus("Not connected");
  }

  async sendPending(): Promise<void> {
    if (this.#sync) await this.#sync;
    const task = this.#sendPendingPages();
    this.#sync = task;
    try {
      await task;
    } finally {
      if (this.#sync === task) this.#sync = null;
    }
  }

  #ensurePeer(): RTCPeerConnection {
    if (this.#peer) return this.#peer;
    const peer = new RTCPeerConnection(this.#configuration);
    this.#peer = peer;
    peer.addEventListener("datachannel", (event) => this.#attachChannel(event.channel));
    peer.addEventListener("connectionstatechange", () => {
      if (peer.connectionState === "connected") {
        if (this.#hasConnected) {
          this.#sentEventDigests.clear();
          void this.sendPending().catch((error: unknown) => this.#report(error));
        }
        this.#hasConnected = true;
        this.#onStatus("Connected; Core-authenticated event sync is active.");
      } else {
        this.#onStatus(`WebRTC ${peer.connectionState}; use ICE restart if it does not recover.`);
      }
    });
    peer.addEventListener("iceconnectionstatechange", () => {
      if (peer.iceConnectionState === "disconnected") {
        this.#onStatus("Network interrupted; WebRTC is attempting ICE recovery.");
      }
    });
    return peer;
  }

  #maxFrameBytes(): number {
    const negotiated = this.#peer?.sctp?.maxMessageSize;
    return negotiated && negotiated > 0 ? Math.min(MAX_EVENT_BYTES, negotiated) : MAX_EVENT_BYTES;
  }

  #attachChannel(channel: RTCDataChannel): void {
    this.#channel = channel;
    channel.binaryType = "arraybuffer";
    channel.bufferedAmountLowThreshold = MAX_BUFFERED_BYTES / 2;
    channel.addEventListener("open", () => {
      this.#sentEventDigests.clear();
      this.#onStatus("Connected; reconciling the bounded local outbox.");
      void this.sendPending().catch((error: unknown) => this.#report(error));
    });
    channel.addEventListener("close", () => {
      if (this.#channel === channel) {
        this.#onStatus("Data channel closed; create an offer to reconnect.");
      }
    });
    channel.addEventListener("message", (event) => {
      if (
        !(event.data instanceof ArrayBuffer) ||
        event.data.byteLength === 0 ||
        event.data.byteLength > this.#maxFrameBytes()
      ) {
        this.#onStatus("Rejected a non-binary or oversized event frame.");
        return;
      }
      void this.#profile
        .run({ operation: "accept-synced-event", canonicalEvent: [...new Uint8Array(event.data)] })
        .then(async () => {
          this.#onStatus("Inbound event passed Core validation.");
          await this.#onEvent();
        })
        .catch((error: unknown) => this.#report(error));
    });
  }

  async #eventDigest(event: Uint8Array): Promise<string> {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(event).buffer),
    );
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async #sendPendingPages(): Promise<void> {
    let cursor: number[] | undefined;
    let sentEvents = 0;
    let sentBytes = 0;
    const channel = this.#channel;
    if (channel?.readyState !== "open") return;
    do {
      const page: OutboxPage | undefined = await this.#profile.run({
        operation: "outbox-message-page",
        spaceId: this.#space.space_id,
        groupReference: this.#space.group_reference,
        ...(cursor ? { afterEventId: cursor } : {}),
      });
      if (!page) return;
      for (const canonicalEvent of page.events) {
        const payload = Uint8Array.from(canonicalEvent);
        if (payload.byteLength === 0 || payload.byteLength > this.#maxFrameBytes()) {
          throw new Error("Core returned an event outside the negotiated WebRTC frame limit.");
        }
        const digest = await this.#eventDigest(payload);
        if (this.#sentEventDigests.has(digest)) continue;
        sentBytes += payload.byteLength;
        if (sentBytes > MAX_SYNC_BYTES) {
          throw new Error("Outbox reconciliation exceeded the 16 MiB per-session bound.");
        }
        await this.#waitForBuffer(channel);
        if (channel.readyState !== "open") return;
        channel.send(payload.buffer);
        this.#sentEventDigests.add(digest);
        sentEvents += 1;
      }
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    this.#onStatus(`Reconciled ${sentEvents} events (${sentBytes} bytes) through the peer link.`);
  }

  async #waitForBuffer(channel: RTCDataChannel): Promise<void> {
    if (channel.bufferedAmount <= MAX_BUFFERED_BYTES) return;
    await new Promise<void>((resolve, reject) => {
      const finish = () => {
        clearTimeout(timeout);
        channel.removeEventListener("bufferedamountlow", check);
        channel.removeEventListener("close", closed);
      };
      const check = () => {
        if (channel.bufferedAmount <= MAX_BUFFERED_BYTES) {
          finish();
          resolve();
        }
      };
      const closed = () => {
        finish();
        reject(new Error("Data channel closed during bounded outbox reconciliation."));
      };
      const timeout = setTimeout(() => {
        finish();
        reject(new Error("WebRTC backpressure did not clear within 20 seconds."));
      }, 20_000);
      channel.addEventListener("bufferedamountlow", check);
      channel.addEventListener("close", closed);
      check();
    });
  }

  #report(error: unknown): void {
    this.#onStatus(error instanceof Error ? `Sync failed: ${error.message}` : "Sync failed.");
  }
}
