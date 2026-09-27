import type { ProfileWorkerClient } from "./worker-client";

const MAX_EVENT_BYTES = 256 * 1024;
const MAX_SYNC_BYTES = 16 * 1024 * 1024;
const BRIDGE_PATH = "/lattice-sync";

interface LoopbackSpace {
  space_id: number[];
  group_reference: number[];
}

interface OutboxPage {
  events: number[][];
  nextCursor: number[] | null;
}

function toHex(bytes: readonly number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validateEndpoint(text: string): URL {
  const url = new URL(text);
  if (
    url.protocol !== "ws:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.pathname !== BRIDGE_PATH ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("CLI sync accepts only ws://localhost-or-loopback/lattice-sync endpoints.");
  }
  return url;
}

export class CliLoopbackEventLink {
  readonly #profile: ProfileWorkerClient;
  readonly #space: LoopbackSpace;
  readonly #onStatus: (status: string) => void;
  readonly #onEvent: () => Promise<void>;

  constructor(
    profile: ProfileWorkerClient,
    space: LoopbackSpace,
    onStatus: (status: string) => void,
    onEvent: () => Promise<void>,
  ) {
    this.#profile = profile;
    this.#space = space;
    this.#onStatus = onStatus;
    this.#onEvent = onEvent;
  }

  async reconcile(endpointText: string, pairingToken: string): Promise<void> {
    const endpoint = validateEndpoint(endpointText.trim());
    if (!/^[0-9a-f]{64}$/i.test(pairingToken.trim())) {
      throw new Error("CLI pairing token must be exactly 32 bytes of hexadecimal.");
    }
    const socket = new WebSocket(endpoint);
    socket.binaryType = "arraybuffer";
    this.#onStatus("Connecting to the loopback CLI event bridge.");

    await new Promise<void>((resolve, reject) => {
      let settled = false;
      let ready = false;
      let uploading = false;
      let receivingBytes = 0;
      let incomingEvents = 0;
      let receiveTail = Promise.resolve();
      let timeout: ReturnType<typeof setTimeout>;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        socket.removeEventListener("open", opened);
        socket.removeEventListener("message", received);
        socket.removeEventListener("error", failed);
        socket.removeEventListener("close", closed);
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
          socket.close();
        }
        if (error) reject(error);
        else resolve();
      };
      const fail = (cause: unknown) => {
        const error = cause instanceof Error ? cause : new Error("CLI loopback sync failed.");
        this.#onStatus(`CLI sync failed: ${error.message}`);
        finish(error);
      };
      const sendPending = async () => {
        if (uploading) return;
        uploading = true;
        await receiveTail;
        let cursor: number[] | undefined;
        let sentBytes = 0;
        let sentEvents = 0;
        do {
          const page: OutboxPage | undefined = await this.#profile.run({
            operation: "outbox-message-page",
            spaceId: this.#space.space_id,
            groupReference: this.#space.group_reference,
            ...(cursor ? { afterEventId: cursor } : {}),
          });
          if (!page) break;
          for (const canonicalEvent of page.events) {
            const payload = Uint8Array.from(canonicalEvent);
            if (payload.byteLength === 0 || payload.byteLength > MAX_EVENT_BYTES) {
              throw new Error("Core returned an event outside the 256 KiB bridge-frame limit.");
            }
            sentBytes += payload.byteLength;
            if (sentBytes > MAX_SYNC_BYTES) {
              throw new Error("Browser outbox reconciliation exceeded its 16 MiB bound.");
            }
            if (socket.readyState !== WebSocket.OPEN)
              throw new Error("CLI bridge disconnected during upload.");
            socket.send(payload.buffer);
            sentEvents += 1;
          }
          cursor = page.nextCursor ?? undefined;
        } while (cursor);
        socket.send(JSON.stringify({ type: "upload-complete" }));
        this.#onStatus(
          `Uploaded ${sentEvents} events (${sentBytes} bytes); waiting for CLI Core acceptance.`,
        );
      };
      const opened = () => {
        socket.send(
          JSON.stringify({
            protocol: "lattice-web-loopback-v1",
            token: pairingToken.trim().toLowerCase(),
            space_id: toHex(this.#space.space_id),
            group_reference: toHex(this.#space.group_reference),
          }),
        );
      };
      const received = (event: MessageEvent<unknown>) => {
        if (event.data instanceof ArrayBuffer) {
          if (event.data.byteLength === 0 || event.data.byteLength > MAX_EVENT_BYTES) {
            fail(new Error("CLI bridge sent an empty or oversized event frame."));
            return;
          }
          receivingBytes += event.data.byteLength;
          if (receivingBytes > MAX_SYNC_BYTES) {
            fail(new Error("CLI history reconciliation exceeded its 16 MiB bound."));
            return;
          }
          receiveTail = receiveTail
            .then(async () => {
              await this.#profile.run({
                operation: "accept-synced-event",
                canonicalEvent: [...new Uint8Array(event.data as ArrayBuffer)],
              });
              incomingEvents += 1;
            })
            .catch(fail);
          return;
        }
        if (typeof event.data !== "string") {
          fail(new Error("CLI bridge sent an unsupported frame type."));
          return;
        }
        let message: {
          type?: unknown;
          events?: unknown;
          accepted?: unknown;
          duplicates?: unknown;
          pending?: unknown;
        };
        try {
          message = JSON.parse(event.data) as typeof message;
        } catch {
          fail(new Error("CLI bridge returned malformed control JSON."));
          return;
        }
        if (message.type === "ready") {
          if (ready) {
            fail(new Error("CLI bridge sent a duplicate ready frame."));
            return;
          }
          ready = true;
          this.#onStatus("Paired; receiving CLI history through the Web profile Core.");
        } else if (message.type === "download-complete" && ready) {
          void (async () => {
            await receiveTail;
            if (incomingEvents > 0) await this.#onEvent();
            await sendPending();
          })().catch(fail);
        } else if (message.type === "complete" && uploading) {
          this.#onStatus(
            `CLI Core accepted ${String(message.accepted)} events, deduplicated ${String(message.duplicates)}, and staged ${String(message.pending)} pending dependencies.`,
          );
          finish();
        } else {
          fail(new Error("CLI bridge sent an out-of-order control frame."));
        }
      };
      const failed = () => fail(new Error("Could not connect to the CLI loopback bridge."));
      const closed = () => {
        if (!settled)
          fail(new Error("CLI loopback connection closed before reconciliation completed."));
      };
      timeout = setTimeout(() => fail(new Error("CLI loopback sync exceeded 60 seconds.")), 60_000);
      socket.addEventListener("open", opened);
      socket.addEventListener("message", received);
      socket.addEventListener("error", failed);
      socket.addEventListener("close", closed);
    });
  }
}
