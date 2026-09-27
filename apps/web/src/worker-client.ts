export interface PublicIdentity {
  public_bundle: number[];
  fingerprint: number[];
}

export interface OpenedProfile {
  requestId: string;
  type: "profile-opened";
  profileId: string;
  identity: PublicIdentity;
}

interface WorkerError {
  requestId: string;
  type: "profile-error";
  message: string;
}

export type ProfileOperationRequest =
  | { operation: "certificate-request" | "list-spaces" }
  | { operation: "create-space" | "publish-key-package"; certificateDer: number[] }
  | {
      operation: "create-invite";
      spaceId: number[];
      groupReference: number[];
      certificateDer: number[];
      keyPackage: number[];
    }
  | {
      operation: "join-space";
      welcomeBootstrap: number[];
      inviterFingerprint: number[];
      certificateDer: number[];
    }
  | {
      operation: "send-text-message";
      spaceId: number[];
      groupReference: number[];
      channelId: number[];
      certificateDer: number[];
      content: string;
    }
  | {
      operation: "message-history";
      spaceId: number[];
      groupReference: number[];
      channelId: number[];
    }
  | {
      operation: "outbox-message-page";
      spaceId: number[];
      groupReference: number[];
      afterEventId?: number[];
    }
  | { operation: "accept-synced-event"; canonicalEvent: number[] }
  | { operation: "pin-identity"; publicBundle: number[]; fingerprint: number[] };

interface WorkerOperationResult {
  requestId: string;
  type: "profile-operation-result";
  operation: ProfileOperationRequest["operation"];
  result: unknown;
}

type WorkerResponse =
  | OpenedProfile
  | WorkerError
  | WorkerOperationResult
  | { requestId: string; type: "profile-closed" };

interface PendingWorkerResponse {
  promise: Promise<WorkerResponse>;
  resolve: (response: WorkerResponse | PromiseLike<WorkerResponse>) => void;
  reject: (reason?: unknown) => void;
}

export class ProfileWorkerClient {
  readonly #worker = new Worker(new URL("./profile.worker.ts", import.meta.url), {
    type: "module",
  });
  readonly #pending = new Map<string, PendingWorkerResponse>();

  constructor() {
    this.#worker.addEventListener("message", (event: MessageEvent<WorkerResponse>) => {
      const pending = this.#pending.get(event.data.requestId);
      if (!pending) return;
      this.#pending.delete(event.data.requestId);
      if (event.data.type === "profile-error") pending.reject(new Error(event.data.message));
      else pending.resolve(event.data);
    });
    this.#worker.addEventListener("error", (event) => {
      for (const pending of this.#pending.values()) pending.reject(new Error(event.message));
      this.#pending.clear();
    });
  }

  openProfile(
    profileId: string,
    confirmedRoot?: { der: Uint8Array; sha256: Uint8Array },
  ): Promise<OpenedProfile> {
    return this.#request({
      type: "open-profile",
      profileId,
      ...(confirmedRoot
        ? { rootDer: [...confirmedRoot.der], rootSha256: [...confirmedRoot.sha256] }
        : {}),
    }).then((response) => {
      if (response.type !== "profile-opened") throw new Error("Unexpected worker response.");
      return response;
    });
  }

  run<T>(request: ProfileOperationRequest): Promise<T> {
    return this.#request({ type: "profile-operation", ...request }).then((response) => {
      if (
        response.type !== "profile-operation-result" ||
        response.operation !== request.operation
      ) {
        throw new Error("Unexpected worker response.");
      }
      return response.result as T;
    });
  }

  async closeProfile(): Promise<void> {
    try {
      const response = await this.#request({ type: "close-profile" });
      if (response.type !== "profile-closed") throw new Error("Unexpected worker response.");
    } finally {
      this.#worker.terminate();
      this.#pending.clear();
    }
  }

  #request(request: object): Promise<WorkerResponse> {
    const requestId = crypto.randomUUID();
    const { promise, resolve, reject } = Promise.withResolvers<WorkerResponse>();
    this.#pending.set(requestId, { promise, resolve, reject });
    this.#worker.postMessage({ ...request, requestId });
    return promise;
  }
}
