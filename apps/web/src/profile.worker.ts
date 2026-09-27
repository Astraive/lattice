import { ProfileKeyVault } from "./profile-key-vault";
import initWasm, { open_profile, type WebProfile } from "./wasm/lattice_web_wasm.js";

interface OpenProfileRequest {
  requestId: string;
  type: "open-profile";
  profileId: string;
  rootDer?: number[];
  rootSha256?: number[];
}

interface CloseProfileRequest {
  requestId: string;
  type: "close-profile";
}

type WorkerOperationRequest =
  | {
      requestId: string;
      type: "profile-operation";
      operation: "certificate-request" | "list-spaces";
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "create-space" | "publish-key-package";
      certificateDer: number[];
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "create-invite";
      spaceId: number[];
      groupReference: number[];
      certificateDer: number[];
      keyPackage: number[];
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "join-space";
      welcomeBootstrap: number[];
      inviterFingerprint: number[];
      certificateDer: number[];
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "send-text-message";
      spaceId: number[];
      groupReference: number[];
      channelId: number[];
      certificateDer: number[];
      content: string;
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "message-history";
      spaceId: number[];
      groupReference: number[];
      channelId: number[];
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "outbox-message-page";
      spaceId: number[];
      groupReference: number[];
      afterEventId?: number[];
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "accept-synced-event";
      canonicalEvent: number[];
    }
  | {
      requestId: string;
      type: "profile-operation";
      operation: "pin-identity";
      publicBundle: number[];
      fingerprint: number[];
    };

type WorkerRequest = OpenProfileRequest | CloseProfileRequest | WorkerOperationRequest;

interface OpenProfileResponse {
  requestId: string;
  type: "profile-opened";
  profileId: string;
  identity: { public_bundle: number[]; fingerprint: number[] };
}

interface WorkerOperationResponse {
  requestId: string;
  type: "profile-operation-result";
  operation: WorkerOperationRequest["operation"];
  result: unknown;
}

interface WorkerErrorResponse {
  requestId: string;
  type: "profile-error";
  message: string;
}

let activeProfileId: string | undefined;
let activeCore: WebProfile | undefined;
let releaseLock: (() => void) | undefined;
let lockRequest: Promise<void> | undefined;
let opening: Promise<OpenProfileResponse> | undefined;
const vault = new ProfileKeyVault();

function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object" && "message" in error) {
    return String(error.message);
  }
  return String(error);
}

function postError(requestId: string, error: unknown): void {
  const response: WorkerErrorResponse = {
    requestId,
    type: "profile-error",
    message: errorMessage(error),
  };
  self.postMessage(response);
}

async function openProfile(request: OpenProfileRequest): Promise<OpenProfileResponse> {
  if (!globalThis.isSecureContext || typeof navigator.storage?.getDirectory !== "function") {
    throw new Error("A secure browser context with OPFS support is required.");
  }
  if (!navigator.locks) throw new Error("This browser does not support exclusive profile locks.");
  if (activeProfileId && activeProfileId !== request.profileId) {
    throw new Error(
      "This worker already owns a different profile; close it before switching profiles.",
    );
  }
  if (activeCore && activeProfileId === request.profileId) {
    return {
      requestId: request.requestId,
      type: "profile-opened",
      profileId: request.profileId,
      identity: JSON.parse(activeCore.identityInfoJson()) as OpenProfileResponse["identity"],
    };
  }
  if (opening) {
    return opening.then((response) => ({ ...response, requestId: request.requestId }));
  }

  const result = Promise.withResolvers<OpenProfileResponse>();
  const shutdown = Promise.withResolvers<void>();
  releaseLock = shutdown.resolve;
  activeProfileId = request.profileId;
  opening = result.promise;

  lockRequest = navigator.locks
    .request(
      `lattice-profile:${request.profileId}`,
      { mode: "exclusive", ifAvailable: true },
      async (lock) => {
        if (!lock) {
          result.reject(new Error("This Lattice profile is already open in another tab."));
          activeProfileId = undefined;
          if (opening === result.promise) opening = undefined;
          releaseLock = undefined;
          return;
        }
        let wrappingKey: Uint8Array | undefined;
        let rootDer: Uint8Array | undefined;
        let rootSha256: Uint8Array | undefined;
        let core: WebProfile | undefined;
        try {
          const hasRoot = request.rootDer !== undefined;
          if (hasRoot !== (request.rootSha256 !== undefined)) {
            throw new Error("Issuer root DER and its SHA-256 pin must be supplied together.");
          }
          const confirmedRoot = hasRoot
            ? {
                der: new Uint8Array(request.rootDer as number[]),
                sha256: new Uint8Array(request.rootSha256 as number[]),
              }
            : undefined;
          const unlocked = await vault.unlock(request.profileId, confirmedRoot);
          wrappingKey = unlocked.wrappingKey;
          rootDer = unlocked.rootDer;
          rootSha256 = unlocked.rootSha256;
          await initWasm();
          core = await open_profile(request.profileId, rootDer, rootSha256, wrappingKey);
          const response: OpenProfileResponse = {
            requestId: request.requestId,
            type: "profile-opened",
            profileId: request.profileId,
            identity: JSON.parse(core.identityInfoJson()) as OpenProfileResponse["identity"],
          };
          activeCore = core;
          result.resolve(response);
          await shutdown.promise;
        } catch (error) {
          result.reject(error);
        } finally {
          core?.close();
          if (activeCore === core) activeCore = undefined;
          wrappingKey?.fill(0);
          rootDer?.fill(0);
          rootSha256?.fill(0);
          if (activeProfileId === request.profileId) activeProfileId = undefined;
          if (opening === result.promise) opening = undefined;
          releaseLock = undefined;
        }
      },
    )
    .catch((error: unknown) => {
      result.reject(error);
      if (activeProfileId === request.profileId) activeProfileId = undefined;
      if (opening === result.promise) opening = undefined;
      releaseLock = undefined;
    });

  return result.promise;
}

let operationQueue = Promise.resolve();

async function runProfileOperation(request: WorkerOperationRequest): Promise<void> {
  const core = activeCore;
  if (!core) throw new Error("Open a browser profile before using it.");
  let result: unknown;
  switch (request.operation) {
    case "certificate-request":
      result = [...core.certificateSigningRequest()];
      break;
    case "pin-identity":
      core.pinIdentity(new Uint8Array(request.publicBundle), new Uint8Array(request.fingerprint));
      result = true;
      break;
    case "list-spaces":
      result = core.spacesJson();
      break;
    case "create-space":
      result = core.createSpace(new Uint8Array(request.certificateDer));
      break;
    case "publish-key-package":
      result = [...core.publishKeyPackage(new Uint8Array(request.certificateDer))];
      break;
    case "create-invite":
      result = core.createInvite(
        new Uint8Array(request.spaceId),
        new Uint8Array(request.groupReference),
        new Uint8Array(request.certificateDer),
        new Uint8Array(request.keyPackage),
      );
      break;
    case "join-space":
      result = core.joinSpace(
        new Uint8Array(request.welcomeBootstrap),
        new Uint8Array(request.inviterFingerprint),
        new Uint8Array(request.certificateDer),
      );
      break;
    case "send-text-message":
      core.sendTextMessage(
        new Uint8Array(request.spaceId),
        new Uint8Array(request.groupReference),
        new Uint8Array(request.channelId),
        new Uint8Array(request.certificateDer),
        request.content,
      );
      result = null;
      break;
    case "message-history":
      result = core.textMessageHistoryJson(
        new Uint8Array(request.spaceId),
        new Uint8Array(request.groupReference),
        new Uint8Array(request.channelId),
      );
      break;
    case "outbox-message-page": {
      const page = core.outboxMessagePage(
        new Uint8Array(request.spaceId),
        new Uint8Array(request.groupReference),
        request.afterEventId ? new Uint8Array(request.afterEventId) : undefined,
      );
      result = {
        events: Array.from(page[0] as Array<Uint8Array>, (event) => [...event]),
        nextCursor: page[1] ? [...(page[1] as Uint8Array)] : null,
      };
      break;
    }
    case "accept-synced-event":
      core.acceptSyncedEvent(new Uint8Array(request.canonicalEvent));
      result = null;
      break;
  }
  const response: WorkerOperationResponse = {
    requestId: request.requestId,
    type: "profile-operation-result",
    operation: request.operation,
    result,
  };
  self.postMessage(response);
}

self.addEventListener("message", (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  if (!request || typeof request.requestId !== "string") return;
  if (request.type === "open-profile") {
    void openProfile(request)
      .then((response) => self.postMessage(response))
      .catch((error: unknown) => postError(request.requestId, error));
    return;
  }
  if (request.type === "close-profile") {
    operationQueue = operationQueue
      .then(async () => {
        const finishClose = releaseLock;
        if (finishClose) {
          finishClose();
          await lockRequest;
        }
        self.postMessage({ requestId: request.requestId, type: "profile-closed" });
      })
      .catch((error: unknown) => postError(request.requestId, error));
    return;
  }
  operationQueue = operationQueue
    .then(() => runProfileOperation(request))
    .catch((error: unknown) => postError(request.requestId, error));
});
