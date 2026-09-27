const DATABASE_NAME = "lattice-web-profile-keys";
const STORE_NAME = "profiles";
const DATABASE_VERSION = 1;
const PROFILE_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const ROOT_PIN_BYTES = 32;
const AAD_DOMAIN = new TextEncoder().encode("lattice.web.origin-profile-key.v1\0");
const PAYLOAD_VERSION = 1;

interface StoredProfileKey {
  profileId: string;
  storageKey: CryptoKey;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}
interface DecodedPayload {
  wrappingKey: Uint8Array;
  rootDer: Uint8Array;
}

export interface UnlockedProfileKey {
  wrappingKey: Uint8Array;
  rootDer: Uint8Array;
  rootSha256: Uint8Array;
}

function requireSecureCrypto(): Crypto {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    throw new Error("Web Crypto and a secure browser context are required.");
  }
  return globalThis.crypto;
}
function arrayBufferOf(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes);
  return copy.buffer;
}

function profileAad(profileId: string): ArrayBuffer {
  const idBytes = new TextEncoder().encode(profileId);
  const aad = new Uint8Array(AAD_DOMAIN.length + idBytes.length);
  aad.set(AAD_DOMAIN);
  aad.set(idBytes, AAD_DOMAIN.length);
  return aad.buffer;
}

function validateProfileId(profileId: string): void {
  const size = new TextEncoder().encode(profileId).length;
  if (size === 0 || size > 128) throw new Error("Profile ID must contain 1 to 128 UTF-8 bytes.");
}

function openDatabase(): Promise<IDBDatabase> {
  const { promise, resolve, reject } = Promise.withResolvers<IDBDatabase>();
  const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
  request.onupgradeneeded = () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(STORE_NAME)) {
      database.createObjectStore(STORE_NAME, { keyPath: "profileId" });
    }
  };
  request.onsuccess = () => resolve(request.result);
  request.onerror = () =>
    reject(request.error ?? new Error("Could not open browser profile key storage."));
  request.onblocked = () =>
    reject(new Error("Browser profile key storage is blocked by another tab."));
  return promise;
}

function requestValue<T>(request: IDBRequest<T>): Promise<T> {
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  request.onsuccess = () => resolve(request.result);
  request.onerror = () =>
    reject(request.error ?? new Error("Browser profile key storage request failed."));
  return promise;
}

async function readRecord(
  database: IDBDatabase,
  profileId: string,
): Promise<StoredProfileKey | undefined> {
  const transaction = database.transaction(STORE_NAME, "readonly");
  return (await requestValue(transaction.objectStore(STORE_NAME).get(profileId))) as
    | StoredProfileKey
    | undefined;
}

async function writeRecord(database: IDBDatabase, record: StoredProfileKey): Promise<void> {
  const transaction = database.transaction(STORE_NAME, "readwrite", { durability: "strict" });
  const completion = Promise.withResolvers<void>();
  transaction.objectStore(STORE_NAME).put(record);
  transaction.oncomplete = () => completion.resolve();
  transaction.onerror = () =>
    completion.reject(transaction.error ?? new Error("Could not commit browser profile key."));
  transaction.onabort = () =>
    completion.reject(transaction.error ?? new Error("Browser profile key commit was aborted."));
  await completion.promise;
}

async function validateRootPin(rootDer: Uint8Array, expectedPin: Uint8Array): Promise<Uint8Array> {
  if (rootDer.length === 0 || rootDer.length > 4096) {
    throw new Error("Issuer root certificate must contain 1 to 4096 bytes.");
  }
  if (expectedPin.length !== ROOT_PIN_BYTES)
    throw new Error("Issuer root SHA-256 pin must be 32 bytes.");
  const digest = new Uint8Array(
    await requireSecureCrypto().subtle.digest("SHA-256", arrayBufferOf(rootDer)),
  );
  if (!digest.every((byte, index) => byte === expectedPin[index])) {
    digest.fill(0);
    throw new Error("Issuer root certificate does not match the confirmed SHA-256 pin.");
  }
  return digest;
}

function encodePayload(wrappingKey: Uint8Array, rootDer: Uint8Array): Uint8Array {
  const payload = new Uint8Array(1 + 2 + PROFILE_KEY_BYTES + rootDer.length);
  payload[0] = PAYLOAD_VERSION;
  new DataView(payload.buffer).setUint16(1, rootDer.length, false);
  payload.set(wrappingKey, 3);
  payload.set(rootDer, 3 + PROFILE_KEY_BYTES);
  return payload;
}

function decodePayload(payload: Uint8Array): DecodedPayload {
  if (payload.length < 1 + 2 + PROFILE_KEY_BYTES || payload[0] !== PAYLOAD_VERSION) {
    throw new Error("Stored browser profile key has an unsupported format.");
  }
  const rootLength = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint16(
    1,
    false,
  );
  if (
    rootLength === 0 ||
    rootLength > 4096 ||
    payload.length !== 1 + 2 + PROFILE_KEY_BYTES + rootLength
  ) {
    throw new Error("Stored issuer root certificate has an invalid length.");
  }
  return {
    wrappingKey: payload.slice(3, 3 + PROFILE_KEY_BYTES),
    rootDer: payload.slice(3 + PROFILE_KEY_BYTES),
  };
}

export class ProfileKeyVault {
  async unlock(
    profileId: string,
    confirmedRoot?: { der: Uint8Array; sha256: Uint8Array },
  ): Promise<UnlockedProfileKey> {
    validateProfileId(profileId);
    requireSecureCrypto();
    const database = await openDatabase();
    try {
      const record = await readRecord(database, profileId);
      if (record) return await this.decryptRecord(profileId, record, confirmedRoot);
      if (!confirmedRoot) {
        throw new Error(
          "This profile has no stored issuer pin; confirm an issuer root to create it.",
        );
      }
      return await this.createRecord(database, profileId, confirmedRoot);
    } finally {
      database.close();
    }
  }

  private async createRecord(
    database: IDBDatabase,
    profileId: string,
    confirmedRoot: { der: Uint8Array; sha256: Uint8Array },
  ): Promise<UnlockedProfileKey> {
    const crypto = requireSecureCrypto();
    const rootSha256 = await validateRootPin(confirmedRoot.der, confirmedRoot.sha256);
    const storageKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    const wrappingKey = crypto.getRandomValues(new Uint8Array(PROFILE_KEY_BYTES));
    const plaintext = encodePayload(wrappingKey, confirmedRoot.der);
    const plaintextBuffer = arrayBufferOf(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: arrayBufferOf(iv),
          additionalData: profileAad(profileId),
          tagLength: 128,
        },
        storageKey,
        plaintextBuffer,
      );
      await writeRecord(database, {
        profileId,
        storageKey,
        iv: iv.slice().buffer,
        ciphertext,
      });
      return { wrappingKey, rootDer: confirmedRoot.der.slice(), rootSha256 };
    } catch (error) {
      wrappingKey.fill(0);
      rootSha256.fill(0);
      throw error;
    } finally {
      plaintext.fill(0);
      new Uint8Array(plaintextBuffer).fill(0);
      iv.fill(0);
    }
  }

  private async decryptRecord(
    profileId: string,
    record: StoredProfileKey,
    confirmedRoot?: { der: Uint8Array; sha256: Uint8Array },
  ): Promise<UnlockedProfileKey> {
    if (
      record.profileId !== profileId ||
      record.storageKey.extractable ||
      record.storageKey.algorithm.name !== "AES-GCM" ||
      !record.storageKey.usages.includes("encrypt") ||
      !record.storageKey.usages.includes("decrypt")
    ) {
      throw new Error("Stored browser key does not satisfy the profile key-protection policy.");
    }
    const crypto = requireSecureCrypto();
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: record.iv,
          additionalData: profileAad(profileId),
          tagLength: 128,
        },
        record.storageKey,
        record.ciphertext,
      ),
    );
    let decoded: DecodedPayload | undefined;
    let keepWrappingKey = false;
    try {
      decoded = decodePayload(plaintext);
      const rootSha256 = new Uint8Array(
        await crypto.subtle.digest("SHA-256", arrayBufferOf(decoded.rootDer)),
      );
      const rootMatches =
        !confirmedRoot ||
        (confirmedRoot.sha256.length === ROOT_PIN_BYTES &&
          confirmedRoot.der.length === decoded.rootDer.length &&
          rootSha256.every((byte, index) => byte === confirmedRoot.sha256[index]) &&
          decoded.rootDer.every((byte, index) => byte === confirmedRoot.der[index]));
      if (!rootMatches) {
        rootSha256.fill(0);
        throw new Error("Confirmed issuer root differs from the immutable profile pin.");
      }
      keepWrappingKey = true;
      return { ...decoded, rootSha256 };
    } finally {
      plaintext.fill(0);
      if (!keepWrappingKey) decoded?.wrappingKey.fill(0);
    }
  }
}
