export type InspectorErrorCode =
  | "INSPECTOR_INVALID_HEX"
  | "INSPECTOR_INVALID_BASE64"
  | "INSPECTOR_INPUT_TOO_LARGE"
  | "INSPECTOR_MALFORMED_CBOR"
  | "INSPECTOR_UNSUPPORTED_CBOR"
  | "INSPECTOR_LIMIT_EXCEEDED";

export class InspectorError extends Error {
  constructor(
    readonly code: InspectorErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "InspectorError";
  }
}

export type CborValue =
  | { readonly type: "unsigned"; readonly value: bigint }
  | { readonly type: "negative"; readonly value: bigint }
  | { readonly type: "bytes"; readonly valueHex: string }
  | { readonly type: "text"; readonly value: string }
  | { readonly type: "array"; readonly items: readonly CborValue[] }
  | {
      readonly type: "map";
      readonly entries: readonly (readonly [CborValue, CborValue])[];
    }
  | { readonly type: "boolean"; readonly value: boolean }
  | { readonly type: "null" };

export interface InspectionLimits {
  readonly maxBytes?: number;
  readonly maxDepth?: number;
  readonly maxItems?: number;
}

export interface UntrustedCborStructure {
  /** The decoded, structurally valid item. This is not an authenticated event. */
  readonly item: CborValue;
  readonly encodedByteLength: number;
}

const DEFAULT_MAX_BYTES = 64 * 1024;
const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_ITEMS = 8192;
const HARD_MAX_BYTES = 1024 * 1024;
const HARD_MAX_DEPTH = 128;
const HARD_MAX_ITEMS = 65_536;
const HEX = "0123456789abcdef";
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function fail(code: InspectorErrorCode, message: string): never {
  throw new InspectorError(code, message);
}

function validateLimit(value: number, name: string, hardMaximum: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > hardMaximum) {
    fail("INSPECTOR_LIMIT_EXCEEDED", `${name} must be between zero and ${hardMaximum}`);
  }
  return value;
}

function decodeHex(input: string, maxBytes: number): Uint8Array {
  if (input.length > maxBytes * 2) {
    fail("INSPECTOR_INPUT_TOO_LARGE", "Decoded input exceeds the byte limit");
  }
  if ((input.length & 1) !== 0 || !/^[0-9a-fA-F]*$/.test(input)) {
    fail("INSPECTOR_INVALID_HEX", "Hex input must contain complete byte pairs");
  }
  const length = input.length / 2;
  if (length > maxBytes) {
    fail("INSPECTOR_INPUT_TOO_LARGE", "Decoded input exceeds the byte limit");
  }
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = Number.parseInt(input.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function decodeBase64(input: string, maxBytes: number): Uint8Array {
  if (input.length > Math.ceil(maxBytes / 3) * 4) {
    fail("INSPECTOR_INPUT_TOO_LARGE", "Decoded input exceeds the byte limit");
  }
  if (
    input.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input)
  ) {
    fail("INSPECTOR_INVALID_BASE64", "Input must be canonical padded base64");
  }
  const padding = input.endsWith("==") ? 2 : input.endsWith("=") ? 1 : 0;
  const length = (input.length / 4) * 3 - padding;
  if (length > maxBytes) {
    fail("INSPECTOR_INPUT_TOO_LARGE", "Decoded input exceeds the byte limit");
  }
  if (
    (padding === 2 && (BASE64.indexOf(input.charAt(input.length - 3)) & 15) !== 0) ||
    (padding === 1 && (BASE64.indexOf(input.charAt(input.length - 2)) & 3) !== 0)
  ) {
    fail("INSPECTOR_INVALID_BASE64", "Base64 has non-zero unused pad bits");
  }
  const bytes = new Uint8Array(length);
  let outputIndex = 0;
  for (let index = 0; index < input.length; index += 4) {
    const a = BASE64.indexOf(input.charAt(index));
    const b = BASE64.indexOf(input.charAt(index + 1));
    const c = input.charAt(index + 2) === "=" ? 0 : BASE64.indexOf(input.charAt(index + 2));
    const d = input.charAt(index + 3) === "=" ? 0 : BASE64.indexOf(input.charAt(index + 3));
    const block = (a << 18) | (b << 12) | (c << 6) | d;
    if (outputIndex < length) bytes[outputIndex++] = (block >>> 16) & 255;
    if (outputIndex < length) bytes[outputIndex++] = (block >>> 8) & 255;
    if (outputIndex < length) bytes[outputIndex++] = block & 255;
  }
  return bytes;
}

function hex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) result += HEX.charAt(byte >>> 4) + HEX.charAt(byte & 15);
  return result;
}

function compareCanonical(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let index = 0; index < a.length; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

class CborReader {
  private offset = 0;
  private itemCount = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly maxDepth: number,
    private readonly maxItems: number,
  ) {}

  parse(): CborValue {
    const item = this.readItem(0);
    if (this.offset !== this.bytes.length) {
      fail("INSPECTOR_MALFORMED_CBOR", "Trailing bytes after the CBOR item");
    }
    return item;
  }

  private readByte(): number {
    if (this.offset >= this.bytes.length) {
      fail("INSPECTOR_MALFORMED_CBOR", "Unexpected end of CBOR input");
    }
    const byte = this.bytes[this.offset++];
    if (byte === undefined) {
      fail("INSPECTOR_MALFORMED_CBOR", "Unexpected end of CBOR input");
    }
    return byte;
  }

  private readArgument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    let count: number;
    let minimum: bigint;
    switch (additional) {
      case 24:
        count = 1;
        minimum = 24n;
        break;
      case 25:
        count = 2;
        minimum = 256n;
        break;
      case 26:
        count = 4;
        minimum = 65536n;
        break;
      case 27:
        count = 8;
        minimum = 0x1_0000_0000n;
        break;
      case 31:
        return fail("INSPECTOR_UNSUPPORTED_CBOR", "Indefinite-length CBOR is unsupported");
      default:
        return fail("INSPECTOR_MALFORMED_CBOR", "Reserved CBOR additional information");
    }
    let value = 0n;
    for (let index = 0; index < count; index += 1) {
      value = (value << 8n) | BigInt(this.readByte());
    }
    if (value < minimum) {
      fail("INSPECTOR_MALFORMED_CBOR", "Non-minimal CBOR argument encoding");
    }
    return value;
  }

  private readLength(additional: number): number {
    const length = this.readArgument(additional);
    if (length > BigInt(this.bytes.length - this.offset)) {
      fail("INSPECTOR_MALFORMED_CBOR", "CBOR length exceeds remaining input");
    }
    return Number(length);
  }

  private readItem(depth: number): CborValue {
    if (depth > this.maxDepth) {
      fail("INSPECTOR_LIMIT_EXCEEDED", "CBOR nesting exceeds the depth limit");
    }
    this.itemCount += 1;
    if (this.itemCount > this.maxItems) {
      fail("INSPECTOR_LIMIT_EXCEEDED", "CBOR item count exceeds the limit");
    }
    const start = this.offset;
    const initial = this.readByte();
    const major = initial >>> 5;
    const additional = initial & 31;
    switch (major) {
      case 0:
        return { type: "unsigned", value: this.readArgument(additional) };
      case 1:
        return { type: "negative", value: -1n - this.readArgument(additional) };
      case 2: {
        const length = this.readLength(additional);
        const contents = this.bytes.subarray(this.offset, this.offset + length);
        this.offset += length;
        return { type: "bytes", valueHex: hex(contents) };
      }
      case 3: {
        const length = this.readLength(additional);
        const contents = this.bytes.subarray(this.offset, this.offset + length);
        this.offset += length;
        try {
          return {
            type: "text",
            value: new TextDecoder("utf-8", { fatal: true }).decode(contents),
          };
        } catch {
          return fail("INSPECTOR_MALFORMED_CBOR", "CBOR text is not valid UTF-8");
        }
      }
      case 4: {
        const length = this.readContainerLength(additional);
        const items: CborValue[] = [];
        for (let index = 0; index < length; index += 1) {
          items.push(this.readItem(depth + 1));
        }
        return { type: "array", items };
      }
      case 5: {
        const length = this.readContainerLength(additional);
        const entries: (readonly [CborValue, CborValue])[] = [];
        const seen = new Set<string>();
        let previousKey: Uint8Array | undefined;
        for (let index = 0; index < length; index += 1) {
          const keyStart = this.offset;
          const key = this.readItem(depth + 1);
          const keyBytes = this.bytes.slice(keyStart, this.offset);
          const keyHex = hex(keyBytes);
          if (seen.has(keyHex)) {
            fail("INSPECTOR_MALFORMED_CBOR", "Duplicate CBOR map key");
          }
          if (previousKey !== undefined && compareCanonical(previousKey, keyBytes) >= 0) {
            fail("INSPECTOR_MALFORMED_CBOR", "CBOR map keys are not canonically ordered");
          }
          seen.add(keyHex);
          previousKey = keyBytes;
          entries.push([key, this.readItem(depth + 1)]);
        }
        return { type: "map", entries };
      }
      case 6:
        return fail("INSPECTOR_UNSUPPORTED_CBOR", "CBOR tags are unsupported");
      case 7:
        if (additional === 20) return { type: "boolean", value: false };
        if (additional === 21) return { type: "boolean", value: true };
        if (additional === 22) return { type: "null" };
        return fail("INSPECTOR_UNSUPPORTED_CBOR", "CBOR simple values and floats are unsupported");
      default:
        return fail("INSPECTOR_MALFORMED_CBOR", `Invalid CBOR major type at byte ${start}`);
    }
  }

  private readContainerLength(additional: number): number {
    const length = this.readArgument(additional);
    if (length > BigInt(this.maxItems - this.itemCount)) {
      fail("INSPECTOR_LIMIT_EXCEEDED", "Container exceeds the remaining item limit");
    }
    return Number(length);
  }
}

/**
 * Decodes and structurally inspects one strict, bounded CBOR item.
 * Structural inspection does not verify signatures, authorization, or event validity.
 */
export function inspectUntrustedCborStructure(
  encoded: string,
  encoding: "hex" | "base64",
  limits: InspectionLimits = {},
): UntrustedCborStructure {
  const maxBytes = validateLimit(limits.maxBytes ?? DEFAULT_MAX_BYTES, "maxBytes", HARD_MAX_BYTES);
  const maxDepth = validateLimit(limits.maxDepth ?? DEFAULT_MAX_DEPTH, "maxDepth", HARD_MAX_DEPTH);
  const maxItems = validateLimit(limits.maxItems ?? DEFAULT_MAX_ITEMS, "maxItems", HARD_MAX_ITEMS);
  const bytes = encoding === "hex" ? decodeHex(encoded, maxBytes) : decodeBase64(encoded, maxBytes);
  return {
    item: new CborReader(bytes, maxDepth, maxItems).parse(),
    encodedByteLength: bytes.length,
  };
}
