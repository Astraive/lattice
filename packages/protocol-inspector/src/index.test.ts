import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { inspectCandidateSignedEvent, inspectUntrustedCborStructure } from "./index.ts";

function expectErrorCode(action: () => unknown, code: string): void {
  let caught: unknown;
  try {
    action();
  } catch (error) {
    caught = error;
  }
  expect(caught).toMatchObject({ name: "InspectorError", code });
}

describe("inspectUntrustedCborStructure", () => {
  test("inspects a canonical CBOR tree without implying authentication", () => {
    const result = inspectUntrustedCborStructure("a2616182182af56162f6", "hex");

    expect(result.encodedByteLength).toBe(10);
    expect(result.item).toEqual({
      type: "map",
      entries: [
        [
          { type: "text", value: "a" },
          {
            type: "array",
            items: [
              { type: "unsigned", value: 42n },
              { type: "boolean", value: true },
            ],
          },
        ],
        [{ type: "text", value: "b" }, { type: "null" }],
      ],
    });
  });
  test("decodes strict base64 input", () => {
    expect(inspectUntrustedCborStructure("AQ==", "base64")).toEqual({
      item: { type: "unsigned", value: 1n },
      encodedByteLength: 1,
    });
  });

  test("returns stable errors for malformed input", () => {
    expectErrorCode(() => inspectUntrustedCborStructure("0xz1", "hex"), "INSPECTOR_INVALID_HEX");
    expectErrorCode(() => inspectUntrustedCborStructure("1817", "hex"), "INSPECTOR_MALFORMED_CBOR");
  });
  test("rejects input over the configured byte limit", () => {
    expectErrorCode(
      () => inspectUntrustedCborStructure("0102", "hex", { maxBytes: 1 }),
      "INSPECTOR_INPUT_TOO_LARGE",
    );
  });
  test("classifies tags as unsupported rather than authenticated content", () => {
    expectErrorCode(
      () => inspectUntrustedCborStructure("d80001", "hex"),
      "INSPECTOR_UNSUPPORTED_CBOR",
    );
  });
  test("rejects duplicate and unsorted canonical map keys", () => {
    expectErrorCode(
      () => inspectUntrustedCborStructure("a2616100616101", "hex"),
      "INSPECTOR_MALFORMED_CBOR",
    );
    expectErrorCode(
      () => inspectUntrustedCborStructure("a2616200616101", "hex"),
      "INSPECTOR_MALFORMED_CBOR",
    );
  });
  test("refuses caller limits above hard parser bounds", () => {
    expectErrorCode(
      () => inspectUntrustedCborStructure("01", "hex", { maxDepth: 129 }),
      "INSPECTOR_LIMIT_EXCEEDED",
    );
    expectErrorCode(
      () => inspectUntrustedCborStructure("01", "hex", { maxItems: 65_537 }),
      "INSPECTOR_LIMIT_EXCEEDED",
    );
  });
});
const signedEventVector = JSON.parse(
  readFileSync(new URL("../../../protocol/vectors/canonical-cbor.json", import.meta.url), "utf8"),
) as { signed_event: { preimage_hex: string; outer_hex: string } };
const SIGNED_EVENT_PREIMAGE = signedEventVector.signed_event.preimage_hex;
const SIGNED_EVENT_OUTER = signedEventVector.signed_event.outer_hex;

async function expectAsyncErrorCode(action: () => Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await action();
  } catch (error) {
    caught = error;
  }
  expect(caught).toMatchObject({ name: "InspectorError", code });
}

describe("inspectCandidateSignedEvent", () => {
  test("verifies the candidate signed-event vector and returns signature-only metadata", async () => {
    const result = await inspectCandidateSignedEvent(SIGNED_EVENT_OUTER, "hex");

    expect(result).toMatchObject({
      status: "signature-verified-candidate",
      signatureVerified: true,
      eventIdHex: "dba9789ef714a3b0df9cad7990abc38841d8ab93fe5880d875da7b55632e1d75",
      preimageHex: SIGNED_EVENT_PREIMAGE,
      authorFingerprintHex: "5f7e15d6a462c18997358f8934ac2d0c53556bce94ed7d031b7c9813da55c02a",
      spaceIdHex: "000102030405060708090a0b0c0d0e0f",
      channelIdHex: null,
      authorSequence: 1n,
      lamport: 42n,
      wallTime: 1_700_000_000_000n,
      parentEventIdsHex: [],
      kind: 1,
      protectedBodyHex: "01020304",
      mlsGroupReferenceHex: "a5".repeat(32),
      mlsEpoch: 0n,
    });
  });

  test("rejects a signature-tampered outer event", async () => {
    await expectAsyncErrorCode(
      () => inspectCandidateSignedEvent(`${SIGNED_EVENT_OUTER.slice(0, -2)}0f`, "hex"),
      "INSPECTOR_INVALID_SIGNATURE",
    );
  });
  test("rejects parent event IDs that are not 32 bytes", async () => {
    const malformedPreimage = SIGNED_EVENT_PREIMAGE.replace("078008", "078141aa08");
    const malformedOuter = SIGNED_EVENT_OUTER.replace(
      `015878${SIGNED_EVENT_PREIMAGE}`,
      `01587a${malformedPreimage}`,
    );

    await expectAsyncErrorCode(
      () => inspectCandidateSignedEvent(malformedOuter, "hex"),
      "INSPECTOR_INVALID_EVENT_SHAPE",
    );
  });

  test("rejects a changed preimage author fingerprint", async () => {
    const changedPreimage = SIGNED_EVENT_PREIMAGE.replace("58205f", "58204f");
    const changedOuter = SIGNED_EVENT_OUTER.replace(SIGNED_EVENT_PREIMAGE, changedPreimage);
    await expectAsyncErrorCode(
      () => inspectCandidateSignedEvent(changedOuter, "hex"),
      "INSPECTOR_AUTHOR_FINGERPRINT_MISMATCH",
    );
  });
});
