import { describe, expect, test } from "bun:test";
import { inspectUntrustedCborStructure } from "./index.ts";

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
