import { describe, expect, test } from "bun:test";
import { formatFingerprint, parseHexBytes } from "../src/identity";

describe("identity input helpers", () => {
  test("parses grouped hexadecimal bytes and checks exact pin length", () => {
    expect(parseHexBytes("01:ab 23", 3)).toEqual(new Uint8Array([1, 171, 35]));
    expect(() => parseHexBytes("01:ab", 3)).toThrow("Expected 3 bytes; got 2.");
  });

  test("rejects malformed byte strings and formats a stable fingerprint", () => {
    expect(() => parseHexBytes("abc")).toThrow("even-length hexadecimal");
    expect(() => parseHexBytes("01xz")).toThrow("even-length hexadecimal");
    expect(formatFingerprint([0, 17, 34, 255])).toBe("0011 22FF");
  });
});
