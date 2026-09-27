export function parseHexBytes(value: string, expectedBytes?: number): Uint8Array {
  const compact = value.replace(/[\s:]/g, "");
  if (compact.length === 0 || compact.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(compact)) {
    throw new Error("Enter an even-length hexadecimal byte string.");
  }
  const bytes = new Uint8Array(compact.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(compact.slice(index * 2, index * 2 + 2), 16);
  }
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new Error(`Expected ${expectedBytes} bytes; got ${bytes.length}.`);
  }
  return bytes;
}

export function formatFingerprint(bytes: readonly number[]): string {
  return (
    bytes
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase()
      .match(/.{1,4}/g)
      ?.join(" ") ?? ""
  );
}
