export interface SpaceRecord {
  space_id: number[];
  group_reference: number[];
  channels: { id: number[]; name: string; channel_type: string }[];
}

export interface HistoryMessage {
  event_id: number[];
  author_id: number[];
  content: string;
}

export interface InviteArtifact {
  target_fingerprint: number[];
  welcome_bootstrap: number[];
}

export function toHex(bytes: readonly number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function toPem(bytes: readonly number[], label: string): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 =
    btoa(binary)
      .match(/.{1,64}/g)
      ?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

export function spaceKey(space: SpaceRecord): string {
  return `${toHex(space.space_id)}:${toHex(space.group_reference)}`;
}

export function parseIceServers(text: string): RTCIceServer[] {
  if (new TextEncoder().encode(text).length > 16 * 1024) {
    throw new Error("ICE configuration exceeds 16 KiB.");
  }
  if (!text.trim()) return [];
  const value: unknown = JSON.parse(text);
  if (!Array.isArray(value) || value.length > 8) {
    throw new Error("ICE configuration must be a JSON array of at most 8 servers.");
  }
  return value.map((entry: unknown) => {
    if (!entry || typeof entry !== "object" || !("urls" in entry)) {
      throw new Error("Each ICE server must define a URL.");
    }
    const urls =
      typeof entry.urls === "string"
        ? [entry.urls]
        : Array.isArray(entry.urls) && entry.urls.every((url) => typeof url === "string")
          ? entry.urls
          : undefined;
    if (
      !urls ||
      urls.length === 0 ||
      urls.length > 4 ||
      urls.some((url) => !/^(stun|stuns|turns):[^\s]+$/i.test(url))
    ) {
      throw new Error("ICE URLs must use stun:, stuns:, or secure turns: schemes.");
    }
    const server: RTCIceServer = { urls };
    if ("username" in entry) {
      if (typeof entry.username !== "string" || entry.username.length > 256) {
        throw new Error("TURN username must be a string of at most 256 characters.");
      }
      server.username = entry.username;
    }
    if ("credential" in entry) {
      if (typeof entry.credential !== "string" || entry.credential.length > 1024) {
        throw new Error("TURN credential must be a string of at most 1024 characters.");
      }
      server.credential = entry.credential;
    }
    if (
      urls.some((url: string) => url.toLowerCase().startsWith("turns:")) &&
      (!server.username || !server.credential)
    ) {
      throw new Error("Secure TURN servers require a username and credential.");
    }
    return server;
  });
}
