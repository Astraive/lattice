# ADR-003: Nostr mailbox profile for opaque Lattice envelopes

Status: accepted candidate profile; interoperability gates remain open
Date: 2026-09-24
Requirements: NET-009–011

## Context and threat

Relays can extend reachability but may drop, replay, reorder, retain, correlate, or censor ciphertext. A relay publish response is not a recipient receipt. NIP-01 provides signed events, tag filters, and subscription flow; NIP-40 expiration is optional and does not guarantee deletion. Lattice uses Ed25519 device identities and must not publish them as relay identities. A general file store, Nostr identity service, global relay, or public Space directory is out of scope.

## Options considered

1. Publish raw Lattice event bytes under a stable Space/group tag. This exposes a public identifier and stable membership correlation.
2. Reuse the Lattice device signing key as the Nostr event key. This directly links relay activity to a long-term Lattice identity.
3. Wrap bounded, already-protected Lattice envelopes in NIP-01 custom events using a separate relay-only key and an opaque per-generation mailbox token. The token remains linkable within one generation, but does not expose the Space ID or device fingerprint.

## Decision and exact scope

Choose option 3 as the accepted local candidate in [`13-relay.md`](../../protocol/specs/13-relay.md):

- Use NIP-01 kind `39001`, an addressable kind. Include `d = lowercase-hex(envelope_id)` so one envelope occupies one address; distinct envelopes are never replacements.
- Sign with a separately generated, platform-protected secp256k1/Schnorr relay key. Never reuse or expose the Lattice Ed25519 device key as the Nostr key.
- Use exactly one `t` retrieval tag combining profile name and a random per-generation 32-byte mailbox token; send it only inside an MLS-protected control message. Include NIP-40 `expiration` equal to the inner envelope expiry. Do not publish `p`, `e`, `a`, Space IDs, group references, channel IDs, or author fingerprints.
- Base64url-encode the exact canonical `EnvelopeV1` in NIP-01 `content`; accept at most 45,000 envelope bytes and 65,536 bytes for the serialized event JSON. Bound the WebSocket command containing the event to 66,048 bytes. Reject file chunks and voice media.
- Require a NIP-11 relay information document advertising NIP-40 and `max_message_length >= 66,048` bytes before publishing. If unsupported, unavailable, disabled, or rejecting the kind/size, report that relay path unavailable and preserve the local event and other routes. Never fall back to public note kinds.
- Bound retrieval to 256 events and 16 MiB per query over at most the preceding 30 days. Relay pagination and empty results are hints only; authenticated peer sync repairs missing history.
- A NIP-01 `OK` is relay acceptance only. Delivery, group authorization, and application acceptance remain separate state.

NIP-40 expiry is a client-retention rule, not secure deletion. Relays learn IP address, relay public key, stable per-generation tag, timing, lengths, and subscription relationships. The token leaks within-generation correlation by design. A fresh recovery generation gets a fresh token; this does not erase metadata already learned by relays.

## Consequences and migration

This choice permits an optional mailbox without exposing the Space identifier or binding relay traffic to the device's signing key. Relay discovery/setup and mailbox distribution need explicit storage, protected key handling, and platform/UI workflows. A relay lacking NIP-11/NIP-40 support, sufficient message-size limits, or custom-kind support is not compatible with this profile; the user can select another relay or use direct paths. The profile does not promise relay availability, deletion, anonymity, anti-censorship, or complete backfill.

No existing events are rewritten. The candidate is not an interoperability release: use no public relay until independent NIP-01/NIP-11/NIP-40 and two-relay conformance tests pass.

## Required vectors, tests, and rollback

Require NIP-01 event-ID/Schnorr vectors, malformed JSON and duplicate-key negatives, exact `d`/`t`/expiration tags, NIP-40 support gating, expiry and 45,000/65,536-byte boundaries, duplicate and reorder handling, same Lattice event under distinct envelopes, custom-kind rejection without event loss, and two independent compatible relays. Until these pass, the adapter remains disabled. Rollback disables relay use; it does not change the event log or fall back to another kind.

## References

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md)
- [NIP-40](https://github.com/nostr-protocol/nips/blob/master/40.md)
- [Networking requirements](../features/networking.md)
- [Protocol relay candidate](../../protocol/specs/13-relay.md)
- [Lattice security model](../security/SECURITY_MODEL.md)
