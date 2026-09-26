# ADR-005: Experimental BLE discovery, identity binding, and framing

Status: accepted experimental candidate; security, implementation, and interoperability gates remain open
Date: 2026-09-26
Requirements: NET-001, NET-002, MOB-003

## Context and threat

BLE can provide a nearby, low-volume path, but advertising is observable and Android controls radio-address privacy, background execution, and permission behavior. A rotating application token can bound one correlation handle's lifetime; it cannot promise anonymity or unlinkability. GATT connection success and local write callbacks do not authenticate a Lattice identity or prove application delivery.

The existing Android scanner uses a pre-profile service UUID, and the standalone `BleFrameCodec` is not connected to an authenticated GATT path. Neither is evidence of exp0 compatibility. The prototype needs concrete semantics for first contact, bounded framing, loss, reconnect, and ownership, without presenting experimental values as a frozen v1 wire contract.

## Options considered

1. Advertise a stable device or Space identifier and trust the GATT peer based on discovery. This is easy to route but leaks a persistent identifier and provides no authenticated identity binding.
2. Keep the pre-profile scan-only behavior and let each adapter invent framing, identity, and retry semantics. This avoids a protocol decision but creates incompatible, unsafe callsites and no meaningful NET-002 contract.
3. Define a labeled experimental profile with a rotating random discovery token, Noise XX transport, transcript-bound Ed25519 identity proofs, strict bounded envelope frames, and explicit retry ownership. This is implementable while retaining an explicit migration boundary and no privacy or interoperability overclaim.

## Decision and exact scope

Choose option 3 for `lattice-ble-exp0`, as specified in [`10-ble.md`](../../protocol/specs/10-ble.md). This is an accepted development candidate only; it is not `lattice-ble-v1`, a stable compatibility promise, or authorization to enable a production BLE route.

- Use service UUID `1c9a0000-7d31-4f6a-9b43-4c4154544943`, profile discriminator `00`, and exactly the legacy 31-byte advertisement defined by the profile. A fresh 72-bit CSPRNG token rotates every 900 monotonic seconds. Token failure stops advertising. Tokens and sightings remain memory-only; no stable identity, Space metadata, address-derived identifier, or local name enters the application advertisement.
- Use Noise `Noise_XX_25519_ChaChaPoly_SHA256` on `control`, with the exact 61-byte role-ordered prologue. Noise static keys are session-only. Post-handshake Ed25519 proofs bind both exact identity bundles, the observed responder token, capabilities, and transcript hash. Pinned full fingerprints must match; first contact requires an out-of-band comparison and explicit full-fingerprint pin before sensitive scope discovery. The six-byte comparison string is a human check, not distance proof.
- Require ATT MTU at least 154 before sending identity or application data; request 247. The minimum is `135` proof bytes + `16` Noise tag + `3` ATT opcode/handle bytes. Define frame value capacity as `min(512, ATT_MTU - 3)`, use a 24-byte big-endian frame header, at most 112,640 envelope bytes and 1,024 frames, one incomplete inbound assembly and 112,640 buffered bytes per direction, a four-frame credit window, and a fixed 30,000 ms assembly lifetime.
- Put `LBTS`, `LBWC`, and `LBFA` control records inside complete Noise transport messages. Transfer IDs are random non-zero `u64` values per sender/session, increment by one, and never wrap within a session. Grants count unique accepted fragments; conflicting duplicates or malformed values close the link. No partial-fragment resume: after link closure, the durable outbox retries the unchanged envelope after fresh identity-bound authentication. `LBFA` reports only bounded transport-ingress handoff, not Core validation, durable acceptance, Space authorization, or destination delivery.
- Keep ownership separate: Core/storage owns authored events and durable outbox; Router selects paths and retry/backoff; Android lifecycle policy controls radio eligibility; GATT adapter owns platform handles and serialized operations; authenticated session owns Noise, controls, and bounded assembly. A GATT callback or local queue result is never a delivery receipt.

These constants are experimental candidate values. A change incompatible with exp0 requires an explicit new experimental label; `lattice-ble-v1` remains reserved until the release gates pass.

## Consequences and migration

The profile gives adapters one explicit integration boundary and keeps signed event bytes, event IDs, authorization, and durable outbox state independent of BLE. Existing pre-profile scanning and the standalone codec cannot be silently treated as exp0. A failed handshake, malformed record, MTU failure, timeout, permission loss, process stop, or Bluetooth shutdown closes the session and discards connection-local transfer state; it does not delete or rewrite the durable envelope.

Observers may still correlate radio behavior through address handling, timing, signal strength, platform behavior, physical observation, or other metadata. No claim is made about anonymity, unlinkability, continuous discovery, throughput, battery use, cross-device interoperability, or delivery from the current design. `lattice-ble-exp0` is suitable only for isolated development/test builds until its gates pass.

## Required vectors, tests, and rollback

[`ble-exp0.json`](../../protocol/vectors/ble-exp0.json) records candidate advertisement, UUID byte order, prologue, deterministic Ed25519 identity-proof/confirmation inputs and records, comparison string, start/credit/completion controls, MTU boundaries, and a five-frame boundary example. Public fixture seeds are test-only. The vector intentionally does not claim Noise transport ciphertext or independent implementation conformance.

Before any stable-v1 or production interoperability claim, require negative and malformed handshake/advertisement/control/frame cases; replay and token-rotation tests; a reproducible Noise XX transport vector; MTU and envelope/frame/credit/assembly-time boundaries; loss, reconnect, duplicate, permission, Bluetooth, and process-lifecycle scenarios; clean-room independent implementations; passive captures across token rotations; and physical two- and three-device acceptance. Fail closed on every invalid or unauthenticated path. Rollback disables exp0 advertising/connection use; it does not fall back to pre-profile behavior or rewrite the event log.

## References

- [BLE experimental profile](../../protocol/specs/10-ble.md)
- [BLE candidate byte vectors](../../protocol/vectors/ble-exp0.json)
- [Device identity bundle](../../protocol/specs/03-identity.md)
- [Networking requirements and implementation boundary](../features/networking.md)
- [Security model](../security/SECURITY_MODEL.md)
- [GitHub issue #8 / Linear AST-7](https://github.com/Astraive/lattice/issues/8)
