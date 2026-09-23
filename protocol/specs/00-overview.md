# Lattice protocol candidate 1 — overview

**Status:** candidate, not an interoperable release. The source of truth remains [`docs/protocol/PROTOCOL.md`](../../docs/protocol/PROTOCOL.md); this document records the executable candidate currently implemented in Rust. Do not advertise wire compatibility until independent implementations pass published vectors and the security gates.

## Scope

Candidate 1 specifies strict canonical CBOR value encoding, SHA-256 event-ID derivation, and the public device bundle byte format. Signed application event framing, MLS lifecycle and storage recovery, link handshakes, forwarding envelopes, capability negotiation, and relay/file/voice wire semantics are not yet frozen. An encoded value is not an accepted event. A signature is not authorization, membership, encryption, delivery, or identity verification by a human.

## Version and failure rules

The CBOR candidate has profile version 1. Objects that require semantics outside this document must reject unknown mandatory versions/features. Parsers MUST reject malformed, truncated, non-canonical, or over-limit inputs before unbounded allocation. There is no plaintext or downgrade fallback. Historical signed bytes are retained as received and MUST NOT be silently recoded.

## Candidate bounds

| Object | Bound |
| --- | ---: |
| One encoded event preimage | 1 MiB |
| One CBOR byte or text string | 256 KiB |
| Items in one array or map | 4,096 |
| Nested array/map levels | 32 |
| Event parent list | 64 |

The per-item limits are implemented in `crates/lattice-protocol`; they are not a whole-database, aggregate-queue, BLE-frame, file, or MLS limit. Local storage and transport impose their own additional independent quotas.

## Implemented components

- [`02-encoding.md`](02-encoding.md): supported value subset, canonical rules and hash preimage.
- [`03-identity.md`](03-identity.md): candidate public key bundle and fingerprint.

Other entries in the planned [`PROTOCOL.md` document map](../../docs/protocol/PROTOCOL.md#wire-document-decomposition-and-freeze-order) remain unimplemented. See `docs/TODO.md` and `docs/quality/TEST_PLAN.md` for evidence and release gates.
