# Lattice protocol candidate 1 — overview

**Status:** candidate, not an interoperable release. This overview distinguishes the implemented Rust subset from candidate schemas that have not passed independent interoperability and security gates. Do not advertise wire compatibility until those gates pass.

## Scope

The executable Rust subset covers strict canonical CBOR values, SHA-256 event-ID derivation, local identity bundles and signed events, candidate Space policy reduction and application authorization, bounded delivery-envelope codecs, strict NIP-01 event signing/verification and NIP-11 capability parsing, and encrypted durable OpenMLS provider records through the core. Candidate documents define membership, message projection, relay networking, and physical-link behavior that are not implemented end-to-end or interoperable. Link handshakes, BLE, file and voice wire semantics remain open. An encoded value is not an accepted event. A signature is not authorization, membership, encryption, delivery, or human identity verification.

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

## Candidate documents and implementation boundary

- [`02-encoding.md`](02-encoding.md) and [`03-identity.md`](03-identity.md): implemented candidate primitives with shared vectors.
- [`05-events.md`](05-events.md): signed-event candidate; the TypeScript inspector verifies shape, event ID, identity fingerprint, and signature only.
- [`06-spaces.md`](06-spaces.md) and [`07-permissions.md`](07-permissions.md): exact candidate payload/permission schemas; Rust has a candidate policy reducer and authorization gate, while MLS membership proof, durable reducer restore, and message projection remain incomplete.
- [`08-mls.md`](08-mls.md): MLS event binding and encrypted durable provider boundary; credential trust, causal membership validation, and durable conflict recovery remain incomplete.
- [`09-envelope.md`](09-envelope.md) and [`13-relay.md`](13-relay.md): candidate envelope codec, strict NIP-01 signed-event codec, and bounded NIP-11 capability parser; no production relay adapter or interoperability claim.
- [`10-ble.md`](10-ble.md): experimental BLE label plus candidate service/discovery and first-contact identity binding; framing, flow-control, and interoperability remain open.

Other entries in the planned [`PROTOCOL.md` document map](../../docs/protocol/PROTOCOL.md#wire-document-decomposition-and-freeze-order) remain unimplemented. See `docs/TODO.md` and `docs/quality/TEST_PLAN.md` for evidence and release gates.
