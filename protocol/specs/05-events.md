# Candidate 1 — signed immutable event framing

**Status:** implemented-in-progress; must match `crates/lattice-events` and vectors before it is considered specified. Not an interoperability claim. The event body is opaque protected bytes; no plaintext encryption/decryption or Space policy authorization is performed by the event-signature layer.

## Candidate canonical preimage

A candidate event preimage is one canonical CBOR integer-key map with exactly keys `0..=11`:

| Key | Value | Requirement |
| ---: | --- | --- |
| 0 | unsigned version | exactly `1` |
| 1 | byte string | random 16-byte Space ID |
| 2 | null or byte string | absent or 16-byte channel ID |
| 3 | byte string | 32-byte author identity-bundle fingerprint |
| 4 | unsigned integer | positive per-device author sequence |
| 5 | unsigned integer | Lamport display/causal-order hint; not permission evidence |
| 6 | unsigned integer | wall-time hint; never grants authority |
| 7 | array of byte strings | at most 64 unique 32-byte parent event IDs, bytewise strictly increasing |
| 8 | unsigned integer | known candidate event kind; unknown values fail closed |
| 9 | byte string | nonempty bounded protected-body ciphertext supplied by an MLS/application layer |
| 10 | byte string | 32-byte MLS group reference derived as specified in [`08-mls.md`](08-mls.md) |
| 11 | unsigned integer | MLS epoch number |

The complete map encoding is the signed preimage. A zero sequence, duplicate/unsorted parents, unsupported kind, unexpected key/length/type, or any over-limit value is rejected. Event IDs use the `lattice:event:v1` domain-separated hash over these exact canonical bytes. Parent order canonicalization does not change event identity: producers sort before signing, consumers reject unsorted arrays.

## Candidate event kinds

| Value | Meaning | Additional limitations |
| ---: | --- | --- |
| 1 | Message | Body is opaque; authorization/decryption external |
| 2 | Edit | Target causality/policy external |
| 3 | Tombstone | Does not erase retained copies |
| 4 | Reaction | Element semantics/reducer external |
| 5 | Pin | Permission/reducer external |
| 6 | Membership | Not proof of valid MLS transition or role authority |
| 7 | MLS control | MLS engine validates its TLS message separately |
| 8 | File manifest | File parser/hash verification and authorization external |
| 9 | Voice signal | Current incarnation and voice permission external |

## Candidate signed outer object

One canonical CBOR integer-key map contains exactly:

| Key | Value |
| ---: | --- |
| 0 | unsigned version, exactly `1` |
| 1 | byte string with exact original unsigned preimage bytes |
| 2 | 65-byte version-1 public identity bundle |
| 3 | 64-byte Ed25519 signature |

Signature bytes are Ed25519 over `UTF8("lattice:event-signature:v1") || 0x00 || exact_preimage_bytes`. The outer map signature field is excluded from the signed bytes. The candidate author field must equal the fingerprint derived from the embedded public bundle. Verify signature against its embedded public signing key. This proves only possession of that key; pinning/human verification, credential-to-member binding, MLS epoch validation, causal dependencies, event operation permission, body decryption, and storage transaction are required before acceptance/projection.

The validator returns a signature-only typed object and MUST NOT name it accepted, authorized, decrypted, delivered, or verified as a Space member. Retain exact outer and preimage bytes. Re-encode for transport by using the stored exact byte representation; never re-sign/re-encode history implicitly.

The deterministic signed-event vector (preimage, signature, outer bytes, and event ID) is `signed_event` in [`../vectors/canonical-cbor.json`](../vectors/canonical-cbor.json). Its test key is public test material only. A Rust conformance test verifies the exact retained bytes and signature.

## Sequence and equivocation

`(author fingerprint, author sequence)` is unique on an accepted device stream. An identical event-ID replay is idempotent. The same stream sequence paired with a different event ID is an equivocation anomaly and must be rejected/quarantined with bounded evidence; it does not overwrite the first event. Remote sequence gaps can be stored immutably and repaired with anti-entropy; local authors reserve/increment sequence atomically with event/outbox persistence.
