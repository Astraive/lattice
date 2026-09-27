# Candidate 1 — delivery envelope

**Status:** candidate, not a frozen interoperability contract. This profile defines opaque delivery accounting around the exact signed event object in [`05-events.md`](05-events.md). It does not grant membership, authorization, decryption, or delivery.

## Envelope encoding and bounds

An envelope is one canonical CBOR integer-key map with exactly keys `0..=8`, using [`02-encoding.md`](02-encoding.md):

| Key | Value | Rule |
| ---: | --- | --- |
| 0 | unsigned version | exactly `1` |
| 1 | byte string | 32-byte envelope ID |
| 2 | byte string | 32-byte Lattice event ID |
| 3 | unsigned integer | delivery class: `0` security dependency, `1` interactive text, `2` deferred history, `3` file chunk; voice media is prohibited |
| 4 | unsigned integer | envelope creation time in Unix seconds; positive |
| 5 | unsigned integer | expiry Unix time in seconds; strictly after key `4` and no more than 30 days later |
| 6 | unsigned integer | remaining hop budget, `0..=64` |
| 7 | unsigned integer | remaining copy budget, `0..=64` |
| 8 | byte string | exact canonical signed event object from `05-events.md`, maximum 1 MiB |

The complete encoded map is at most 1 MiB. Reject unknown/missing fields, wrong widths/types, unknown classes, invalid creation/expiry order, excess budgets, non-canonical bytes, and any mismatch between key `2` and the embedded event ID. A receiver MUST bound the complete object before decoding or allocating its payload.

The envelope ID is:

```text
SHA-256(UTF8("lattice:envelope:v1") || 0x00 || canonical_cbor(map_without_key_1))

Key `1` is omitted from the hash preimage; keys `0` and `2..=8` are encoded in canonical order. The event ID is unchanged across envelopes. A re-envelope, expiry refresh, route-class change, or changed hop/copy budget therefore creates a new envelope ID while retaining the exact signed event bytes and event ID. An envelope ID authenticates no field; validate every decoded field and the inner signed event independently.

## Forwarding and deduplication

A forwarder decrements hop budget before forwarding. It MUST NOT forward when the remaining budget is zero. A courier transferring a copy decrements the sender's copy budget and MUST ensure a disconnect cannot leave both peers with the full pre-transfer budget. The relay profile does not consume courier copy budget; relays are independent remote stores, not trusted couriers.

## Pinned TCP courier transfer v1

Courier transfer v1 uses a separate Noise XX prologue `lattice:courier-transfer:noise-xx:v1\0` and identity-proof domain `lattice:courier-identity-proof:v1\0`. Both endpoints MUST bind the Noise transcript to the exact full-fingerprint identity pin before transferring payload bytes. A direct-sync session is not interchangeable with a courier session.

The encrypted application stream carries one envelope per authenticated connection. Every frame begins with `LCOR || 0x01 || kind`; all multi-byte integers are unsigned big-endian. Kind `1` is a ten-byte start frame followed by a four-byte complete envelope length. Kind `2` is a chunk frame followed by a four-byte zero-based chunk index and 1–60,000 data bytes. Chunks MUST arrive exactly once, in increasing order, and their aggregate size MUST equal the declared length, which MUST be in `1..=1,048,576`. The receiver bounds allocation by that length before reassembly and validates canonical envelope bytes, signature, expiry, and remaining hop budget before queue admission. Kind `3` is a six-byte acceptance frame; kind `4` is a six-byte generic rejection. Both acknowledgement kinds use the same `LCOR || 0x01 || kind` prefix. A kind-3 acknowledgement means only that the authenticated next peer committed the opaque envelope to its local enabled queue.

Before transmitting the start frame, the sender MUST atomically consume the source queue row and decrement both remaining copy and hop budgets in the transferred envelope. It MUST NOT restore the source row after any later transport failure, including an absent acknowledgement; the copy may be lost, but its budget cannot be duplicated. The sender MUST authenticate the pinned peer before consumption and MUST reject a stored item whose local metadata disagrees with its canonical envelope. The receiver MUST reject zero remaining hop budget for this queue-transfer profile and enforce existing local duplicate, expiry, item-count, and byte quotas before acknowledging.

Because this profile stores envelopes for future forwarding rather than final application delivery, the sender MUST refuse a queue item with remaining hop budget `0` or `1`; decrementing the value `1` would produce a zero-budget envelope that this receiver profile cannot retain.

This profile has no retry, resume, simultaneous bidirectional transfer, transport upgrade, or recipient-delivery receipt. A new send requires a new session and a distinct queued copy. TCP endpoints and local quota identifiers are not protocol envelope IDs. Queue identifiers and per-peer quota keys are domain-separated local values and MUST NOT be treated as identities or authorization.

Keep bounded duplicate records for both envelope ID and event ID. The same envelope ID with different encoded bytes is malformed. Distinct envelope IDs with the same event ID are expected after re-enveloping; the event log deduplicates by signed event ID. The same author/sequence paired with conflicting event IDs remains an equivocation, not a duplicate.

Expire envelopes when local time reaches key `5`; key `4` and `5` are retention bounds, not authorization evidence. Receivers reject an envelope whose expiry is not after creation, exceeds 30 days, or has already passed. The sender outbox retains its own bounded retry state and does not mark destination delivery on a local enqueue, a relay publish response, or a courier deposit. A remote receipt is scoped to the named hop/destination and is not a proof that a human read content.

File chunks use class `3` only when the selected path explicitly supports bulk transfer and its own quotas. Nostr MUST reject class `3` in candidate 1. Voice media is never represented as a durable envelope.
