# Candidate 1 — Nostr opaque-envelope relay profile

**Status:** accepted local profile candidate; not a Nostr interoperability or availability claim. The profile is optional. Direct delivery and local state continue when no relay is configured or a relay rejects an event. Envelope bytes are defined in [`09-envelope.md`](09-envelope.md); signed inner events are defined in [`05-events.md`](05-events.md).

## Nostr event form

Use NIP-01 addressable event kind `39001` for one Lattice delivery envelope. Its required `d` tag is the lowercase-hex envelope ID, which gives each distinct envelope a distinct address; the same envelope can be republished idempotently. Do not use public note kind, profile kind, or NIP-17 semantics. The NIP-01 event object has exactly its standard fields `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, and `sig`; reject duplicate JSON keys, unknown outer fields, wrong types, invalid hex, and malformed NIP-01 serialization before processing content.

The profile requires exactly these tags, in this order:

```json
[["d", "<64 lowercase hex envelope ID>"],
 ["t", "lattice1.<64 lowercase hex mailbox bytes>"],
 ["expiration", "<unsigned decimal Unix seconds>"]]
```

The mailbox token is a fresh random 32-byte value for each Space MLS generation. Authorized members obtain it only in an MLS-protected control application message after admission; it is not the Space ID, group reference, author fingerprint, or MLS group secret. Keep it in protected local storage. A recovery generation creates a new token. A token is stable within its generation and therefore lets a relay correlate envelopes for that generation; this profile does not claim unlinkability or anonymity.

NIP-01 filtering uses one exact `#t` value, e.g. `{"kinds":[39001],"#t":["lattice1.<token>"],"since":<unix-seconds>,"limit":256}`. The single tag combines protocol marker and mailbox token so the filter does not OR a public protocol-only tag with the private route value. The `d` tag MUST equal the decoded envelope ID. No `p`, `e`, `a`, Space ID, group reference, author fingerprint, or channel tag is emitted.

The event `pubkey` is an x-only secp256k1/Schnorr relay-publishing key generated independently of the Lattice device signing key and protected by the platform key protector. It is not reused across identities or exposed inside the signed Lattice event. No NIP-05 identifier or profile event is published by this profile. Rotation of this relay key does not change the Lattice event ID or the mailbox token.

## Content and exact cross-layer checks

`content` is the unpadded base64url encoding of exactly one canonical `EnvelopeV1` from `09-envelope.md`. The envelope payload MUST already be protected for its intended Lattice recipients; the Nostr layer adds no confidentiality. The NIP-01 `created_at` MUST equal envelope key `4`; the single `expiration` tag MUST equal envelope key `5`. Reject any mismatch, past expiry, expiry more than 30 days after creation, non-canonical base64url, decoded payload above 45,000 bytes, `d` tag not equal to the envelope ID, or envelope class `3` (file chunk). Voice media is never published.

The recipient MUST independently validate the NIP-01 event ID and Schnorr signature, the relay profile kind and tags, the expiry, envelope canonical encoding/ID, and the inner signed event ID/signature. The outer Nostr author proves only possession of a relay-publishing key. Neither Nostr signature nor relay response establishes a Lattice identity, group membership, permission, destination receipt, or message read.

Maximum decoded envelope content is 45,000 bytes; its unpadded base64url content is at most 60,000 ASCII bytes. The complete serialized NIP-01 JSON event is at most 65,536 UTF-8 bytes. Reject oversize data before base64 decoding or unbounded JSON allocation. The profile has no fragmentation path through Nostr. If an envelope exceeds these limits, report this relay as ineligible for that envelope and keep other permitted paths available; do not truncate, split, or change its inner event.

## Expiration, duplicates, and bounded retrieval

Before publishing, fetch the relay's NIP-11 information document using `Accept: application/nostr+json`; require `supported_nips` to include `40` and integer `max_message_length` to be at least 66,048 bytes. Missing, malformed, or insufficient capability information means this relay is unavailable for Lattice envelopes. Do not send an expiration event to a relay that does not advertise NIP-40. Relays may still ignore or delay the hint; receivers MUST enforce expiry locally. Expiry is not proof that any relay deleted a copy. Maximum residence is 30 days from `created_at`; receivers ignore later copies even if a relay returns them.

Publish the same signed outer Nostr event independently to each configured relay. Treat a successful NIP-01 `OK` response as acceptance by that relay only. Record per-relay status; do not mark the Lattice outbox delivered. Re-envelope only by creating a new envelope ID and a new outer Nostr event; retain the exact inner signed event bytes and event ID. Deduplicate relay responses by Nostr event ID, then envelope ID, then inner Lattice event ID. A matching ID with different decoded bytes is an integrity conflict and is not applied.

A retrieval request MUST specify the exact mailbox tag, kind `39001`, an explicit lower `since` bound no earlier than `now - 30 days`, and `limit` no greater than 256. Accept at most 256 events and 16 MiB total response bytes per query. Stop reading when either bound is reached and resume with a bounded request. Store a local cursor per relay and mailbox, but treat timestamps/cursors and relay history as hints: NIP-01 timestamp pagination cannot prove that no event was omitted. Query each configured relay independently, deduplicate results, then use authenticated peer sync to reconcile gaps. Never claim relay backfill is complete solely because a relay reached an empty response.

Reject malformed, unsupported, expired, oversize, or non-Lattice-kind events without blocking other relay events. Keep relay failure/status separate from MLS, policy, and destination-delivery state. A relay outage, rate limit, custom-kind rejection, or user disablement MUST NOT invalidate local events or prevent direct BLE/LAN routes.

## Privacy and implementation boundary

A relay learns the client IP, relay-publishing public key, the stable mailbox tag, timestamps, event sizes, publish/subscription behavior, relay set, and whether clients share a generation tag. The encrypted envelope hides event bodies from the relay but does not hide these metadata. Users can configure multiple relays or none; no global relay is required. A relay is an untrusted byte store, cannot mint authority, cannot force event acceptance, and may drop, replay, reorder, correlate, retain, or censor ciphertext.

Candidate conformance requires byte-exact NIP-01 event-ID/signature vectors, valid and invalid tag/expiry/content vectors, same inner event under distinct envelopes, duplicate and out-of-order relay delivery, event/aggregate bounds, relay rejection without local event loss, and two independent compatible relay implementations. Until the vectors and two-relay exercise exist, ship no interoperation claim.
