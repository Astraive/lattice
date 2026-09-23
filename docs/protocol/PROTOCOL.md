# Protocol profile and interoperability boundaries

**Status:** draft. `spec.md` contains longer examples; stable v1 wire bytes are not frozen. A bounded executable candidate currently exists for canonical CBOR, event-ID hashing, and the local identity bundle; see [`protocol/specs/00-overview.md`](../../protocol/specs/00-overview.md) and its vector file. Those candidate bytes are not an interoperability claim. Do not ship independent client implementations from this summary alone.

## Current executable candidate

[`00-overview.md`](../../protocol/specs/00-overview.md), [`02-encoding.md`](../../protocol/specs/02-encoding.md), [`03-identity.md`](../../protocol/specs/03-identity.md), and [`canonical-cbor.json`](../../protocol/vectors/canonical-cbor.json) track the Rust subset implemented so far. Signed event framing, authorization, MLS, sessions, envelopes, relay, files-on-wire and voice signaling remain separate profile work; do not infer acceptance from the CBOR decoder.

## Layer map

| Layer | Object | Stable across paths? | Validation |
| --- | --- | --- | --- |
| Identity | Canonical public bundle, fingerprint | Yes | Signature/key binding and human verification |
| Application | Signed/MLS-protected event with causal parents | Yes | Canonical hash, auth, parent, epoch and policy |
| Delivery | Envelope ID, TTL, copy budget, destination hint | May change on re-envelope | Bound, expiry, replay and class checks |
| Link | BLE fragments, LAN frames, WebSocket relay events | No | Link session and framing checks |
| Media | Voice signaling events vs WebRTC media | Session-scoped | Space permission, ICE/DTLS-SRTP checks |

### Candidate event shape

```text
EventV1 { version, space_id?, channel_id?, author_device_id,
  author_seq, lamport, wall_time_hint, parents[], kind, flags,
  protected_body, authentication_context }
event_id = SHA-256("lattice:event:v1" || canonical_cbor(event_preimage))
```

The signed preimage/ID/signature order must be pinned before v1. An `author_seq` rollback or duplicate `(author,seq)` with distinct bytes is a validation error. Wall time cannot grant authority. Envelope ID may change after expiry or delivery-class change; event ID must not. An envelope does not prove a sender is authorized. Versioned CBOR profile uses integer keys, minimal encodings, duplicate-key rejection, no indefinite structures in hashed values, strict bounds and public vectors. [CBOR RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) is a foundation, not Lattice's complete profile.

## Identity and invitation

Identity bundle candidate fields: Ed25519 verify key, X25519 DH key, version, creation hint and extensions; fingerprint is a domain-separated hash of exact canonical public bytes. Profile/name are separate signed events. Invite carries random Space ID, genesis hash, inviter proof, expiry, nonce/use policy, join policy and untrusted BLE/LAN/relay rendezvous hints. A human-verified contact pins full fingerprint. KeyPackage and Welcome delivery are separate authenticated steps.

## Transport handshakes and BLE

Nearby paths perform a reviewed Noise handshake with explicit pattern, prologue, transcript identity/version/capability/token binding and replay window. Advertising carries a generic service UUID and rotating app token, never static key or Space name. BLE GATT `control`, `rx`, `tx`, `capabilities`, and `upgrade` characteristics are candidates. Fragment after envelope encryption; per-peer aggregate reassembly bytes, object count, deadline, fragment count and pacing credits are mandatory. Adapter “queued to OS” is not remote receipt.

## Sync state

Per authorized scope, exchange `{author_id, contiguous_seq, gap_digest}`, recent-event summary, snapshot floor and capabilities. Request missing range/dependencies in bounded batches; authenticate all events before projection. MLS proposals/Commits and policy dependencies are requested before ciphertext needing those epochs. A Bloom/Golomb-type recent summary may have false positives, so a later exact reconciliation path must repair gaps. Never reveal unrelated Space membership merely by sending every known scope.

## Membership and conflict

An MLS group has a linear epoch history. [MLS architecture §5.2](https://www.rfc-editor.org/rfc/rfc9750#section-5.2) describes peer delivery and simultaneous Commit strategies. ADR-001 must specify deterministic acceptance/wait period, losing-branch messages, Welcome handling, fork-state retention/deletion, and explicit recovery. ADR-002 fixes channel confidentiality semantics. Generic Lamport sorting is only for presentation. Until those decisions are implemented, secure concurrent-admin operation is not supported.

## Relay and files

Nostr is an optional opaque-envelope carrier following a versioned profile: event kind, outer key policy, retrieval tags, expiration hint, size/duplicate handling, relay set, and backfill window. [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) defines basic events/subscriptions, not Lattice's group authorization. Never claim NIP-17 or Bitchat interoperability from similar wrapping. File manifests/chunks have independent hashes and transfer quotas; general event relays are not assumed to store file payloads.

## Compatibility, error classes and vectors

Major version mismatch or unknown mandatory feature fails closed; compatible optional fields need explicit hashed-byte retention semantics. Minimum vectors: identity fingerprint; canonical message/admin event and ID; distinct envelope IDs carrying same event; malformed duplicate map key; author-sequence collision; signed invite; Noise transcript; MLS add/remove/competing Commit; fragment reassembly; sync gap; file chunk; relay wrap/unwrap; voice signaling authorization. Stable error classes: `PROTO_UNSUPPORTED`, `PROTO_MALFORMED`, `CRYPTO_AUTH_FAILED`, `CRYPTO_EPOCH_MISSING`, `POLICY_DENIED`, `POLICY_CONFLICT`, `ROUTE_UNAVAILABLE`, `ROUTE_EXPIRED`, `TRANSPORT_PERMISSION`, `TRANSPORT_UNSUPPORTED`, `STORAGE_FULL`, `STORAGE_CORRUPT`, `FILE_HASH_MISMATCH`, `VOICE_ICE_FAILED`, `VOICE_TURN_REQUIRED`.

References: [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420), [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750), [Noise](https://noiseprotocol.org/noise.html), [DTN RFC 4838](https://www.rfc-editor.org/rfc/rfc4838), [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md), and [architecture.md](../architecture.md).

## Wire document decomposition and freeze order

| Versioned document | Must fix before a stable implementation |
| --- | --- |
| `00-overview` | Version/capability matrix, normative language and scopes |
| `01-identifiers`, `02-encoding` | Field widths, byte order/CBOR profile, domain strings, canonical hashes |
| `03-identity`, `04-sessions` | Identity bundle, credential verification, Noise pattern/prologue/replay |
| `05-events`, `06-spaces`, `07-permissions` | Event kinds, causal references, authorization context, role bit registry |
| `08-mls` | Ciphersuite, KeyPackages, Welcome, Commit ordering/fork profile, exporter labels |
| `09-envelope`, `10-ble` | Delivery classes, hop/copy budget, fragmentation, GATT UUIDs, flow control |
| `11-sync`, `12-routing` | Gap summaries, snapshots, path metrics, retry and courier rules |
| `13-relay`, `14-files`, `15-voice` | Mailbox profile, manifest/chunks, room incarnation and signaling |
| `16-versioning` | Required/optional feature bits, downgrade prevention and migration |

Each document defines maxima for strings, arrays, event body, parent list, fragments, pending dependencies and queue bytes, and contains byte-exact positive/negative vectors. A field marked “future” in the integrated spec does not silently become required for v1. No implementer may derive a byte limit from a UI placeholder or radio MTU alone.

## Validation pipeline with failure classes

```mermaid
flowchart TD
    B["Received bounded bytes"] --> F["Frame and session check"]
    F --> C["Canonical decode and hash"]
    C --> A["Author and MLS proof"]
    A --> P["Parents and policy"]
    P --> S["Atomic storage and projection"]
```

If frame/canonical format is malformed, return `PROTO_MALFORMED` before large allocation. A valid ciphertext with an absent epoch is `CRYPTO_EPOCH_MISSING` and goes into a bounded pending queue, not the projection. Valid signature but absent permission yields `POLICY_DENIED`. Conflicting valid branches yield `POLICY_CONFLICT` under ADR-001. All accepted event IDs are idempotent, but a repeated author sequence with a different event ID is a protocol-security anomaly requiring quarantine/diagnostic evidence. Link session proof alone never proves an event body is acceptable to a Space.

## Space sync exchange

1. Authenticate a peer, negotiate protocol/capabilities and minimize disclosed Space intersection; refuse incompatible required features.
2. Exchange scope-specific summaries with contiguous per-author sequence, sparse gap digests and snapshot horizon.
3. Compute missing ranges and explicit dependency IDs; schedule MLS/policy before ordinary text, then files. Scope each request to permissions.
4. Choose a path by total delta and policy: BLE for compact summaries/control, eligible IP for bulk; cap each batch and memory footprint.
5. Verify each immutable object; perform atomic insert/projection; return summary/receipt. A failed batch object does not invalidate earlier accepted events but cannot leave a half-projected object.
6. Continue until exact ranges reconcile or report a retention/partition gap. A probabilistic recent-item filter never proves historical completeness.

## Courier and relay accounting

An envelope records delivery class, expiry, hop limit and copy budget; duplicate suppression uses envelope and event IDs at different layers. Binary spray may split budget between carriers, but the exact atomic transfer/ACK protocol must prevent both peers from each retaining the full budget after a disconnect. Retried author envelopes can be rewrapped after expiry without altering event ID. Public relay events are accepted only when inner Lattice content and its associated membership context validate. Outer Nostr key is a routing/publishing identity, not Space membership. A public relay cannot promise deletion, so security must not depend on expiration hints.

## Files and media boundaries

File manifests are authenticated event payloads; chunk bytes are verified against hashes before becoming available. Do not route large chunks through ordinary Nostr events by default. Voice signaling events must be associated with a current room incarnation and authorized member, while SDP/ICE and network candidates may leak IP/topology metadata to call participants; data-routing encryption does not make a call anonymous. Media uses WebRTC security and never inherits courier retention.
