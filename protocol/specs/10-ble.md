# BLE experimental profile 0

**Profile label:** `lattice-ble-exp0`  
**Status:** experimental candidate; not an interoperable release.  
**Scope:** BLE discovery, authenticated link establishment, and link-layer envelope framing only. Event identity, authorization, MLS state, and envelope semantics remain transport-independent.

This document assigns the first migration label and defines candidate service, discovery, first-contact identity-binding, and bounded-framing values for BLE. [`ADR-005`](../../docs/decisions/ADR-005-ble-exp0-profile.md) records their experimental status, and [`ble-exp0.json`](../vectors/ble-exp0.json) supplies candidate byte vectors. These are development/test values only; negative/replay coverage, a reproducible Noise transport vector, independent implementation checks, security/privacy review, and Android device acceptance remain release gates. No independent implementation may infer stable wire compatibility from this experimental profile.

## Version domains and migration labels

`lattice-ble-exp0` is a BLE-profile label, not the global protocol major version, canonical-CBOR version, signed-event version, envelope version, or application event kind. A BLE profile change MUST NOT change an already-authenticated Lattice event ID or require recoding a signed event or envelope.

| Label | Meaning | Compatibility rule |
| --- | --- | --- |
| `pre-profile` | Existing prototype code or captures with no assigned BLE profile | No interoperability or security property is implied; do not infer compatibility from a source constant ending in `V1` or `VERSION = 1`. |
| `lattice-ble-exp0` | This experimental design line | Development/test use only; incompatible changes require a new explicit experimental label. No stable-wire or cross-client compatibility promise. |
| `lattice-ble-v1` | Reserved for the first frozen interoperable BLE profile | MUST NOT be used until service/advertisement/handshake/framing definitions, migration rules, byte vectors, independent implementation checks, and Android physical acceptance are complete. |

These labels are for specifications, build metadata, diagnostics, and test evidence. They are not advertisement contents and MUST NOT be treated as secret or as peer authentication. The on-air profile discriminator below is a separate one-byte field. Experimental builds MUST opt into `lattice-ble-exp0` explicitly and MUST identify it in local build metadata and diagnostics. Release builds MUST NOT silently accept an experimental peer as `lattice-ble-v1`.

A `pre-profile` implementation is not an implicit `lattice-ble-exp0` peer. Android's scan-only service UUID constant `LATTICE_SERVICE_UUID_V1` and the standalone `BleFrameCodec` header version do not establish an assigned profile: neither is connected to an authenticated GATT message path. Unknown required profile semantics and incompatible profile versions MUST fail closed before sensitive scope discovery or application data exchange. Authentication, framing, or version failure MUST NOT trigger automatic fallback to a weaker or older profile.

Migration from `lattice-ble-exp0` to `lattice-ble-v1` requires explicit profile selection and a newly established link session under the selected profile. It MUST NOT reinterpret an in-progress frame assembly or handshake transcript under another profile. Migration changes only the carrier session: signed event bytes, event IDs, envelope identity rules, durable outbox state, and authorization decisions remain unchanged. A failed or interrupted migration leaves the application object pending for ordinary retry; it does not create a replacement event.

## GATT service

The `lattice-ble-exp0` GATT service UUID is `1c9a0000-7d31-4f6a-9b43-4c4154544943`. The previous scan prototype UUID `1c9a0001-7d31-4f6a-9b43-4c4154544943` remains `pre-profile`; it MUST NOT be interpreted as this service. Characteristic UUIDs use the same base and the listed 16-bit allocation:

| Characteristic | UUID | Properties and direction | Meaning |
| --- | --- | --- | --- |
| `control` | `1c9a0002-7d31-4f6a-9b43-4c4154544943` | Central writes; server notifies | Link handshake and connection-local control records. Before session establishment, only handshake records are allowed. After establishment, control records are protected by the authenticated link session. |
| `rx` | `1c9a0003-7d31-4f6a-9b43-4c4154544943` | Central writes | Ingress for opaque, already-protected envelope fragments. Application payload is rejected until the link session is authenticated. |
| `tx` | `1c9a0004-7d31-4f6a-9b43-4c4154544943` | Server notifies | Egress for opaque, already-protected envelope fragments. The central enables the Client Characteristic Configuration Descriptor before notifications are sent. |
| `capabilities` | `1c9a0005-7d31-4f6a-9b43-4c4154544943` | Public read-only | Three-byte descriptor: profile discriminator `u8` (`0` for exp0), then optional-feature bits `u16` little-endian (`0` in exp0). It contains no identity, Space, device model, or address data. |
| `upgrade` | `1c9a0006-7d31-4f6a-9b43-4c4154544943` | Central writes; server notifies | Authenticated fast-path negotiation records only. Values are rejected before the link session is authenticated; exact record semantics remain owned by the path-upgrade protocol. |

The service and all five characteristics are present on an exp0 GATT server. Each device may act as central and peripheral subject to platform support. ATT operation success means only local-stack acceptance; it is not remote receipt. Application authentication and authorization MUST NOT rely on GATT permissions, characteristic UUIDs, or possession of a discovered token.

## Advertising and discovery token

Exp0 uses one legacy advertising payload no larger than 31 octets. It contains exactly a Flags AD structure and one Service Data - 128-bit UUID AD structure, in that order. It MUST NOT include a local name, manufacturer data, transmit-power hint, stable identity, Space/channel identifier, or content.

| AD structure | On-air bytes | Meaning |
| --- | --- | --- |
| Flags | `02 01 06` | General discoverable; BR/EDR unsupported. |
| Service Data - 128-bit UUID | Length `1b`, type `21`, service UUID `43 49 54 54 41 4c 43 9b 6a 4f 31 7d 00 00 9a 1c`, profile discriminator `00`, then a 9-byte token | Bluetooth's little-endian UUID encoding of `1c9a0000-7d31-4f6a-9b43-4c4154544943`, exp0, and its current discovery token. |

The profile discriminator is the unsigned byte `0x00`; it is not the string `lattice-ble-exp0` and does not identify a device. The nine token octets are sampled from a cryptographically secure random generator. The token is an ephemeral sighting/deduplication handle only; it does not authenticate a peer, establish a private rendezvous, or authorize a GATT connection or Space operation. A scanner MUST select on the Service Data UUID and validate the discriminator and exact token length before recording a sighting.

The maximum legacy payload is 31 bytes: Flags use 3 octets and the Service Data structure uses 28 octets (2-byte AD header, 16-byte UUID, and 10-byte profile/token value). The exp0 advertisement therefore requires no extended-advertising support and no Bluetooth SIG manufacturer identifier.

## Token lifecycle and local retention

A device generates a fresh 72-bit token at exp0 advertising-session start and rotates it every 900 seconds using a monotonic clock. Process restart, advertising-session restart, or failure to obtain cryptographic randomness requires a new token before advertising; if secure randomness is unavailable, advertising MUST remain stopped. Tokens MUST NOT be derived from or reused as a device key, MAC address, account key, Space ID, or persistent local identifier. Wall-clock time MUST NOT select or validate a token.

Rotation replaces the old token atomically; the advertiser MUST NOT emit both generations to bridge a rotation. A scanner treats different tokens as separate sightings and retains sighting tokens only in memory, for at most 900 seconds, with a hard cap of 1,024 entries. Stop, permission loss, Bluetooth shutdown, process restart, or expiry clears the corresponding ephemeral sightings. The scanner MUST deduplicate using the advertised token, not `BluetoothDevice.address`, and MUST NOT persist addresses, names, RSSI histories, tokens, or token-derived identifiers.

Rotation limits the lifetime of this application-layer handle; it does not guarantee unlinkability or anonymity. A nearby observer may correlate transmissions across a token change using timing, radio address behavior, signal strength, hardware/OS behavior, or physical observation. Android controls address privacy and background execution; the application MUST NOT claim a guaranteed address-rotation schedule or continuous discovery.

## Noise XX and first-contact identity binding

For each GATT connection, the central is the Noise initiator and the service host is the responder. Exp0 uses `Noise_XX_25519_ChaChaPoly_SHA256`; the Noise-generated static keys are session-only and MUST NOT be treated as Lattice identity keys. The initiator and responder exchange the three Noise XX handshake messages on `control`, each with an empty Noise payload. A completed Noise handshake alone is unauthenticated and MUST NOT expose Space identifiers, membership, invitations, or application envelopes.

Both sides construct the same fixed-width prologue:

```text
UTF8("lattice:ble:exp0:noise-xx:v0") || 0x00
|| service_uuid[16]                    # canonical UUID/network byte order
|| profile_discriminator[1]            # 0x00
|| initiator_capabilities[3]
|| responder_capabilities[3]
|| observed_responder_token[9]
```

The service UUID bytes in this prologue use the canonical byte order shown by the UUID string, not Bluetooth's little-endian advertising representation. Capabilities are ordered by handshake role, not GATT direction. Both exp0 capability descriptors are exactly `00 00 00`; the advertisement token is the responder's token observed by the initiator. The prologue length is exactly 61 octets. The responder MUST compare that token with its active token when the first identity proof arrives, then retain the matched value only for this connection through proof completion. If rotation wins that race, it rejects the handshake and requires rediscovery; it MUST NOT accept a token from another profile or silently retry under a weaker one.

After Noise enters transport mode, the peers exchange these strictly sized, Noise-encrypted records. All multi-byte lengths and integers are unsigned big-endian; the existing 65-byte version-1 identity bundle is used unchanged.

- Initiator → responder, identity proof (135 bytes): `LBEI || 00 || 01 || initiator_bundle[65] || signature[64]`.
- Responder → initiator, identity proof (135 bytes): `LBER || 00 || 02 || responder_bundle[65] || signature[64]`.
- Initiator → responder, confirmation (70 bytes): `LBEC || 00 || 01 || signature[64]`.
- Responder → initiator, confirmation (70 bytes): `LBEC || 00 || 02 || signature[64]`.

The four-byte magic values are the ASCII octets shown. Version and role are one byte each; no length field or optional extension is permitted in these exp0 records.

The signature inputs are exact byte concatenations. `H` is the 32-byte Noise handshake hash; `T` is the 9-byte observed responder token; `CI` and `CR` are the initiator and responder's three-byte capability descriptors; `BI` and `BR` are their exact 65-byte public bundles. Each domain below includes its trailing `0x00`:

```text
InitiatorProof = UTF8("lattice:ble:exp0:identity-init:v0") || 00
                 || 00 || H || T || CI || CR || BI
ResponderProof = UTF8("lattice:ble:exp0:identity-responder:v0") || 00
                 || 00 || H || T || CI || CR || BI || BR
InitiatorConfirm = UTF8("lattice:ble:exp0:identity-confirm-initiator:v0") || 00
                   || 00 || H || T || CI || CR || BI || BR
ResponderConfirm = UTF8("lattice:ble:exp0:identity-confirm-responder:v0") || 00
                   || 00 || H || T || CI || CR || BI || BR
```

Each signature is Ed25519 over its corresponding input, using the signing key in that sender's bundle. The verifier MUST strictly parse the public bundle, validate its version and key encodings, recompute the full fingerprint, verify the expected role/magic and signature, and reject trailing or missing bytes. It MUST NOT infer identity from the Noise static key. Distinct role/domain strings and the Noise handshake hash prevent proof reflection, cross-protocol replay, and reuse across sessions.

The first-contact comparison string is the first six bytes of:

```text
SHA-256(UTF8("lattice:ble:exp0:sas:v0") || 0x00
       || H || initiator_fingerprint[32] || responder_fingerprint[32])
```

Render those bytes as twelve lowercase hexadecimal digits grouped into six two-digit groups separated by hyphens (for example, `ab-cd-ef-01-23-45`). This 48-bit string binds both full identity fingerprints to this session; it does not establish physical distance. If the peer is already pinned, its exact full fingerprint MUST match the pin or the connection closes without a replacement prompt. On first contact, each user MUST verify the same comparison string through an independent out-of-band channel (or verify the full fingerprint through an equivalent trusted QR/invite flow) and explicitly pin the full fingerprint before sensitive scope discovery. Silent trust-on-first-seen is forbidden. A locally pinned fingerprint proves only that the caller accepted that identity; it does not authorize Space membership or application actions.

The initiator sends its confirmation only after verifying the responder proof and local first-contact policy. The responder becomes peer-authenticated only after verifying that confirmation and its own local first-contact policy; it then sends the responder confirmation. The initiator becomes peer-authenticated only after verifying the responder confirmation. Neither side may send sensitive scope data before reaching that state. Any malformed proof, fingerprint mismatch, failed signature, token mismatch, declined comparison, cancellation, or transport error closes the GATT session and discards the Noise state, proofs, and connection-local token copy.

## Envelope framing, credits, pacing, and reconnect

All values below are `lattice-ble-exp0` candidate rules, not a stable interoperability contract. Every authenticated control record is one complete Noise transport message on `control`; Noise adds its 16-byte ChaChaPoly tag. No GATT long writes, prepare writes, or implicit record concatenation are used. The largest identity-proof record is 135 bytes before Noise encryption, so the negotiated ATT MTU MUST be at least 154 octets: `135 + 16 + 3` for the GATT value and ATT opcode/handle. The central SHOULD request MTU 247 before starting Noise; if the negotiated MTU is below 154, the connection closes before sending identity or application data. A failed MTU request is not permission to fall back.

Let `V = min(512, ATT_MTU - 3)` be the maximum value accepted for a write, notification, or indication. Exp0 envelope frames have a 24-byte header: ASCII `LF`, version `01`, reserved `00`, `transfer_id[8]`, `sequence[2]`, `fragment_index[2]`, `frame_count[2]`, `envelope_length[4]`, and `payload_length[2]`; all integers are unsigned big-endian. `sequence` MUST equal `fragment_index`. Each frame carries a non-empty contiguous slice of one already-protected envelope, and its complete value MUST fit `V`. The payload capacity is `V - 24`; the negotiated minimum therefore permits at least 127 payload bytes per frame. Exp0 caps one envelope at 112,640 bytes (110 KiB), one transfer at 1,024 frames, one incomplete inbound assembly per direction, 112,640 buffered bytes per direction, and a fixed 30,000 ms assembly lifetime measured on a monotonic clock. Implementations MUST configure stricter exp0 limits than the standalone codec defaults where necessary. Frame count MUST equal `ceil(envelope_length / payload_capacity)`, and all non-final fragments MUST fill the capacity exactly.

An authenticated sender begins each envelope with one `LBTS` transfer-start record: `ASCII("LBTS") || 00 || sender_role[1] || transfer_id[8] || envelope_length[4] || frame_count[2]`, exactly 20 bytes before Noise encryption. The sender chooses one cryptographically random non-zero `u64` transfer ID per direction and authenticated session, increments it by one for each later transfer, and closes the session before wrap; the receiver requires this sequence after accepting its first start. The role is `01` for initiator or `02` for responder. A receiver accepts a start only when no transfer in that direction is active and the length, count, role, ID sequence, and negotiated-MTU arithmetic are exact.

The receiver grants a sliding window with one 16-byte pre-encryption `LBWC` record: `ASCII("LBWC") || 00 || sender_role[1] || transfer_id[8] || grant_limit[2]`. `grant_limit` is the exclusive upper bound: the sender may transmit only fragment indices smaller than it. The first grant is `min(4, frame_count)`; after each newly accepted unique fragment, the receiver raises it to `min(accepted_unique_fragment_count + 4, frame_count)`. Identical duplicate fragments are idempotent and do not create credit; conflicting duplicates abort the transfer and close the link. Grants MUST be monotonic, match the active transfer and sender role, and never exceed `frame_count`. A sender MUST send fragments in increasing index order and keep no more than four uncredited fragments in flight. Each GATT connection serializes characteristic operations: at most one client write request is outstanding, and server notifications are emitted one at a time. GATT callback success or local queue acceptance is not remote application receipt.

After complete reassembly, the receiver hands the opaque envelope to its bounded ingress owner. Only after that bounded handoff succeeds does it send a 14-byte pre-encryption completion record `ASCII("LBFA") || 00 || sender_role[1] || transfer_id[8]`. `LBFA` means the receiving transport accepted one complete envelope into bounded ingress; it does not mean Core validation, durable storage, Space authorization, destination delivery, or reading. If ingress cannot accept it, the receiver closes without `LBFA`. A missing credit/completion or incomplete assembly that reaches the 30,000 ms deadline closes the connection; exp0 does not resume fragment state. The sender retains the original durable outbox object and retries that complete envelope after a fresh authenticated session. The signed event and event ID are unchanged; receiver deduplication handles a whole-envelope retry. Transfer IDs and partial assemblies are connection-local and are discarded on every close.

Ownership is explicit: Core/storage owns authored events and durable outbox state; the router owns path choice and retry/backoff, including waking a pending send after fresh discovery; the Android lifecycle owner decides whether permissions, foreground policy, and Bluetooth state permit scanning or reconnect; the GATT adapter owns platform handles, MTU reporting, serialized operations, and typed local results; the authenticated BLE session owns Noise state, transfer/credit validation, and the bounded per-connection assembler. The adapter MUST NOT invent an event, mark a GATT write as delivery, reconnect on its own, or persist a partial transfer. Permission loss, Bluetooth shutdown, process/lifecycle stop, malformed control/frame data, MTU failure, or link loss closes the session and clears ephemeral token, Noise, credit, and assembly state. A subsequent connection rediscovers a current token and repeats the complete identity-binding handshake; no weaker-profile fallback or cross-session fragment resume is allowed.

These ceilings bound one BLE session, not a measured throughput or battery promise. NET-001/002 and the chosen MTU/window behavior remain unverified until exercised on named Android devices under loss, disconnection, permission changes, and process restart.

## Security and release boundary

No privacy guarantee is claimed for `lattice-ble-exp0` until passive-capture behavior and correlation risk are reviewed under ADR-005. Candidate positive advertisement, prologue, identity-proof, frame, and credit vectors are in [`ble-exp0.json`](../vectors/ble-exp0.json); malformed/negative and replay coverage, a reproducible Noise XX transport vector, independent implementation checks, and physical two-/three-device acceptance remain release gates.
