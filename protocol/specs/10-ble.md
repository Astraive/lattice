# BLE experimental profile 0

**Profile label:** `lattice-ble-exp0`  
**Status:** experimental candidate; not an interoperable release.  
**Scope:** BLE discovery and link-layer framing only. Event identity, authorization, MLS state, and envelope semantics remain transport-independent.

This document assigns the first migration label and defines candidate service, discovery, and first-contact identity-binding values for BLE. These values are suitable for isolated development/test builds only; ADR-005 review, byte vectors, independent implementation checks, and Android device acceptance remain release gates. No independent implementation may infer stable wire compatibility from this experimental profile.

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

| Direction | Record | Exact layout | Bytes |
| --- | --- | --- | ---: |
| Initiator → responder | Initiator identity proof | `LBEI || 00 || 01 || initiator_bundle[65] || signature[64]` | 135 |
| Responder → initiator | Responder identity proof | `LBER || 00 || 02 || responder_bundle[65] || signature[64]` | 135 |
| Initiator → responder | Initiator confirmation | `LBEC || 00 || 01 || signature[64]` | 70 |
| Responder → initiator | Responder confirmation | `LBEC || 00 || 02 || signature[64]` | 70 |

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

## Security and release boundary

No privacy guarantee is claimed for `lattice-ble-exp0` until passive-capture behavior and correlation risk are reviewed under ADR-005. Byte-exact positive/negative handshake and advertisement vectors, replay tests, frame layout, aggregate reassembly limits, pacing/credit windows, reconnect ownership, independent implementation checks, and physical two-/three-device acceptance remain release gates.
