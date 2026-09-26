# BLE experimental profile 0

**Profile label:** `lattice-ble-exp0`  
**Status:** experimental candidate; not an interoperable release.  
**Scope:** BLE discovery and link-layer framing only. Event identity, authorization, MLS state, and envelope semantics remain transport-independent.

This document assigns the first migration label and defines candidate service and discovery values for BLE. These values are suitable for isolated development/test builds only; ADR-005 review, byte vectors, independent implementation checks, and Android device acceptance remain release gates. No independent implementation may infer stable wire compatibility from this experimental profile.

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

## Security and release boundary

No privacy guarantee is claimed for `lattice-ble-exp0` until passive-capture behavior and correlation risk are reviewed under ADR-005. Exact handshake identity binding, replay behavior, frame layout, aggregate reassembly limits, pacing/credit windows, reconnect ownership, and byte-exact positive/negative vectors remain separate requirements. Release claims also require independent implementation checks and physical two-/three-device acceptance; this candidate specification alone proves none of them.
