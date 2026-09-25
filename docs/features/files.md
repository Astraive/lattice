# Attachments and transfer — FIL

The local transfer crate models attachments as bounded manifests and independently verified chunks. This is not itself a sender-authentication, authorization, or network-transport layer.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| FIL-001 | An authorized member shall attach a file by creating an authenticated manifest with length and hashes. | Modified manifest is rejected before chunk transfer. | M4 |
| FIL-002 | Chunks shall have deterministic identity and be independently checked before marking present. | Corrupted/replaced chunk fails hash and is not reported complete. | M4 |
| FIL-003 | Transfer shall resume after app restart and path change by missing-chunk bitmap/ranges. | Start over BLE, finish over LAN/Wi-Fi without retransmitting verified chunks. | M4 |
| FIL-004 | Large file traffic shall prefer a direct high-bandwidth path when eligible. | With local fast path present, BLE carries discovery/control but not file bulk. | M4 |
| FIL-005 | Users shall accept incoming files and see size/source before durable export. | Declined or over-quota transfer never creates a completed exported file. | M4 |
| FIL-006 | Filenames and MIME claims shall be sanitized and treated as untrusted. | Traversal/HTML/executable-name cases cannot overwrite arbitrary paths or execute. | M4 |
| FIL-007 | Storage and transfer queues shall enforce per-file/global limits and clean partial state. | Oversized manifest rejected; interrupted chunks expire under policy. | M4 |

## Implemented local behavior

`lattice-files` streams a source reader through a fixed-size chunk buffer and produces a bounded manifest with ordered chunk hashes and a whole-file SHA-256 digest. A seekable source can later serve individual chunks through `read_verified_chunk_into`, which checks the manifest-declared size and digest before exposing each chunk to a transport caller. Manifests enforce the crate file/chunk/metadata limits, and incoming filename hints must already be safe display names. MIME hints remain untrusted.

Both receiver types require an explicit accept decision before chunk submission, validate each chunk before staging it, expose missing ranges, and gate completion on the whole-file digest. The seekable `StreamedAttachmentReceiver` uses a caller-owned store and rebuilds resume state by rechecking stored chunks; it holds only a chunk buffer and bitmap in memory. `copy_verified_to` rechecks the whole-file digest before streaming verified content to a caller-selected writer. The in-memory receiver provides the same acceptance and integrity gates but stages the entire file, bounded by the caller's quota.
`AttachmentStagingStore` reserves each event-bound manifest's full declared size before opening a writable staging file. Callers choose per-file bytes, global reserved bytes, retained transfer count, and inactivity retention. It uses an advisory cross-process quota lock, an exclusive per-transfer file lock, and transfer-ID-derived filenames; Unix-created staging directories/files use owner-only permissions. The same private directory restores verified chunks after restart. `cleanup_expired` removes idle records (and runs before a new reservation); callers should also run it periodically and call `remove` after export or rejection. Construct the store and reserve bytes only after the user has reviewed the authenticated source and manifest size.

## Integration limits

`lattice-core` retains a manifest only after authenticating its MLS-bound event and authorizing `MESSAGE_SEND | MESSAGE_ATTACH`. For local sending, `Client::queue_file_manifest` validates the bounded manifest, encrypts it as an MLS application, authorizes it through the same reducer, and atomically stores the signed event and outbox envelope. Attachment bytes remain in caller-owned staging storage; the queue receipt means only `queued`. Callers can request an opaque, event-specific attachment capability from an authorized reducer node and create the existing receivers from its retained manifest. A deterministic transfer ID binds the exact event ID and manifest metadata but is not an authorization proof; receivers still require explicit acceptance.

`lattice-files` does not encrypt content, enforce membership, choose export paths, or provide attachment UI. Its disk store enforces caller-configured per-file/global/count quotas and expiry but depends on the caller to select a private application directory, choose policy limits, trigger periodic cleanup, and remove completed/rejected records after the workflow. `lattice-node` adds authenticated, resumable attachment transport over an already connected peer adapter; the caller still supplies the authorized manifest/event and peer authorization. Export remains a caller action after verification to a safe selected destination. This does not provide BLE/LAN discovery, platform path selection/failover, app UI, or Android/desktop adapter wiring.

The requirements table above records the intended FIL acceptance criteria; it is not a claim that the integrations listed here are implemented.
