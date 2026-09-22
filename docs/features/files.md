# Attachments and transfer — FIL

Files are authenticated manifests plus bounded, independently verified chunks. The application displays the transfer status and never assumes a Nostr event relay accepts arbitrary binary objects.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| FIL-001 | An authorized member shall attach a file by creating an authenticated manifest with length and hashes. | Modified manifest is rejected before chunk transfer. | M4 |
| FIL-002 | Chunks shall have deterministic identity and be independently checked before marking present. | Corrupted/replaced chunk fails hash and is not reported complete. | M4 |
| FIL-003 | Transfer shall resume after app restart and path change by missing-chunk bitmap/ranges. | Start over BLE, finish over LAN/Wi-Fi without retransmitting verified chunks. | M4 |
| FIL-004 | Large file traffic shall prefer a direct high-bandwidth path when eligible. | With local fast path present, BLE carries discovery/control but not file bulk. | M4 |
| FIL-005 | Users shall accept incoming files and see size/source before durable export. | Declined or over-quota transfer never creates a completed exported file. | M4 |
| FIL-006 | Filenames and MIME claims shall be sanitized and treated as untrusted. | Traversal/HTML/executable-name cases cannot overwrite arbitrary paths or execute. | M4 |
| FIL-007 | Storage and transfer queues shall enforce per-file/global limits and clean partial state. | Oversized manifest rejected; interrupted chunks expire under policy. | M4 |

Whole-file SHA-256 and chunk hashes protect integrity. Encryption and membership use the same approved application profile as channel data, with key retention for resumed transfers. Uploading an attachment to a volunteer blob service is a separate, explicit transport profile, never a hidden mandatory dependency.

## Manifest and transfer flow

The author selects a local file, checks role, size and local policy, streams hashes without loading the whole file into memory, creates a protected manifest containing opaque file ID, filename/MIME hints, length, whole-file digest, ordered chunk digests and channel/Space association, then commits a message referencing that manifest. A recipient sees size/source/accept action before durable export. The transfer planner compares chunk bitmaps and requests only missing pieces. A path can switch mid-transfer; chunk identity stays constant. Chunks received out of order are placed in bounded temporary storage and verified before the bitmap advances. Completion requires matching whole-file hash and an atomic move to a sanitized export destination.

| Failure | Required behavior |
| --- | --- |
| Manifest signature/permission invalid | Reject file reference and all following chunks. |
| Claimed length or chunk count exceeds quota | Reject before allocation or write. |
| One corrupt chunk | Discard only that chunk; request replacement; never mark full file complete. |
| Sender disappears | Keep permitted partial state with expiry and clear resume status. |
| Storage becomes full | Pause safely, clean temporary writes and preserve already verified state. |
| Filename contains `../`, reserved path or misleading extension | Sanitize display/export and require explicit user choice as needed. |
| Sender removed during transfer | Define epoch/key access according to manifest authorization and retention; no automatic old-key access. |

Small BLE transfers are a policy exception, not the normal path. Relays carry manifest/event references only unless an explicitly compatible encrypted blob transport exists. A volunteer cache should not receive arbitrary large content by default. Device-local file cache and export have separate retention, so deleting a message projection does not silently claim that all previously exported copies vanished.
