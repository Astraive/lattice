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

`lattice-files` streams a source reader through a fixed-size chunk buffer and produces a bounded manifest with ordered chunk hashes and a whole-file SHA-256 digest. Manifests enforce the crate file/chunk/metadata limits, and incoming filename hints must already be safe display names. MIME hints remain untrusted.

Both receiver types require an explicit accept decision before chunk submission, validate each chunk before staging it, expose missing ranges, and gate completion on the whole-file digest. The seekable `StreamedAttachmentReceiver` uses a caller-owned store and rebuilds resume state by rechecking stored chunks; it holds only a chunk buffer and bitmap in memory. `copy_verified_to` rechecks the whole-file digest before streaming verified content to a caller-selected writer. The in-memory receiver provides the same acceptance and integrity gates but stages the entire file, bounded by the caller's quota.

## Integration limits

The crate does not authenticate or authorize manifests, encrypt content, enforce membership or global storage quotas, choose export paths, persist a staging store, expire partial transfers, or implement BLE/LAN/network transport. Callers must perform authorization before receiver creation, present the manifest's size and source as appropriate before acceptance, provide a private staging store and its retention/cleanup policy, and export only after successful verification using a safe caller-selected destination. Resume works only when the caller reopens the same suitable seekable store and supplies the same manifest; no saved bitmap is trusted. Network path selection, event references, blob services, and key retention remain integration work.

The requirements table above records the intended FIL acceptance criteria; it is not a claim that the integrations listed here are implemented.
