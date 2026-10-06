# Known blockers

Ordered by dependency impact. These do not reduce product scope.

| Order | Blocker | Affected capabilities | Evidence / exact missing input | Next action |
| --- | --- | --- | --- | --- |
| 1 | No supported browser-to-native transport or network matrix | WEB-007 and browser-to-native/CLI/Desktop/Android interoperability | Managed Chromium verified one Web↔CLI exchange each way over exact-origin, token-paired loopback `ws://`; the CLI bridge is HTTP-only and one-session. Isolated Web and Desktop profiles joined the same signed Space (`cbdf6ebc535ac51621c9a31daf157093`, MLS group `aabab6da4d710eb7e368979a62ce548d151d2c5ca3a7e6280c1ca924d039f746`) using Web's Welcome and Desktop's own credential vector. They exchanged one signed application event each way over manually signaled WebRTC: Desktop event `eac2fe5266eb0cc968fde194a343b1b80bf61dbe97c733e00e107bdb3eed2f9f`; Web event `e8c088beab09ed8d9484b31dfd69a37851c0be180d3dbaab8f6400b728f9b7c6`. Core accepted both; both clients displayed both messages, and Desktop UI restart/history reload retained them. This verifies that test path only. WebRTC does not authenticate peer identity at the transport layer or carry membership transitions. Android adapters, secure WebSocket/HTTPS-compatible transport, Internet/NAT/TURN, and other-browser coverage remain absent. | Add an authenticated browser-native carrier and run supported-browser plus LAN/NAT/TURN acceptance. |
| 2 | No physical Android/adb | Offline two-device BLE and three-device carry acceptance; Android cross-client paths | Workstation inspection records no Android device or adb; physical acceptance cannot be simulated by unit tests. | Attach two/three devices, run `PHYSICAL_ANDROID_ACCEPTANCE.md`, capture hardware/OS/revision/log evidence. |
| 3 | Full Desktop membership and convergence matrix incomplete | Member removal/rekey, repeated reconciliation, and cross-client MLS membership transitions | Two isolated Desktop profiles joined the same Space, restarted, and exchanged an authorized application event; the receiver excluded one older checkpoint-covered ciphertext from projection. `cargo test --locked -p lattice-core create_space_invite_commits_transition_and_importable_welcome -- --nocapture` passes. This resolves the earlier `WrongEventKind` process-path gap for the recorded exchange, but does not establish broader lifecycle or convergence. | Exercise additional reconciliation rounds, member removal/rekey, restart after new membership transitions, and confirm both MLS/policy states and projected histories. Keep Android hardware acceptance separate. |
| 4 | OPFS crash, quota and same-profile contention matrix incomplete | Web durable storage and restart | A managed Chromium smoke verified separate profile directories and persistence after page reload/reopen; browser process-kill, crash rollback, quota failure and same-profile tab exclusion were not exercised. | Run the failure/restart matrix on supported browsers and capture pre/post-commit state and lock behavior. |
| 5 | Web compatibility, accessibility and privacy review incomplete | WEB-009 and Web release readiness | No supported-browser matrix, keyboard/screen-reader acceptance, CSP/network capture, or independent Web security review has been recorded. | Complete accessibility, privacy and dependency/security review before support claims. |

## Issue #19 — Desktop cross-client acceptance

The current run records in the [interoperability matrix](INTEROP_MATRIX.md) satisfy only bounded portions of the Desktop acceptance; they do not close DSK-001–DSK-007.

| Acceptance item | Status | Evidence and remaining gate |
| --- | --- | --- |
| Authenticated Desktop↔CLI sync | PARTIAL | One reciprocal authenticated event exchange is recorded. Run repeated repair/reconciliation rounds and verify stable convergence. |
| Authenticated Desktop↔Android exchange | BLOCKED-EXTERNAL | No physical Android device or `adb` is available. Emulators and unit tests are not substitutes for the paired-client run. |
| Space membership, messages, mutations, and attachments survive restart | PARTIAL | Two Desktop profiles retained membership and one accepted event through the recorded restart path. Cross-client mutations, attachment transfer, and their post-restart state are not evidenced. |
| Pinned-peer mismatch fails closed | PARTIAL | The authenticated node regression `mismatched_peer_pin_fails_before_scope_data_is_sent_or_loaded` covers the lower-level rejection; a Desktop process-level negative run remains unrecorded. |
| Desktop is optional courier, never required authority | UNVERIFIED | Desktop documentation describes courier-only persistent peer mode. No end-to-end run proves opt-in/restart behavior or that Space authorization never depends on the courier. |

Keep the issue open until the missing runtime evidence exists; implementation notes and lower-level tests do not satisfy these client acceptance gates.

The historical feature inventory and further source-audit gaps are in [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md). A blocker is not permission to remove or narrow acceptance criteria.
