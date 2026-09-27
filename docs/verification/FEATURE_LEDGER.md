# Feature verification ledger

This is the current evidence-oriented view of product capabilities. Historical inventory and implementation mapping remain in [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md); that source audit is not runtime proof. A capability is `VERIFIED` only for the exact acceptance path named below. Other states follow the master contract: `BLOCKED-EXTERNAL`, `FAILED`, or owner-authorized `INTENTIONALLY REMOVED`.

| Capability | Requirements / clients | Implementation evidence | Runtime acceptance and result | Status |
| --- | --- | --- | --- | --- |
| Authenticated CLI-to-CLI synchronization | CLI, identity, sync | `apps/cli`; historical source and details in [quality ledger](../quality/FEATURE_LEDGER.md) | Two independently persisted CLI profiles exchanged signed/MLS Space events using reciprocal full-fingerprint pins; see audit run log there. | VERIFIED for this exact CLI process scenario; not a proxy for other client pairs. |
| Desktop-to-Desktop application messaging | Desktop | `apps/desktop/src-tauri/src/sync.rs::sync_local_space_once` runs authenticated v2 sync and passes received events into Core; UI entry is `LocalSyncPanel`. Persistent peer mode remains separate opaque courier. | No real Desktop event exchange has been run; Rust command compilation and frontend build pass. | FAILED acceptance — implementation is present but real two-profile Core event receipt remains unverified. |
| Desktop-to-CLI application messaging | Desktop, CLI | Desktop bounded sync command uses the existing authenticated v2 session and Core acceptance path; CLI provides the compatible reconcile peer. | No Desktop↔CLI process exchange has been run; Rust command compilation and frontend build pass. | FAILED acceptance — implementation is present but no application event receipt is evidenced. |
| Core/OpenMLS same-database transaction | Core, MLS, storage | `crates/lattice-core`, `crates/lattice-mls`, `crates/lattice-storage`, local `crates/openmls-sqlite-storage` fork | `cargo test -p lattice-core openmls_group_and_event_share_a_durable_transaction` passed (1); `cargo test -p lattice-core -p lattice-mls -p lattice-storage` passed (111). | VERIFIED on native SQLite; OPFS behavior is separately recorded below. |
| Web OPFS SQLite VFS registration and runtime | Web, MLS | `lattice_mls::api::install_browser_opfs_vfs_for_profile`; `sqlite-wasm-vfs` 0.2; rusqlite 0.39 | LLVM clang-enabled Web production build passed; managed Chromium opened two independent OPFS profiles concurrently and both retained their identity and message history after page reload. | VERIFIED for the exercised worker/profile/OPFS path; crash recovery, quota handling, same-profile contention and browser matrix remain unverified. |
| Web identity, profile and Space participation | Web, CLI | `apps/web/src/App.tsx`, `apps/web/src/cli-loopback-link.ts`, `apps/web/src/profile.worker.ts`, `apps/web/src/worker-client.ts`, `apps/cli/src/web_sync.rs`, `crates/lattice-web-wasm`, `crates/lattice-core`, `crates/lattice-mls` | Two browser profiles enrolled under a pinned issuer, one profile created a Space and offline Welcome, the invitee pinned the inviter fingerprint and joined, and both exchanged signed MLS events over same-origin BroadcastChannel. A separate CLI-created Space and browser profile exchanged one real event each way over the exact-Origin/token-paired HTTP-loopback WebSocket bridge through normal Core acceptance. | VERIFIED for these browser-local and Web↔CLI paths; not a supported remote transport or broad WEB-001–009 release acceptance. |
| Android/Desktop/CLI/Web cross-client matrix | All four clients | Pairwise rows in [`INTEROP_MATRIX.md`](INTEROP_MATRIX.md) | No blanket cross-client proof; only individually evidenced paths are marked. | FAILED as a matrix-wide acceptance; exact verified and blocked paths remain individually classified in the matrix. |
| Android offline BLE communication | Android | See mobile and BLE audit entries in [quality ledger](../quality/FEATURE_LEDGER.md) | Physical device/adb absent; no two-device Internet-disabled evidence. | BLOCKED-EXTERNAL for physical acceptance; scanner/GATT source is not acceptance. |

## Source inventory

The historical feature map, requirement links, implementation paths, tests, audit observations, and campaign evidence are recorded in [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md). It covers the 214-commit default-branch inventory performed for this effort. The 28 grouped capabilities are individually classified below; each state is limited to the acceptance boundary stated in its row.

## Historical source capability groups

The historical inventory has 28 grouped capabilities. Each group below has one exact final state for the acceptance scope in its source-ledger row; `VERIFIED` is limited to the stated path, while missing product paths are `FAILED` and environment-only prerequisites are `BLOCKED-EXTERNAL`.

| Capability group | Final state | Acceptance boundary |
| --- | --- | --- |
| Workspace, build graph, platform scaffolds | FAILED | Native workspace checks pass, but this aggregate scaffold scope includes missing Web and incomplete product integrations. |
| Canonical encoding, event IDs, signed events, vectors and inspector | VERIFIED | Rust and TypeScript canonical-vector and hostile-decoder paths pass; this does not prove client interoperability. |
| Identity generation, storage, fingerprints and protected keys | VERIFIED | Native protection, identity persistence and process-reopen paths pass; Android device storage acceptance is separate. |
| Peer pinning, mismatch handling and unpin | VERIFIED | Exact fingerprint pinning, persistence, mismatch rejection and the authenticated CLI peer scenario are evidenced. |
| X.509 / RFC 9420 credential validation and PKI issuance | VERIFIED | Windows CLI CSR-derived credentials pass production trust validation and expected negative credential checks. |
| Canonical Space genesis, durable snapshots and recovery | VERIFIED | Native Core persistence, restore and recovery paths pass; this is not a cross-client membership claim. |
| Space policy, permissions, conflicts, membership and MLS transitions | FAILED | Core authorization and conflict recovery pass, but product member-removal/rekey transitions remain unavailable. |
| Invites, KeyPackages, Welcome bootstrap and recovery generation | VERIFIED | Core invite transaction, Welcome import and restored checkpoint policy regression paths pass. |
| Text, encrypted cache, history, send status and edits | VERIFIED | Authenticated CLI-to-CLI Space text event acceptance and durable Core projections are evidenced; only that process scenario is verified. |
| Tombstones, reactions, pins, mentions, rich text, dependencies and ephemeral state | FAILED | Core projections and expiry tests exist, but required cross-client mutation authoring/acceptance is incomplete. |
| Device-scoped DM MLS groups | FAILED | The two-device MLS primitive passes unit coverage; Core event, storage, outbox and client workflows do not exist. |
| Search and retained-history query | FAILED | Local search behavior is tested; authenticated remote history and the required cross-client restart path are absent. |
| Attachment manifests, receivers, staging quotas and verified chunks | FAILED | Local transfer/staging mechanisms pass; cross-client interrupted transfer and process-restart resume acceptance is unmet. |
| Bounded routing, path offers, health and TCP framing | FAILED | Component policies are tested, but production clients do not integrate path negotiation or failure fallback. |
| Direct authenticated sync, scoped summaries and repair | VERIFIED | One real authenticated CLI-to-CLI event exchange and convergence passed; Desktop and other client pairs are not implied. |
| CLI identity, Space, messaging, history, search, relay config and sync | VERIFIED | CLI process persistence and authenticated CLI-to-CLI sync are evidenced; this is not cross-client coverage. |
| Desktop identity, Space/message UI, local paths, relay settings and bounded sync | BLOCKED-EXTERNAL | The sync/Core command compiles, but Desktop process acceptance could not run because available WebView input and inspector routes failed. |
| Shared Desktop theme and status components | FAILED | Package-level component checks pass, but no production consuming surface is established. |
| Courier queues, pinned TCP forwarding and relay outbox | FAILED | Queue mechanisms and one-hop transfer are tested; multi-hop/failure preservation is not met, and source consumption on send can lose a copy. |
| NIP-01/NIP-11/NIP-40 relay codec and client | FAILED | Codec/parser paths pass, but no product relay publish/retrieve callsite or independent-service interoperability exists. |
| Android Compose identity, Space, messages, diagnostics, permissions and accessibility | BLOCKED-EXTERNAL | Android message notification selection is source-tested but JVM/device execution is unavailable without Java, Android hardware and adb. |
| Android BLE codec, scanning, GATT primitives and nearby service | BLOCKED-EXTERNAL | Authenticated session source exists; required two/three-device offline BLE acceptance needs unavailable physical devices and adb. |
| Android UI selection and native key status | BLOCKED-EXTERNAL | Real supported-device accessibility, lifecycle and native-key acceptance requires unavailable Android hardware. |
| Voice signaling, lifecycle and permission termination | VERIFIED | Deterministic Rust state, error, deadline and revocation tests pass; this does not claim media calls. |
| Voice native media, audio adapters, WebRTC/Opus/ICE/TURN | FAILED | No platform media dependency, native artifacts or actual media integration is present. |
| Testkit, property/campaign and fuzz harnesses | FAILED | Selected bounded fuzz campaigns pass; required BLE/invite/MLS-wrapper/voice target coverage remains absent. |
| Documentation, requirements, status corrections and architecture decisions | VERIFIED | Current requirements, evidence ledgers, matrices and blocker documents state implemented, failed and externally blocked paths explicitly. |
| Web application and browser Lattice client | FAILED | An experimental browser profile and same-origin two-profile MLS flow are verified, as is one HTTP-loopback Web↔CLI Core exchange in each direction. Secure remote transport, HTTPS page support, WAN/NAT, Desktop/Android paths, compatibility, accessibility and release gates remain unmet. |
