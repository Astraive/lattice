# Release readiness

Current gate: **NOT READY**. The product-owner completion contract requires real Android, Desktop, CLI and Web communication and persisted-state evidence; the current verification record does not satisfy that gate.

| Gate | Current assessment | Evidence / next action |
| --- | --- | --- |
| History and requirements inventory | Inventory recorded; runtime reconciliation remains incomplete | [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md); continue capability-by-capability validation. |
| Native Core/MLS shared transaction | Passes native regression | `cargo test -p lattice-core openmls_group_and_event_share_a_durable_transaction`; no OPFS inference. |
| Web shared SQLite/OPFS | Limited verified | Production WASM build passed; two distinct Chromium profiles opened concurrently and identity plus messages survived a full page reload/reopen. OPFS crash recovery, quota/error handling, same-profile contention and supported-browser matrix remain unverified. |
| Authenticated cross-client path | Limited verified paths only | CLI↔CLI, a real two-way Desktop↔CLI application-event round, and Web↔CLI loopback are evidenced; the earlier pre-fix Desktop membership-event path failed with `WrongEventKind`. A post-fix Core regression now covers atomic membership-bundle acceptance, but no authenticated Desktop↔Desktop exchange has been rerun. Android physical paths and full convergence remain unverified. See [`INTEROP_MATRIX.md`](INTEROP_MATRIX.md) and [`KNOWN_BLOCKERS.md`](KNOWN_BLOCKERS.md). |
| Physical Android BLE | Not run | Requires physical devices; execute [`PHYSICAL_ANDROID_ACCEPTANCE.md`](PHYSICAL_ANDROID_ACCEPTANCE.md). |
| Durable restart/recovery | Component-level tests exist; full matrix incomplete | See [`RESTART_MATRIX.md`](RESTART_MATRIX.md). |
| Security negatives | Component tests and bounded fuzz evidence exist; end-to-end coverage incomplete | See [`SECURITY_NEGATIVE_MATRIX.md`](SECURITY_NEGATIVE_MATRIX.md). |
| Transport/courier/relay | Mixed component-level and limited CLI/Desktop acceptance | See [`TRANSPORT_MATRIX.md`](TRANSPORT_MATRIX.md); multi-hop, routing integration, and relay receive remain unverified. |
| M8/migrations/external review | Not a final release gate yet; no independent review claimed | Complete software-fixable acceptance first; record exact reviewer/dependency when scheduled. |

No release claim may use `PARTIAL`, `IMPLEMENTED`, or `COMPILES` as final feature state. Final classification must use `VERIFIED`, `BLOCKED-EXTERNAL`, `FAILED`, or explicit owner-authorized `INTENTIONALLY REMOVED` with exact evidence.
