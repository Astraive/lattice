# Release readiness

Current gate: **NOT READY**. The product-owner completion contract requires real Android, Desktop, CLI and Web communication and persisted-state evidence; the current verification record does not satisfy that gate.

| Gate | Current assessment | Evidence / next action |
| --- | --- | --- |
| History and requirements inventory | Inventory recorded; runtime reconciliation remains incomplete | [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md); continue capability-by-capability validation. |
| Native Core/MLS shared transaction | Passes native regression | `cargo test -p lattice-core openmls_group_and_event_share_a_durable_transaction`; no OPFS inference. |
| Web shared SQLite/OPFS | Limited verified | Production WASM build passed; two distinct Chromium profiles opened concurrently and identity plus messages survived a full page reload/reopen. OPFS crash recovery, quota/error handling, same-profile contention and supported-browser matrix remain unverified. |
| Authenticated cross-client path | Limited verified paths only | CLI↔CLI, one reciprocal Desktop↔CLI application-event round, the checkpoint-aware Desktop↔Desktop exchange after restart, Web↔CLI loopback, and one bounded manually signaled Desktop↔Web signed-event exchange are evidenced. A separate fresh-profile Desktop↔WebRTC retest failed: Web local send returned `unreachable`; Web Core then reported an unsafe-aliasing recursion error on Desktop ingress, with no message displayed. Treat Desktop↔Web as a historical one-off, not repeatable acceptance. Desktop-WebRTC does not authenticate transport peer identity; Android physical paths, full convergence, member removal/rekey and matrix-wide acceptance remain unverified. See [`INTEROP_MATRIX.md`](INTEROP_MATRIX.md) and [`KNOWN_BLOCKERS.md`](KNOWN_BLOCKERS.md). |
| Physical Android BLE | Not run | SDK ADB sees two emulators, but physical-device acceptance remains unsatisfied; run [`PHYSICAL_ANDROID_ACCEPTANCE.md`](PHYSICAL_ANDROID_ACCEPTANCE.md) on named physical hardware. |
| Durable restart/recovery | Component-level tests exist; full matrix incomplete | See [`RESTART_MATRIX.md`](RESTART_MATRIX.md). |
| Security negatives | Component tests and bounded fuzz evidence exist; end-to-end coverage incomplete | See [`SECURITY_NEGATIVE_MATRIX.md`](SECURITY_NEGATIVE_MATRIX.md). |
| Scheduled deep verification | `.github/workflows/deep-verification.yml` runs bounded campaigns for all 13 maintained libFuzzer targets, clean-install SQLite migration/idempotence, workspace and fixed-seed protocol/convergence tests, and compares two clean release CLI builds. | No deep run is recorded yet; sanitizer coverage, mixed-version campaigns beyond existing vectors, and physical/external acceptance remain separate gates. |
| Transport/courier/relay | Mixed component-level and limited CLI/Desktop acceptance | See [`TRANSPORT_MATRIX.md`](TRANSPORT_MATRIX.md); multi-hop, routing integration, and relay receive remain unverified. |
| M8/migrations/external review | Not a final release gate yet; no independent review claimed | Complete software-fixable acceptance first; record exact reviewer/dependency when scheduled. |

No release claim may use `PARTIAL`, `IMPLEMENTED`, or `COMPILES` as final feature state. Final classification must use `VERIFIED`, `BLOCKED-EXTERNAL`, `FAILED`, or explicit owner-authorized `INTENTIONALLY REMOVED` with exact evidence.
