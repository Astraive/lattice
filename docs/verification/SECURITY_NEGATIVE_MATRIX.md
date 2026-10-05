# Security negative acceptance matrix

Current evidence is mostly bounded crate/Core tests. No row implies an end-to-end network security audit. Invalid input must fail before authorized projection and plaintext release.

| Input / boundary | Existing evidence | Current status | Missing cross-layer acceptance |
| --- | --- | --- | --- |
| Wrong-key, expired, untrusted-root X.509 credential | Windows PKI workflow exercised production CLI credential validation; see quality ledger | VERIFIED for CLI validator scenarios | Android/Desktop/Web certificate and trust-bootstrap tests. |
| Forged signed event / malformed canonical bytes | Protocol/event negative tests and bounded fuzz campaigns | VERIFIED for parser/component cases | Malicious live transport input across every client. |
| Wrong MLS author, ciphertext, epoch, group, fingerprint | Core/MLS negative tests | VERIFIED for listed test paths | Real authenticated peer/network rejection before projection. |
| Nonmember or disallowed action/target | Core authorization tests | VERIFIED for local cases | Cross-client mutation authorization. |
| Duplicate/replay and conflicting dependency state | Local sync/Core tests; source audit | UNVERIFIED; component evidence exists but restart/cross-client behavior is untested | Persisted replay and reordering across process restart and clients. |
| Unsafe attachment metadata/name | Files tests/source audit | VERIFIED for bounded local paths | Cross-client malicious manifest and export-path scenario. |
| Malformed sync framing / unplanned targets | Sync planner/transport tests | VERIFIED for unit-level boundary | Malicious live TCP peer and durable-state non-projection proof. |
| Malformed relay mailbox event | Relay parser tests; Core kind-11 admission requires an active manager, complete heads, MLS-authenticated exact generation and post-admission roster | VERIFIED for local Core authorization and codec cases | Independent relay delivery, malformed received event rejection without projection, and cross-client ingress remain unverified. |
| Malformed BLE advertisements/frames | Candidate specification/vectors; implementation and device path unaudited | UNVERIFIED | Fuzz/negative vectors and physical GATT-to-Core tests. |
| Unauthorized notification | Projection source rules documented; app-level notification path audited earlier | UNVERIFIED end-to-end | Actual notification must follow authorized decrypted projection only. |
| WASM/OPFS storage corruption or quota failure | No browser runtime | BLOCKED | Browser tests with malformed DB state, quota failure, reopen, and fail-closed behavior. |

Detailed source/test coverage and bounded fuzz counts remain in [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md). Add new cases only when they defend observable rejection and no-projection behavior.
