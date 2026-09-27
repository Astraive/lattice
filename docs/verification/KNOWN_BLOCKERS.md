# Known blockers

Ordered by dependency impact. These do not reduce product scope.

| Order | Blocker | Affected capabilities | Evidence / exact missing input | Next action |
| --- | --- | --- | --- | --- |
| 1 | No general Web-to-native carrier or browser network matrix | WEB-007 and browser-to-native/CLI/Desktop/Android interoperability | Managed Chromium verified one Web↔CLI exchange each way over exact-Origin/token-paired loopback `ws://`; the CLI bridge is HTTP-only and one-session. No secure WebSocket/HTTPS-compatible carrier, Internet/NAT/TURN, Desktop/Android adapter, or other-browser matrix. | Add an HTTPS-compatible authenticated path and run supported-browser plus LAN/NAT/TURN acceptance; do not count carrier state as Core acceptance. |
| 2 | No physical Android/adb | Offline two-device BLE and three-device carry acceptance; Android cross-client paths | Workstation inspection records no Android device or adb; physical acceptance cannot be simulated by unit tests. | Attach two/three devices, run `PHYSICAL_ANDROID_ACCEPTANCE.md`, capture hardware/OS/revision/log evidence. |
| 3 | Desktop/Android live application event path not established | Android↔Desktop/CLI and same-Space cross-client acceptance | Desktop's bounded receive path is compiled, but no Desktop↔CLI process exchange has run; Android physical path remains absent. | Complete and prove the real cross-process authenticated Core path before marking matrix rows. |
| 4 | OPFS crash, quota and same-profile contention matrix incomplete | Web durable storage and restart | A managed Chromium smoke verified separate profile directories and persistence after page reload/reopen; browser process-kill, crash rollback, quota failure and same-profile tab exclusion were not exercised. | Run the failure/restart matrix on supported browsers and capture pre/post-commit state and lock behavior. |
| 5 | Web compatibility, accessibility and privacy review incomplete | WEB-009 and Web release readiness | No supported-browser matrix, keyboard/screen-reader acceptance, CSP/network capture, or independent Web security review has been recorded. | Complete accessibility, privacy and dependency/security review before support claims. |

The historical feature inventory and further source-audit gaps are in [`docs/quality/FEATURE_LEDGER.md`](../quality/FEATURE_LEDGER.md). A blocker is not permission to remove or narrow acceptance criteria.
