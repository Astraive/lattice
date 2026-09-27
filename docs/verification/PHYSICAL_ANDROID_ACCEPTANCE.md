# Physical Android acceptance procedure

Status: **not run**. Current workstation has no physical Android device or `adb`; no BLE acceptance is claimed. Use this procedure when hardware is attached. Keep this document as a ready-to-run gate, not evidence.

## Record before each run

- Device model, Android version/build, Bluetooth chipset if available
- App revision and APK SHA-256
- Test date/time, operator, permissions granted, battery state
- Network state verified offline (Wi-Fi and cellular disabled)
- Independent identity fingerprints, Space identifier, peer pins
- Test logs with identity private keys, message plaintext where unnecessary, and tokens redacted

Never reuse profile directories between devices. Create identities and Space membership using normal onboarding/invite flows. Do not seed application database rows.

## Two-device offline test

1. Install the same recorded build on Android A and B. Initialize independent profiles and obtain their public fingerprints.
2. While network services are available only if onboarding requires it, establish the test Space with normal Lattice membership/Welcome flows; then disable Wi-Fi and cellular on both devices and verify no project service is reachable.
3. Start the supported nearby service on both. Record discovery, authenticated identity proof, session, transport, and Core acceptance diagnostics. A scan alone is a failure.
4. Send a new text event A→B, then B→A using product UI. Record canonical event IDs and author fingerprints from Core diagnostics.
5. Confirm the receiving UI derives history from the authorized Core projection; close both apps and relaunch. Verify identity, membership and exactly one copy of each event.
6. Queue another event while peers are disconnected, reconnect, and confirm durable outbox recovery and no duplicate visible projection.
7. Preserve redacted logs, screenshots of resulting UI, event IDs, revision, and device metadata in a dated evidence directory; do not mark verified without the artifacts.

## Three-device carry/recovery test

1. Initialize A, B, C independently; establish common Space membership through normal flows. Disable Internet on all devices.
2. Keep C unreachable, let A author event E, and let B receive/carry it. Disconnect A before B meets C.
3. Synchronize B→C and verify C accepts the unchanged event ID and original author after signature, MLS, and Space authorization checks.
4. Restart B during a second queued event, reconnect B/C, then verify eventual convergence and no duplicate projection.
5. Capture the same metadata and evidence as the two-device run, plus timed contact schedule and restart times.

## Failure criteria

Any plaintext or direct UI injection bypassing Core; an identity mismatch; invalid authorization; changed event ID; data loss after restart; unbounded/repeated duplicate projection; or required Internet/project-service dependency fails acceptance. Keep physical and emulator results distinct.
