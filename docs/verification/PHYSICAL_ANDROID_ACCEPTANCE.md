# Physical Android acceptance procedure

Status: **physical acceptance not run**. The configured ADB target list contains two Android emulators and no physical devices. Emulator results are useful for JVM/build behavior but do not satisfy the two-/three-physical-device acceptance gates. Use this procedure when the required hardware is attached; do not claim BLE acceptance from a build or unit test.

The Android CSR/system-root provisioning requirements for the development-only test CA are specified in [development PKI](../development-pki.md); until a disposable system image is prepared, this path remains externally blocked.

## Run record

Copy this template into a dated evidence file. Leave unknown fields blank and mark the step blocked; do not infer an outcome from a successful scan.

| Field | Value |
| --- | --- |
| Test date/time and operator | |
| Exact Git revision | |
| APK SHA-256 | |
| Android A model, release/build, Bluetooth chipset | |
| Android B model, release/build, Bluetooth chipset | |
| Device A serial / device B serial | |
| A and B full identity fingerprints | |
| Android C model, release/build, Bluetooth chipset | |
| Device C serial | |
| C full identity fingerprint | |
| Space ID / group reference | |
| Peer pins and runtime permissions | |
| Wi-Fi and cellular disabled on both | |

| Direction / attempt | Event or DM packet ID | Sender outbox before / after | Receiver Core outcome | Receiver history count | Duplicate count | Disconnect, retry, and restart result | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A→B first send | | | | | | | |
| B→A first send | | | | | | | |
| Retry after disconnect | | | | | | | |
| Post-relaunch history check | | | | | | | |

| Evidence file | Path | Redacted and reviewed |
| --- | --- | --- |
| A and B logcat | | |
| Screenshots | | |
| Additional diagnostics | | |

## Host preflight

Run from the repository root in PowerShell. Keep the revision and APK hash with the test record.

```powershell
if (git status --porcelain) { throw "Commit or separately record all source changes before the physical acceptance build." }
$revision = git rev-parse HEAD
Write-Output "revision=$revision"
Set-Location apps/android
.\gradlew.bat :app:assembleDebug
$apk = "app\build\outputs\apk\debug\app-debug.apk"
Get-FileHash $apk -Algorithm SHA256
adb devices -l
```

Connect physical Android devices A and B; attach C for the three-device carry scenario. Confirm every serial is listed as `device`. Install the same APK on each attached device:

```powershell
$serialA = "replace-with-Android-A-serial"
$serialB = "replace-with-Android-B-serial"
$serialC = "replace-with-Android-C-serial"
adb -s $serialA install -r $apk
adb -s $serialB install -r $apk
adb -s $serialC install -r $apk
```

Record model, Android release, build ID, Bluetooth chipset, and serial for every participating device. Run `adb -s $serialA shell getprop ro.product.model`, `adb -s $serialA shell getprop ro.build.version.release`, and `adb -s $serialA shell getprop ro.build.display.id`; repeat for B and C. Record the chipset from device information when available. Grant permissions through the app's runtime flow, not by seeding app state.

Android supports local one-time KeyPackage publishing, signed invitation creation, and pinned Welcome import. No physical device is available here to execute or record the radio test. Provision all profiles before the run using the in-app flow below; do not seed SQLite rows or count a scan as acceptance.

### Provision shared membership

1. Obtain a trusted leaf-first X.509 credential vector for each device through the external issuer. Each vector must match that profile's protected signing identity; Android does not issue certificates.
2. On B, open Spaces → Invite a device, enter B's credential vector, publish the one-time KeyPackage, and transfer its Base64 bytes to A through a trusted out-of-band channel.
3. On A, create a local Space if needed. Open that Space, enter A's credential vector and B's KeyPackage, choose an expiry and use limit, then create the signed invitation. Transfer the Welcome bootstrap to B.
4. On B, pin A's exact public identity bundle after independently comparing A's full fingerprint. Import the Welcome bootstrap with A's full fingerprint and B's credential vector.
5. Confirm both apps show the same Space ID and group reference. On A, pin B's exact identity bundle for first-contact BLE verification. Record the certificate issuer and confirmation method; never include private material in the evidence bundle.

## Two-device offline test

Use the foreground Nearby screen on both devices. Its lifecycle owns the GATT server and stops scanning and sessions when the Activity leaves the foreground. The separate Persistent nearby service only scans and advertises rotating tokens; it does not start GATT or exchange messages.

1. Launch Lattice on A and B. Confirm independent full identity fingerprints and the same Space ID and group reference. Resolve any runtime permission prompts, then keep both Nearby screens visible.
2. Disable Wi-Fi and cellular on both devices. Confirm no project service is reachable. Start nearby scanning on both and record the unverified token sightings.
3. On A, select B's current sighting. On both screens, compare and approve the safety number when prompted. Approve opaque-envelope forwarding only after identity verification. A scan or token match alone is not a successful connection.
4. Queue a fresh text event on A and record its event ID and local outbox state. Confirm B's authorized message history shows exactly one copy with that event ID. Record B's Core result from available session diagnostics or logs. Record LBFA as peer-ingress acceptance, never destination delivery.
5. Queue a fresh event on B and repeat the connection in the opposite direction. Record the same fields for B→A. Include the sender's state before the attempt, after peer ingress acknowledgement, and after disconnect.
6. Close both apps normally, relaunch them, and confirm identities, Space membership, and one visible copy of each accepted event persist. Record queued or peer-accepted outbox states and any duplicate count.
7. Queue an event while the peer is disconnected. Reconnect and confirm the same event ID is retried and appears once in authorized history. Disconnect once during a transfer and record whether retry succeeds without changing the event ID or claiming destination delivery.
8. Capture redacted logs and screenshots with timestamps. The message history UI displays event IDs; never include credential vectors, private keys, full rendezvous tokens, or unrelated user data.

For log capture, clear logs immediately before a run and save them after it:

```powershell
adb -s $serialA logcat -c
adb -s $serialB logcat -c
# Run the device scenario, then save each buffer:
adb -s $serialA logcat -d -v threadtime > android-a-logcat.txt
adb -s $serialB logcat -d -v threadtime > android-b-logcat.txt
```

## Lifecycle, permissions, and network matrix

Run these transitions on both named devices after the foreground offline exchange. Use a distinct event ID for each queued item. For each row, capture the device serial, Android build, permission/radio state, visible capability/status text, scanner/advertiser/GATT state, outbox state and attempt count before/after, receiver Core result, history count, duplicate count, and timestamps. Mark a row blocked rather than inferring behavior when the required state or diagnostic is unavailable.

| Transition | Procedure | Required result |
| --- | --- | --- |
| Foreground → background or locked | Start a foreground Nearby scan/session, queue one event while the peer is unavailable, press Home and lock the screen. | The foreground GATT session stops as documented. The app does not present an active connection or delivery claim. The durable event ID and queued state remain available. |
| Background/locked → foreground | Unlock and reopen Nearby on both devices, restore permissions if requested, then explicitly re-establish the authenticated peer session. | Capability text reflects the actual permission/radio state. The pending event is retried with the same ID and appears at most once in authorized history after Core accepts it. |
| Persistent nearby mode | Enable the separate persistent mode, background or lock the device, and capture its notification and radio state; then return to the foreground. | Report only the service's scanning/advertising behavior. This service does not start GATT or exchange messages; it must not imply a connected peer or delivery. |
| Bluetooth permission revoked/restored | With the app idle and during a foreground attempt, revoke required Bluetooth permissions in Android Settings; capture state, restore them through the runtime flow, and retry. | Revocation stops the affected operation without a crash or stale “available/connected” state. Restoring permissions does not fabricate a peer session; explicitly restart and verify the operation. |
| Bluetooth off/on | Turn Bluetooth off during scan and during a transfer, then turn it on and return to Nearby. | Radio loss is visible, active work stops safely, and locally committed events remain queued or show the recorded peer-ingress state. After radio recovery, a new authenticated session is required and retries preserve IDs. |
| Process termination/restart | Queue an event with the peer absent, terminate the app process using the device's app controls, relaunch it, and re-open Nearby. Record the termination method (force-stop is not equivalent to ordinary backgrounding). | The local event and ID survive restart; the UI does not report remote delivery. When a supported transport is explicitly re-established, pending work can retry without duplicate projection. |
| Network loss/recovery | With Wi-Fi and cellular disabled, queue an event and record the outbox state; restore connectivity without changing the BLE peer state. | Record whether the tested feature uses network transport. Do not credit network restoration as BLE acceptance; there is no delivery claim without the corresponding authenticated peer/Core result. |

| Scenario | Device serial | Event ID | Permission/radio before → after | Outbox state / attempts before → after | UI status | Core/history/duplicate result | Timestamp / evidence path | Pass / blocked |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| | | | | | | | | |

Pass only when local commits remain durable, capability/UI state tracks real Android permissions and radio state, and no state is described as recipient delivery without the recorded Core evidence. Keep each device's result separate; an emulator run does not fill this physical matrix.

## Pairwise direct-message test

Run after both Nearby screens establish authenticated BLE sessions and compare the pinned peer identities. A shared Space is not required for this section.

1. On both devices, open Identity → Direct messages and enter each device's externally issued X.509 credential vector. Publish a fresh local KeyPackage on each device; exchange each public KeyPackage and full identity fingerprint out of band.
2. On A, enter B's exact fingerprint and KeyPackage and create the pairwise conversation. Confirm the invitation is locally queued and not shown as accepted or delivered before transport.
3. Transfer the invitation over the authenticated BLE session to B. Before consent, verify B shows one pending invitation and no active conversation. On B, explicitly accept; verify the Welcome imports and a conversation appears. Also run one declined invitation and confirm it creates no conversation.
4. Send a new text packet A→B and B→A. Record packet IDs, sender outbox state, receiver Core result, and exactly one decrypted history entry per direction. Repeat one packet or reconnect to verify duplicate ingress does not create another history entry.
5. Disconnect one peer before sending, then reconnect and confirm the same packet ID is retried and accepted once. Restart both apps and confirm conversations and protected local history persist.
6. Capture redacted logs and screenshots. Do not capture credential vectors, Welcome bytes, private keys, or message bodies containing user data.

An invitation still pending user consent is a successful peer-ingress receipt only after its durable pending record commits. It is not proof that the user accepted the conversation. Message peer-ingress acceptance is not a read receipt.

## Three-device carry test

The software carry path is implemented with durable per-peer retry/acceptance state. Physical three-device carry, restart recovery, and final projection convergence remain unverified.

1. Initialize A, B, and C independently. Establish common Space membership through supported flows. Disable Wi-Fi and cellular on all devices.
2. Keep C unreachable. Let A author event E and transfer it to B. Record A's event ID and B's Core outcome; B must retain one authorized copy under E's original ID and signature.
3. Disconnect A. Restart B and confirm E remains in authorized history and its relay eligibility/retry state survives the restart. Do not seed SQLite rows.
4. Connect B to C. Confirm C accepts the unchanged E (same event ID and original author) after signature, MLS, dependency, and Space authorization checks.
5. Reconnect A and exercise duplicate delivery of E. Confirm no additional visible copy on A, B, or C and no forwarding loop back to already-accepting peers.
6. Repeat with a fresh event interrupted during B's restart/transfer path. Verify retry retains the same signed bytes and all three final authorized event/projection sets converge.
7. Capture the evidence fields above, plus the contact schedule, relay state before/after restart, Core outcomes, event IDs, duplicate counts, and timestamps. Keep the issue open until this physical run passes.

## Failure criteria

Any plaintext or direct UI injection bypassing Core; an identity mismatch; invalid authorization; changed event ID; data loss after restart; unbounded/repeated duplicate projection; or required Internet/project-service dependency fails acceptance. Keep physical and emulator results distinct.
