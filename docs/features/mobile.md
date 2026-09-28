# Native Android client — MOB

Android is the only in-scope mobile client and uses Kotlin/Compose with shared Rust logic through UniFFI. Android adapters own Bluetooth, local network, key storage, lifecycle, notifications and audio. No assumption of always-on suspended-phone routing. MOB-004 and MOB-005 are retired; retained iOS-specific design notes are not implementation or acceptance requirements.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| MOB-001 | Android shall run a native Compose shell using the shared Rust event/identity API. | Offline create/send/restart path without duplicate protocol implementation in Kotlin. | M1 |
| MOB-002 | Android shall request Bluetooth permissions at the point needed and explain denials. | Fresh/denied/revoked permission tests show status and safe fallback. | M1 |
| MOB-003 | Android BLE adapter shall handle central/peripheral role, GATT pacing and reconnection within hardware limits. | Three-device active chain and disconnect/reconnect test. | M1 |
| MOB-004 | Retired for current scope: no iOS shell or Core Bluetooth adapter is required. | No iOS implementation, verification or support claim. | Retired |
| MOB-005 | Retired for current scope: iOS background-radio behavior is not a release requirement. | No iOS implementation, verification or support claim. | Retired |
| MOB-006 | Android persistent mesh mode shall be explicit and use a valid visible service when platform permits. | User toggle/start/stop, notification and restricted-background tests. | M2 |
| MOB-007 | Android shall probe Wi-Fi Aware/P2P/LAN capabilities rather than infer them from OS version. | Supported and unsupported devices take correct upgrade/fallback route. | M4 |
| MOB-008 | Android notifications shall be generated only from decrypted, authorized local state and user policy. | Relay packet alone cannot cause plaintext/unauthorized notification. | M3 |
| MOB-009 | Android shall surface Space, channel, transfer, voice, identity and network diagnostics consistently with shared Rust state. | Navigation/accessibility matrix and displayed states match the authenticated Rust projection. | M8 |
| MOB-010 | UI subscriptions and FFI operations shall be coarse, asynchronous and lifecycle-safe. | Background/recreation stress test shows no per-packet UI flood or leaked observer. | M8 |
| MOB-011 | Android shall create and export a PKCS#10 certificate request for the protected device identity. | The CSR verifies against the device Ed25519 key and contains exactly its full-fingerprint URI SAN; private material is never exported, and issued-certificate import is not implied. | M7 |

## Current Rust mobile boundary

`lattice-uniffi` opens local profiles through a caller-provided platform key protector. It exposes public identity and CSR operations, exact peer pins, bounded local Space pages and creation, text outbox/history/search operations, and local recovery. For membership setup it publishes a target-bound one-time X.509 KeyPackage while retaining its private material locally, commits a signed invitation against a restored Space generation, and returns the invite event ID, target fingerprint, token, and Welcome bootstrap for out-of-band transfer. It also imports a bounded Welcome bootstrap only after the exact inviter identity is pinned. Pinning alone does not join a Space, and these local operations do not imply network delivery or general history replay.

Android exposes KeyPackage publication and signed invitation creation through a Compose membership card, and pinned Welcome import through a separate form. The invitation operation commits its policy transition and Welcome checkpoint locally; the join operation validates the inviter pin and MLS Welcome, then imports the signed current-policy checkpoint. Later policy replay, relay delivery, and general history synchronization remain separate and incomplete.

The host `:app:generateUniFfiBindings` task regenerated the Kotlin API successfully. `cargo test -j 1 -p lattice-uniffi` passed 19 tests; the focused Android `testDebugUnitTest` invocation compiled the Compose app and passed the BLE transport and projection-registry tests. The invitation and pinned-Welcome Core scenarios each passed their targeted `lattice-core` test. These checks do not include an APK install, physical BLE, or Android hardware-backed-key acceptance.

Android has permission-checked GATT central/client and peripheral/server primitives plus a foreground session path that composes them with rotating-token discovery, explicit candidate selection, GATT service/CCCD setup, Noise authentication, pinned-identity confirmation, forwarding consent, bounded envelope framing, and Rust Core ingress. The low-level GATT primitives remain transport-only; the app session provides the protocol composition. Automated BLE tests cover framing and ingress behavior, but neither those tests nor emulator behavior complete physical MOB-003 acceptance.

Android also supports opt-in persistent nearby discovery through a connected-device foreground service and ongoing status notification. Starting it requires the relevant Bluetooth permissions and visible notification access; radio-off pauses scanning and advertising, while missing permissions on start/resume or unavailable radio hardware stops or pauses the mode. Android's [connected-device foreground-service rules](https://developer.android.com/develop/background-work/services/fgs/service-types#connected-device) and [notification permission rules](https://developer.android.com/develop/ui/compose/notifications/notification-permission) still apply. The service scans and advertises rotating 72-bit exp0 discovery tokens, retains sightings only in bounded memory, and does not start GATT, authenticate peers, or exchange messages. It is not a background data path.

Android's Wi-Fi probe checks `PackageManager` feature flags for Wi-Fi Aware/Direct, current Aware service availability, the P2P system service, and the active default network's Wi-Fi/Ethernet transports. It labels missing hardware, missing path permission, and temporary unavailability separately; it refreshes when the default network changes. Wi-Fi permissions follow Android's [Wi-Fi Aware](https://developer.android.com/develop/connectivity/wifi/wifi-aware) and [Wi-Fi Direct](https://developer.android.com/develop/connectivity/wifi/wifip2p) API generations (`ACCESS_FINE_LOCATION` through API 32, `NEARBY_WIFI_DEVICES` from API 33). This is a local capability snapshot, not peer reachability. No Wi-Fi data adapter is active, so a probe never switches the route: Bluetooth discovery remains the baseline, and there is no connected data path to claim.

Primary screens: welcome/identity, profile/permissions, Space list, channel/thread, DM, voice, transfer center, members/roles, invite verification, relay/network state, local retention, diagnostics. Theme tokens can be shared; Android semantics and accessibility remain native. Recheck Android permission guidance at release time.

## Native responsibilities

| Concern | Android | Shared Rust |
| --- | --- | --- |
| Nearby radio | Bluetooth permissions, GATT client/server, capability probe, optional foreground service | Envelope validity, route policy, sync and peer state |
| Keys | Android Keystore-backed wrapping where available | Identity/MLS formats and key-use policy |
| Call | Audio focus/route, microphone, WebRTC engine | Voice authorization, signaling state |
| UI | Compose state/notifications | Command result and projection subscription |

## Lifecycle matrix

The physical lifecycle matrix remains unrun. The foreground Activity owns GATT sessions and tears down scanning and sessions when it stops; the opt-in foreground service only scans and advertises tokens. Core persists local outbox records, but physical restart, reconnection, and resend behavior remain acceptance items.

## UI and FFI operation contract

The UniFFI boundary exposes coarse local profile operations, BLE session operations, and bounded projection subscriptions; Compose does not issue raw SQL or construct authenticated event bytes. The full `send_message`, `observe_channel`, and `join_voice` interface in the product contract is not yet implemented end to end. Current BLE handling ingests complete opaque envelopes through Core and reports bounded projection updates; physical backpressure and lifecycle behavior remain unverified.

On Android, profile operations run on `Dispatchers.IO` inside `lifecycleScope`; cancellation is rethrown and UI publication checks that the Activity is still alive. Activity teardown closes the profile, while generated UniFFI handles keep in-flight calls alive and `MobileClient` serializes access with a Rust mutex. Android's current notification path is limited to the explicit persistent-scan status; it contains no peer or message content. Message notifications remain unavailable until a decrypted, authorized local projection is connected to a notification policy.

UniFFI exposes bounded, coalesced Core projection observers with cancellable waits and explicit close. Android owns observer workers in a profile-scoped registry and closes them during profile teardown; UI refreshes local snapshots rather than receiving an unbounded per-event callback stream.

Accessibility is functional: TalkBack and Android accessibility labels for queued vs delivered, non-color status, focus order in message actions, enlarged text that keeps the composer usable, reduced motion and audio device announcements. Theme tokens may align color/spacing across desktop and Android, but native controls remain idiomatic.

Android exposes Identity, Spaces and Diagnostics tabs; selecting a local Space opens its channel composer, while Diagnostics shows BLE, Wi-Fi, persistent-service readiness, and AndroidKeyStore wrapping-key protection status. API 31 and newer use `KeyInfo.securityLevel`; older releases use `KeyInfo.isInsideSecureHardware`. The status applies only to the wrapping key; it does not claim StrongBox use or hardware-resident identity signing keys. Compose content scrolls vertically, uses scalable Material text/input styles, exposes major sections as headings, and applies safe-drawing insets so content does not overlap system bars. Recovery and channel options use labeled radio semantics. On an API 37 emulator, TalkBack focus moved among tabs and Diagnostics opened from the focused tab; at 1.5 font scale, long content remained vertically scrollable. That emulator reported software-backed wrapping-key protection. Physical-device accessibility and hardware protection remain unverified.
