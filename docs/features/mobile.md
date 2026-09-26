# Native mobile clients — MOB

Android uses Kotlin/Compose and iOS uses Swift/SwiftUI. Shared Rust logic arrives through UniFFI; native adapters own Bluetooth, local network, key storage, lifecycle, notifications and audio. No assumption of always-on suspended-phone routing.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| MOB-001 | Android shall run a native Compose shell using the shared Rust event/identity API. | Offline create/send/restart path without duplicate protocol implementation in Kotlin. | M1 |
| MOB-002 | Android shall request Bluetooth permissions at the point needed and explain denials. | Fresh/denied/revoked permission tests show status and safe fallback. | M1 |
| MOB-003 | Android BLE adapter shall handle central/peripheral role, GATT pacing and reconnection within hardware limits. | Three-device active chain and disconnect/reconnect test. | M1 |
| MOB-004 | iOS shall run a native SwiftUI shell with shared Rust semantics and Core Bluetooth adapter. | Mixed Android/iPhone offline text/sync test succeeds on devices. | M2 |
| MOB-005 | iOS shall show background-limited radio availability accurately. | Foreground, lock, suspension and relaunch capture matches UI. | M2 |
| MOB-006 | Android persistent mesh mode shall be explicit and use a valid visible service when platform permits. | User toggle/start/stop, notification and restricted-background tests. | M2 |
| MOB-007 | Mobile shall probe Wi-Fi Aware/P2P/LAN capabilities rather than infer them from OS version. | Supported and unsupported devices take correct upgrade/fallback route. | M4 |
| MOB-008 | Native notifications shall be generated only from decrypted, authorized local state and user policy. | Relay packet alone cannot cause plaintext/unauthorized notification. | M3 |
| MOB-009 | Native clients shall surface Space, channel, transfer, voice, identity and network diagnostics consistently. | Navigation/accessibility matrix and equivalent event state on both clients. | M8 |
| MOB-010 | UI subscriptions and FFI operations shall be coarse, asynchronous and lifecycle-safe. | Background/recreation stress test shows no per-packet UI flood or leaked observer. | M8 |
| MOB-011 | Android shall create and export a PKCS#10 certificate request for the protected device identity. | The CSR verifies against the device Ed25519 key and contains exactly its full-fingerprint URI SAN; private material is never exported, and issued-certificate import is not implied. | M7 |

## Current Rust mobile boundary

`lattice-uniffi` opens local profiles through a caller-supplied platform key protector. It exposes the public identity snapshot, a DER PKCS#10 request signed by the protected device key, exact full-fingerprint peer pin creation, lookup, and idempotent local removal, bounded local Space Genesis pages with channel IDs, creation, text-message queueing and editing, bounded recent local history, offline full-cache text search, and local one-member recovery generation creation. Local pin removal does not revoke the remote identity or change Space membership. History and search include authorized incoming and locally authored messages retained by Core; search scans within the local cache quotas, accepts non-empty queries up to 256 UTF-8 bytes, and returns at most the 100 newest matches with exact counts. The queue APIs revalidate an RFC 9420 X.509 credential, authorize against an unchanged local Genesis policy, and commit immutable signed events, outbox rows, and encrypted local history. Recovery validates the supplied credential and prior local generation; it does not rejoin existing members or establish network membership. Android Compose currently displays the latest 100 locally retained messages and enables editing for queued outgoing rows; the full-cache search FFI is not yet wired into the screen. Network forwarding and recipient delivery remain unknown. No identity pin or queue result establishes Space membership.

UniFFI now exposes `join_space_from_welcome_bootstrap` with bounded package bytes, the exact pinned-inviter fingerprint, and X.509 credential content. Android exposes this through a Compose import form and refreshes the protected profile's local Space projection on success. The operation imports a signed current-policy checkpoint and validated MLS Welcome; it does not establish relay delivery or independently replay general history.

Android Gradle builds regenerate the checked-in Kotlin bindings from the host UniFFI library with the Android cleaner enabled, then build Rust libraries for `arm64-v8a` and `x86_64`. `:app:compileDebugKotlin`, `:app:testDebugUnitTest`, `:app:assembleDebug`, and `:app:lintDebug` pass. The debug APK archive contains `liblattice_uniffi.so` for both ABIs. Device behavior remains unverified: the available emulator reports `offline`, and a replacement emulator could not start because the existing instance holds the AVD lock.

Android now includes permission-checked GATT central/client and peripheral/server primitives. They require `BLUETOOTH_CONNECT` from Android 12 onward, gate inbound data callbacks after permission loss, provide best-effort GATT teardown, and bound characteristic payloads to the GATT attribute limit. The server accepts caller-provided services and the client accepts caller-provided characteristics; they do not assign protocol UUIDs, advertise, authenticate/encrypt, pace traffic, or reconnect. These primitives do not complete the device-level MOB-003 acceptance test.

Android also supports opt-in persistent nearby discovery through a connected-device foreground service and ongoing status notification. Starting it requires the relevant Bluetooth permissions and visible notification access; radio-off pauses scanning, while missing permissions on start/resume or an unavailable scanner stop the mode. Android's [connected-device foreground-service rules](https://developer.android.com/develop/background-work/services/fgs/service-types#connected-device) and [notification permission rules](https://developer.android.com/develop/ui/compose/notifications/notification-permission) still apply. The service only scans for a generic BLE service: it does not advertise, connect, authenticate peers, or exchange messages.

Android's Wi-Fi probe checks `PackageManager` feature flags for Wi-Fi Aware/Direct, current Aware service availability, the P2P system service, and the active default network's Wi-Fi/Ethernet transports. It labels missing hardware, missing path permission, and temporary unavailability separately; it refreshes when the default network changes. Wi-Fi permissions follow Android's [Wi-Fi Aware](https://developer.android.com/develop/connectivity/wifi/wifi-aware) and [Wi-Fi Direct](https://developer.android.com/develop/connectivity/wifi/wifip2p) API generations (`ACCESS_FINE_LOCATION` through API 32, `NEARBY_WIFI_DEVICES` from API 33). This is a local capability snapshot, not peer reachability. No Wi-Fi data adapter is active, so a probe never switches the route: Bluetooth discovery remains the baseline, and there is no connected data path to claim.

Primary screens: welcome/identity, profile/permissions, Space list, channel/thread, DM, voice, transfer center, members/roles, invite verification, relay/network state, local retention, diagnostics. Theme tokens can be shared; native semantics and accessibility remain platform-specific. [Android permission guidance](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions) and [Apple background guidance](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html) must be rechecked at release time.

## Native responsibilities by platform

| Concern | Android | iOS | Shared Rust |
| --- | --- | --- | --- |
| Nearby radio | Bluetooth permissions, GATT client/server, capability probe, optional foreground service | Core Bluetooth central/peripheral, background mode, Wi-Fi Aware entitlement, Network.framework | Envelope validity, route policy, sync and peer state |
| Keys | Keystore-backed wrapping where available | Keychain accessibility matched to lifecycle | Identity/MLS formats and key-use policy |
| Call | Audio focus/route, microphone, WebRTC engine | AVAudioSession/route, microphone, WebRTC engine | Voice authorization, signaling state |
| UI | Compose state/notifications | SwiftUI state/local notifications | Command result and projection subscription |

## Lifecycle matrix

Test freshly installed, permissions not determined, denied/revoked, app foreground, screen locked, OS-backgrounded, force-stopped, device rebooted, radio toggled and battery-restricted. An Android opt-in persistent mode shows a visible service and still obeys service-start limitations. iOS background restoration or a Live Activity must be treated as conditional capability, not an always-running daemon. Pending local events remain durable across process death; when a transport restarts, it reauthenticates paths and resumes summary exchange rather than trusting old sockets.

## UI and FFI operation contract

The view model calls coarse `send_message`, `create_space`, `observe_channel`, `join_voice` operations and receives immutable snapshots or bounded delta streams. It must not issue raw SQL or construct authenticated event bytes. Native adapters batch received buffers and observe backpressure rather than invoking one expensive cross-language callback per BLE fragment. UI recreation must cancel subscriptions and avoid duplicate notifications or messages. Rust errors map to actionable platform states: permission, storage, unsupported transport, missing epoch, denied policy or no route.

On Android, profile operations run on `Dispatchers.IO` inside `lifecycleScope`; cancellation is rethrown and UI publication checks that the Activity is still alive. Activity teardown closes the profile, while generated UniFFI handles keep in-flight calls alive and `MobileClient` serializes access with a Rust mutex. Android's current notification path is limited to the explicit persistent-scan status; it contains no peer or message content. Message notifications remain unavailable until a decrypted, authorized local projection is connected to a notification policy.

Accessibility is functional: TalkBack/VoiceOver labels for queued vs delivered, non-color status, focus order in message actions, enlarged text that keeps the composer usable, reduced motion and audio device announcements. Theme tokens may align color/spacing across clients, but native platform controls remain idiomatic.

The Android Compose screen scrolls vertically, uses scalable Material text/input styles and exposes major sections as headings. Space recovery and channel choices use labeled radio semantics for TalkBack selection. This is source-level support only; device TalkBack traversal and large-font behavior remain unverified while the available emulator is offline.
