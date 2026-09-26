# Live voice — VOC

Voice rooms are ephemeral sessions in a Space. Authenticated Lattice events carry signaling; continuous media uses WebRTC/Opus on an ICE-selected IP path. The v1 target is **small rooms**, with a measured maximum after physical testing.

**Current delivery scope:** Android and desktop voice only; iOS is out of scope and is not a build or acceptance target.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| VOC-001 | Member with `VOICE_JOIN` shall join a permitted voice room and leave cleanly. | Denied/banned member cannot join valid session; empty-room incarnation changes ID. | M6 |
| VOC-002 | Signaling shall bind current Space/room/session, identity, permissions and MLS context. | Replay offer/ICE from old session or removed member is rejected. | M6 |
| VOC-003 | Audio shall use WebRTC secure RTP with Opus over eligible IP path, never BLE/relay event flooding. | Packet capture shows no continuous RTP-like stream on BLE/Nostr. | M6 |
| VOC-004 | User shall mute/deafen, see speaking state and select available audio devices. | Local mute stops outgoing microphone media; UI stays consistent after reconnect. | M6 |
| VOC-005 | ICE shall try viable direct paths and may use configured STUN/TURN under user policy. | LAN/direct NAT/TURN/no-TURN scenarios report path and result correctly. | M6 |
| VOC-006 | Call failure shall show path/permission reasons rather than falsely connecting. | Forced ICE failure transitions to actionable failure state. | M6 |
| VOC-007 | Moderation and `VOICE_SPEAK` policy shall be checked on join and changes. | Revoked permission stops participation under defined epoch/session semantics. | M6 |
| VOC-008 | Small-room topology shall publish a measured safe participant limit. | CPU/network/audio tests on defined Android and desktop matrix determine limit; no unlimited-room claim. | M8 |

Direct WebRTC peer connections can grow costly with group size; a volunteer SFU is deferred and requires its own trust and deployment ADR. [ICE RFC 8445](https://www.rfc-editor.org/rfc/rfc8445), [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656), and [Opus RFC 6716](https://www.rfc-editor.org/rfc/rfc6716) are the baseline references.
Current implementation is limited to `lattice-voice`'s bounded, caller-clocked signaling state machine. Each session gets an OS-cryptographic random incarnation and accepts only exact per-session control sequence numbers; controls with a stale incarnation, replayed/gapped sequence, denied join policy, invalid state, or expired deadline are rejected without advancing the control sequence. Caller-reported permission revocation, failure, leave, and deadline expiry are terminal, and later controls cannot restore the session. Permission checks are caller inputs, not policy evaluation or peer authentication; a denied operation is not itself evidence that permissions were revoked, so callers must report revocation explicitly. SDP and ICE are opaque strings checked for size and basic control/line structure, with fixed per-session bounds; they are not parsed, stored, sent, or connected. `SignalingConnected` records signaling completion only and is not call-connected or media-path evidence. No WebRTC, secure RTP, OS audio, or network/media backend is implemented.
The selected native media backend is libwebrtc, but the repository and available Gradle cache contain no pinned WebRTC SDK/binding or native SDK artifacts: no WebRTC Cargo dependency, Android AAR/`libwebrtc.so`, or desktop native library. `lattice-voice` remains signaling-only; no real native backend can be built or exercised from the current inputs, so no native lifecycle or media success is exposed. The backend requirements and currently configured in-scope targets are listed below. End-to-end use also requires authenticated Lattice signaling with identity, membership, permission-epoch, and MLS-context verification; Android/desktop permission, audio, lifecycle and device-route adapters; and real ICE/STUN/TURN policy. TURN requires server credentials and deployment policy. All VOC end-to-end and physical-device gates remain open.
The runtime flow and state/scalability sections below describe the target behavior, not implemented features.

## Target join-to-leave runtime

1. Check current Space membership, `VOICE_JOIN`, optional `VOICE_SPEAK`, local microphone permission and room incarnation.
2. Publish authenticated `VOICE_JOIN` over a current Lattice data path; presence is short-lived and never backfilled as durable room history.
3. Peers exchange versioned offer/answer and trickled ICE candidates bound to the room incarnation and session identity. Stale candidates/offers cannot join a new incarnation.
4. ICE nominates direct LAN/Wi-Fi/Internet path where possible. An explicitly configured TURN path is allowed by local policy if direct connectivity fails; show actual route class without exposing sensitive IP details by default.
5. WebRTC handles secure RTP and Opus; native audio layer handles interruption, Bluetooth headset, speaker changes, route loss and OS audio focus. A mute action must actually stop outgoing microphone media, not merely change an icon.
6. Leave or epoch/policy removal closes media, expires presence and releases microphone resources. After reconnection, authenticate a fresh room/session state before resuming.

## State and scalability

`not joined → requesting → negotiating → connected → reconnecting → ended/failed`. Distinguish denied permission, no path, ICE failure, microphone unavailable, peer left and application background interruption. For small rooms, each participant may have several peer connections; upload and CPU growth must be measured before setting a maximum. A future SFU would add a volunteer component with separate E2EE/media trust analysis, deployment policy and failure UX, not simply a larger toggle.

Voice signaling may traverse BLE or relay at modest volume, but a voice channel does **not** guarantee a call whenever text can be delivered: a continuous IP path and successful traversal are separate requirements.

## Native libwebrtc integration contract and build inputs

`lattice-voice` owns bounded signaling and caller-supplied policy only. A future adapter must own a real, version-pinned libwebrtc peer connection and native audio device path; this section is a contract, not an implemented adapter.

- Android is configured for API 26–37 and Java 17. The Rust mobile build targets `arm64-v8a` and `x86_64`. Supply a maintained, version-pinned Android WebRTC AAR (or equivalent reproducible native build inputs) containing `libwebrtc` for both ABIs and integrate it into the app build. The checked-in `jniLibs` currently contain only `liblattice_uniffi.so`; the Gradle app has no WebRTC dependency. A usable path also needs Android microphone permission declaration and runtime handling, plus libwebrtc's Android audio device integration.
- Desktop's Tauri bundle config requests all host bundle formats (`targets: all`) but does not pin a desktop OS/architecture support matrix. Each chosen release OS/architecture needs a matching libwebrtc binary or reproducible native build inputs, linked and packaged with the app, and platform audio device integration. `lattice-desktop` currently has no native WebRTC dependency.
- For every target, pin the SDK release/revision and checksums and provide the build inputs required by that distribution. If building libwebrtc from source, provide its matching source revision and Chromium build toolchain; if consuming prebuilt SDKs, provide and package the matching ABI artifacts. A Rust binding alone is insufficient without its native library.

The adapter must create/configure the peer connection, apply local and remote descriptions, add ICE candidates, and observe actual native peer-connection and ICE state. `SignalingConnected`, SDP acceptance, candidate presence, or a caller-supplied permission value must never be reported as media-connected or peer-authenticated. Keep join/speak authorization separate from identity/membership/MLS authentication; gate microphone capture and outgoing audio on current local permission and native platform grant; map real ICE/path and microphone failures to failure states; and close peer connections and release audio resources on leave, expiry, or permission revocation. A connected call indication requires an observed usable ICE path and a functioning native audio path, not merely successful signaling. Device/audio permission denial and failed route negotiation must stay explicit failures.

No target can exercise that contract until its native SDK artifacts and platform audio/permission integration are present. The WebRTC SDK release/revision, target library artifacts, authenticated signaling bridge, platform permission/audio adapters, and TURN credentials/policy are currently unspecified or absent; they must be supplied before an actual libwebrtc lifecycle can be built or truthfully exercised.
