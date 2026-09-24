# Live voice — VOC

Voice rooms are ephemeral sessions in a Space. Authenticated Lattice events carry signaling; continuous media uses WebRTC/Opus on an ICE-selected IP path. The v1 target is **small rooms**, with a measured maximum after physical testing.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| VOC-001 | Member with `VOICE_JOIN` shall join a permitted voice room and leave cleanly. | Denied/banned member cannot join valid session; empty-room incarnation changes ID. | M6 |
| VOC-002 | Signaling shall bind current Space/room/session, identity, permissions and MLS context. | Replay offer/ICE from old session or removed member is rejected. | M6 |
| VOC-003 | Audio shall use WebRTC secure RTP with Opus over eligible IP path, never BLE/relay event flooding. | Packet capture shows no continuous RTP-like stream on BLE/Nostr. | M6 |
| VOC-004 | User shall mute/deafen, see speaking state and select available audio devices. | Local mute stops outgoing microphone media; UI stays consistent after reconnect. | M6 |
| VOC-005 | ICE shall try viable direct paths and may use configured STUN/TURN under user policy. | LAN/direct NAT/TURN/no-TURN scenarios report path and result correctly. | M6 |
| VOC-006 | Call failure shall show path/permission reasons rather than falsely connecting. | Forced ICE failure transitions to actionable failure state. | M6 |
| VOC-007 | Moderation and `VOICE_SPEAK` policy shall be checked on join and changes. | Revoked permission stops participation under defined epoch/session semantics. | M6 |
| VOC-008 | Small-room topology shall publish a measured safe participant limit. | CPU/network/audio tests on defined mobile matrix determine limit; no unlimited-room claim. | M8 |

Direct WebRTC peer connections can grow costly with group size; a volunteer SFU is deferred and requires its own trust and deployment ADR. [ICE RFC 8445](https://www.rfc-editor.org/rfc/rfc8445), [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656), and [Opus RFC 6716](https://www.rfc-editor.org/rfc/rfc6716) are the baseline references.
Current implementation is limited to `lattice-voice`'s bounded, caller-clocked signaling state machine. It validates sequence, incarnation, permission inputs, expiry and SDP/candidate size but does not authenticate peers, process signaling over Lattice, parse ICE/SDP, establish WebRTC, handle media/audio, or expose an implemented media path. `SignalingConnected` is not call-connected evidence; all VOC end-to-end and physical-device gates remain open.

## Join-to-leave runtime

1. Check current Space membership, `VOICE_JOIN`, optional `VOICE_SPEAK`, local microphone permission and room incarnation.
2. Publish authenticated `VOICE_JOIN` over a current Lattice data path; presence is short-lived and never backfilled as durable room history.
3. Peers exchange versioned offer/answer and trickled ICE candidates bound to the room incarnation and session identity. Stale candidates/offers cannot join a new incarnation.
4. ICE nominates direct LAN/Wi-Fi/Internet path where possible. An explicitly configured TURN path is allowed by local policy if direct connectivity fails; show actual route class without exposing sensitive IP details by default.
5. WebRTC handles secure RTP and Opus; native audio layer handles interruption, Bluetooth headset, speaker changes, route loss and OS audio focus. A mute action must actually stop outgoing microphone media, not merely change an icon.
6. Leave or epoch/policy removal closes media, expires presence and releases microphone resources. After reconnection, authenticate a fresh room/session state before resuming.

## State and scalability

`not joined → requesting → negotiating → connected → reconnecting → ended/failed`. Distinguish denied permission, no path, ICE failure, microphone unavailable, peer left and application background interruption. For small rooms, each participant may have several peer connections; upload and CPU growth must be measured before setting a maximum. A future SFU would add a volunteer component with separate E2EE/media trust analysis, deployment policy and failure UX, not simply a larger toggle.

Voice signaling may traverse BLE or relay at modest volume, but a voice channel does **not** guarantee a call whenever text can be delivered: a continuous IP path and successful traversal are separate requirements.
