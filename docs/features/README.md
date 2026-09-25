# Feature catalog

Each feature ID is also a functional requirement. A row has desired behavior, a pass condition, and an earliest build milestone. All are proposed except where explicitly blocked. The [central register](../REQUIREMENTS.md) owns shared `LAT` requirements; files below own the domain IDs. “MVP” means a testable implementation slice, not a security claim.

| Area | Prefix | Document | Scope |
| --- | --- | --- | --- |
| Identity | IDN | [identity.md](identity.md) | Installations, verification, invites, recovery |
| Spaces | SPC | [spaces.md](spaces.md) | Community membership, channels, roles, moderation |
| Messaging | MSG | [messaging.md](messaging.md) | DMs, text, threads, receipts, history |
| Networking | NET | [networking.md](networking.md) | BLE, direct paths, mesh, sync, relays |
| Files | FIL | [files.md](files.md) | Manifests, chunk transfer and resume |
| Voice | VOC | [voice.md](voice.md) | Small-room live audio and failure behavior |
| Mobile | MOB | [mobile.md](mobile.md) | Android/iOS radio, lifecycle and UI |
| Desktop | DSK | [desktop.md](desktop.md) | Tauri app and node controls |
| CLI | CLI | [cli.md](cli.md) | Commands, diagnostics, optional peer |

**Important distinction:** Space roles can restrict actions, but channel roles do not hide reads from other members of the same MLS Space. Cryptographically read-private channels are unsupported under [accepted ADR-002](../decisions/ADR-002-channel-read-semantics.md) and must fail closed if requested. The [ADR-001](../decisions/ADR-001-membership-commit-conflicts.md) fail-closed membership policy is accepted; conflict and recovery behavior still requires model/vector evidence. Read requirements with the [security model](../security/SECURITY_MODEL.md), not as standalone crypto claims.
