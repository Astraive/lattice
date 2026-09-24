# Lattice requirements register

**Status:** proposed v0.1. “Shall” denotes desired behavior for the indicated release; it does not assert implementation. Each requirement has a stable ID and a concrete pass condition. `M0`–`M8` refer to [PLAN.md](PLAN.md).

## ID registry

| Prefix | Domain | Source file | Range |
| --- | --- | --- | --- |
| `LAT` | System-wide functional/nonfunctional constraints | This file | LAT-001–LAT-020 |
| `IDN` | Identity and onboarding | [identity.md](features/identity.md) | IDN-001–IDN-008 |
| `SPC` | Spaces, roles, permissions | [spaces.md](features/spaces.md) | SPC-001–SPC-011 |
| `MSG` | Text, DMs, history | [messaging.md](features/messaging.md) | MSG-001–MSG-012 |
| `NET` | Discovery, routing, relays, sync | [networking.md](features/networking.md) | NET-001–NET-013 |
| `FIL` | Attachments and transfer | [files.md](features/files.md) | FIL-001–FIL-007 |
| `VOC` | Voice and media | [voice.md](features/voice.md) | VOC-001–VOC-008 |
| `MOB` | Native Android/iOS behavior | [mobile.md](features/mobile.md) | MOB-001–MOB-010 |
| `DSK` | Desktop | [desktop.md](features/desktop.md) | DSK-001–DSK-006 |
| `CLI` | CLI and node | [cli.md](features/cli.md) | CLI-001–CLI-010 |

IDs are never renumbered. A row is one independently testable requirement; amend the row and history when semantics change. Status values: **proposed**, **blocked**, **implemented**, **verified**, **retired**. All rows begin proposed unless explicitly blocked. `M0`–`M2` prototype work does not make the wider v1 profile stable.

## Cross-cutting requirements

| ID | Requirement | Acceptance evidence | Gate |
| --- | --- | --- | --- |
| LAT-001 | Basic nearby Space text shall operate with DNS and Internet denied and no project account. | Two physical devices create/join and exchange text with networking blocked except Bluetooth. | M2 |
| LAT-002 | An authenticated event shall retain its ID and projection semantics across transport and re-envelopment. | Identical event over BLE/LAN/relay yields one stored event and identical projection. | M5 |
| LAT-003 | All accepted remote mutations shall pass canonical, signature/MLS, causal and policy checks before projection. | Invalid/reordered/forged corpus never creates an authorized view. | M3 |
| LAT-004 | Local send shall commit durably before any networking and expose queued/forwarded/delivered/read distinctly. | Crash/restart and relay-acceptance tests show no false destination receipt. | M1 |
| LAT-005 | No carrier, courier or relay shall act as authoritative Space state. | Removing every relay still permits a reachable peer pair to create/send/sync. | M5 |
| LAT-006 | All parser sizes, peer queues, relay/courier copies and radio work shall have enforced limits. | Malformed and flood tests stay inside published memory/disk/radio budgets. | M8 |
| LAT-007 | Accepted replicas with identical valid dependencies shall project identical state regardless of event arrival order, within the approved conflict policy. | Permutation/property tests across partition traces; MLS conflicts use ADR-001. | M3 |
| LAT-008 | Users shall see actual connectivity/degraded capability, with no globally authoritative online indicator. | Background, missing permission, absent relay and partition UI scenarios. | M2 |
| LAT-009 | Local secret material shall use platform-protected storage, with actual hardware protection reported honestly. | Storage inspection and secure-storage failure tests per device family. | M3 |
| LAT-010 | No plaintext Space body, stable Lattice key or nickname shall be emitted in unauthenticated BLE advertising or relay payload. | Packet and relay captures; metadata leakage documented separately. | M8 |
| LAT-011 | Protocol version/capability negotiation shall reject unknown mandatory semantics. | Mixed-version vectors fail closed and supported optional fields interoperate. | M8 |
| LAT-012 | A user shall be able to create a Space, send text and consult locally retained history while disconnected. | Offline creation, restart and search smoke test. | M3 |
| LAT-013 | Accessible navigation, labels, keyboard support and scalable text shall work on shipped clients. | Screen-reader/keyboard/text-scale matrix; voice status not color-only. | M8 |
| LAT-014 | No app-controlled telemetry endpoint shall be required for product operation. | Deny all project domains; functionality and local diagnostics remain available. | M8 |
| LAT-015 | Content deletion and member removal shall not be presented as retroactive remote erasure. | UX copy and malicious-retention scenario checked. | M3 |
| LAT-016 | Radio/voice/background behavior shall adapt to supported OS permissions, entitlements and lifecycle states. | Physical Android/iOS foreground/background/restart matrix. | M2 |
| LAT-017 | Normal operations shall not silently require a specific volunteer node, relay or TURN provider. | Tests remove each optional component; expected degraded capabilities are explicit. | M6 |
| LAT-018 | A stable protocol release shall include public vectors, migration path, fuzz coverage and interop results. | Release checklist and clean-room decoder reproduce canonical IDs. | M8 |
| LAT-019 | Logs and diagnostic exports shall exclude plaintext, keys and unnecessary identifiers by default. | Automated redaction fixture review and manual capture audit. | M8 |
| LAT-020 | Security and performance claims shall be scoped to tested devices, adversaries and measurement methods. | Release notes cite test matrix and unresolved limitations. | M8 |

## Release scope and traceability

| Scope | Required IDs | Gate |
| --- | --- | --- |
| Prototype | LAT-001–004, IDN-001–003, SPC-001–003, MSG-001–003, NET-001–005, MOB-001–004 | M0–M2 |
| Interoperable security core | LAT-003,007,009,015, IDN-004–008, SPC-004–011, MSG-004–009 | M3 |
| Local files/fast paths | NET-006–008, FIL-001–007 | M4 |
| Optional Internet | NET-009–013, DSK-001–006, CLI-001–009 | M5/M7 |
| Voice | VOC-001–008 | M6 |
| Stable v1 | All non-deferred items and every LAT security/release gate | M8 |

This register intentionally does not invent per-device performance guarantees. Targets from the integrated spec become benchmark thresholds only after workload and device matrix are fixed in [TEST_PLAN.md](quality/TEST_PLAN.md). Use [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) terminology only in versioned normative protocol documents.
