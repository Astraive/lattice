# Lattice execution TODO

**Status:** backlog, not implementation progress. Check boxes change only with linked evidence. Priorities: P0 blocks the next milestone; P1 required for v1; P2 later optimization. IDs in parentheses trace to requirements or decisions.

## P0 — before writing interoperable v1 code

- [ ] Define exact canonical CBOR/event/envelope preimages, size bounds, domain strings and public vectors. (LAT-002, LAT-003, NET-003; M0)
- [ ] Choose initial Noise pattern/profile, transcript binding and reviewed implementation; add handshake vectors. (IDN-001, NET-002; M0)
- [ ] Define immutable event/MLS-state transaction boundary and crash recovery. (LAT-003, SPC-006; M0/M3)
- [ ] Build seeded fake-clock/transport harness and reordered/duplicate corpus. (LAT-007, NET-005; M0)
- [ ] Create Android BLE GATT spike with physical hardware and no Internet. (MOB-002–003, NET-001–002; M1)
- [ ] Decide ADR-001 competing MLS Commit ordering, Welcome coupling and losing-branch behavior before secure Spaces. (SPC-006–007; M3)
- [ ] Decide ADR-002 whether channel privacy restricts reads, and choose independent keying if so. (SPC-011; M3)
- [ ] Specify signed Space genesis, membership/policy payloads, permission-bit IDs, causal conflicts, and MLS credential/group transaction binding. (SPC-001–010, LAT-003, LAT-007; M3)

## P1 — functional build sequence

- [ ] Wire Android Compose → UniFFI → Rust core with local SQLite outbox. (MOB-001, MSG-001–003; M1)
- [ ] Test three-device Android store/carry/sync under app restart. (NET-004–005; M1/M2)
- [ ] Implement signed invite, verification, KeyPackage lifecycle and member rekey. (IDN-004–008, SPC-003,006; M3)
- [ ] Implement role/policy reducer and adversarial concurrency tests. (SPC-004–010, LAT-007; M3)
- [ ] Implement DMs, edits, tombstones, threads, reactions, mentions and local search. (MSG-004–012; M3)
- [ ] Probe/upgrade local IP paths and resume hash-verified attachments. (NET-006–008, FIL-001–007; M4)
- [ ] Freeze relay kind, retrieval tags and outer identity profile in ADR-003 before public interop claims. (NET-010; M5)
- [ ] Implement two-relay encrypted mailbox tests with drop/reorder and metadata capture. (NET-009–013; M5)
- [ ] Implement WebRTC signaling, direct/TURN matrix and room-size gate. (VOC-001–008; M6)
- [ ] Build Tauri and Rust CLI atop core, plus opt-in bounded node mode. (DSK-001–006, CLI-001–009; M7)
- [x] Add bounded read-only local Space Genesis pages to the CLI. (CLI-009)
- [ ] Perform mobile power/background, parser fuzzing, migration, security and accessibility gates. (LAT-006,009–020; M8)

## P2 — tracked later or conditional

- [ ] Define multi-device human identity/recovery if adopted after device-scoped v1. (ADR-006)
- [ ] Research dedicated mailbox adapter if Nostr kind/retrieval/privacy constraints prove unsuitable. (ADR-003)
- [ ] Study large-room SFU with separate end-to-end media/trust requirements. (VOC-008)
- [ ] Define signed snapshot/compaction proof before aggressively pruning old state. (ADR-004)
- [ ] Evaluate private rendezvous tokens against radio correlation attacks. (ADR-005)

## Update rule

When completing an item, link its code revision, device/test result, protocol vector or ADR in the issue tracker. Keep this backlog concise; detailed implementation subtasks belong in issues. ADR-001 and ADR-002 policies are accepted; keep M3/M8 open until required conflict, recovery, channel-capability, and release evidence passes.

## Subsystem completion checklists

**Protocol:** canonical encodings and negative vectors; ID collision/equivocation handling; feature negotiation; Noise transcript; MLS serialization and concurrent Commit recovery; separate event/envelope IDs; size limits; gap repair; snapshot trust.

**Storage:** authored sequence reservation; atomic local event/outbox commit; receive insert/projection; pending dependency queue; key/DB crash journal; migrations; history retention; file temp cleanup; search-index purge.

**Mobile:** Android central/peripheral GATT and permissions; radio duty cycle and battery capture; Android device matrix; supported/unsupported Wi-Fi Aware; foreground/background UI; secure-storage behavior; audio interruptions. iOS-specific design material is not a current implementation or acceptance task.

**Community:** signed genesis and invite; KeyPackage/Welcome; role hierarchy; channel overrides; moderation, bans and removal; message editing/tombstones/threads; DMs; protected private-channel key semantics.

**Delivery:** direct BLE, LAN/aware upgrade, courier limits, sender outbox, anti-entropy, relay profile/two-relay tests, metadata analysis and honest receipt state.

**Release:** fuzz every untrusted decoder; benchmark bounded memory/power; test clean installation and previous stable migration; accessibility; redacted diagnostic export; sign builds; obtain external crypto/protocol review; publish limitations and device matrix.

This checklist expands the ID-linked work queue above; no item is marked complete without acceptance evidence recorded in [TEST_PLAN.md](quality/TEST_PLAN.md).
