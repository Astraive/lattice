# Architectural decisions and unresolved choices

This index tracks decisions. Create one `ADR-xxx-title.md` per resolved item with **context → alternatives → decision → consequences → validation → date/status**; retain superseded ADRs. Until then, these entries are explicit open work, not hidden decisions.

| ADR | Issue | Current safe rule | Blocking IDs | Gate |
| --- | --- | --- | --- | --- |
| ADR-001 | Concurrent MLS Commit order, policy conflict, fork recovery | No claim of secure convergence under simultaneous membership changes; keep explicit conflict/pending state. | SPC-006–007, LAT-007 | M3 |
| ADR-002 | Does channel privacy include read confidentiality from other Space members? | Do not advertise read-private channel using only Space exporter material. | SPC-011, LAT-003 | M3 |
| ADR-003 | Relay kind, tags, outer identity, expiration/size and backfill | Experimental relay profile only; no Nostr-wide interop claim. | NET-010 | M5 |
| ADR-004 | Snapshot provenance, compaction, retention and history recovery | Retain dependencies; surface gaps rather than accepting unverifiable snapshot. | MSG-011, LAT-007 | M8 |
| ADR-005 | Rotating BLE advertisement/rendezvous token design | Avoid stable app identity, but do not claim anonymity/unlinkability. | NET-001, LAT-010 | M2/M8 |
| ADR-006 | One human on multiple devices and key recovery | Each installation is a separate v1 MLS member. | IDN-006 | After v1 |
| ADR-007 | Room topology and future SFU trust | Small measured peer topology only; no unlimited conference. | VOC-008 | M6/M8 |

## Existing baseline decisions

Native Kotlin/Swift mobile; shared Rust core/UniFFI; Tauri/React desktop; Rust CLI; SQLite local log; deterministic event ID independent of carrier; BLE text/control; supported local IP for bulk; optional untrusted Nostr-compatible mailbox; MLS group security; reviewed Noise link sessions; WebRTC/Opus voice. These are architectural baselines, not proof that a specific library or hardware combination passes verification.

## Resolve ADR-001 before membership implementation

Compare (a) a short wait window with deterministic Commit tie break and (b) immediate speculative application with bounded prior-state retention and rollback. Specify sequence and validation order; simultaneous add/remove precedence; dependencies/proposals; losing-branch messages; Welcome coupling; old secret deletion; recovery after long partitions; malicious invalid Commit; and test vectors. [RFC 9750 §5.2](https://www.rfc-editor.org/rfc/rfc9750#section-5.2) is primary guidance. Avoid an unreviewed local-wall-time winner.

## Resolve ADR-002 before naming a private channel

Option A: Space-wide MLS keys with action-only permissions, meaning every Space member with group secrets can derive channel ciphertext. Option B: per-channel MLS membership with explicit add/remove/rekey. Option C: a reviewed subordinate key distribution protocol with equivalent isolation. Compare state size, join/remove complexity, offline sync and cryptographic review burden. Select semantics first, then implementation.

## ADR governance

Link each accepted decision to requirements, architecture, protocol profile, vectors, tests, and release note. If later changed, write a superseding ADR with migration behavior; never erase history. [ADR practice](https://docs.aws.amazon.com/prescriptive-guidance/latest/architectural-decision-records/best-practices.html).

## Decision template

```markdown
# ADR-xxx: short decision title
Status: proposed | accepted | superseded
Date: YYYY-MM-DD
Requirements: IDs

## Context and threat/quality requirement
## Options considered
## Chosen rule and exact scope
## Consequences and migration
## Required vectors, tests and rollback
## References and supersedes
```

## Questions with no safe implicit answer

**MLS ordering:** Do we wait a bounded time for competing Commits, or apply speculatively and retain the previous epoch? How do disconnected peers agree on tie-break bytes? Who signs/publishes branch resolution? What do we do with content already sent on the losing branch? How long can an old secret be retained without undermining forward secrecy? Which Welcome should a new member process? What if the tie-break winning Commit is invalid to one replica because policy state diverged?

**Channel confidentiality:** Does “read-private” hide ciphertext from Space members or simply hide the UI/deny normal reads? If separate group, how are member changes synchronized between Space and channel groups, how many groups per device, and how are old messages handled? If subordinate keys, who distributes them in a partition and how are they revoked? No choice is free of state and recovery costs.

**Relay privacy:** What tags enable retrieval without exposing Space identity? How are Nostr outer keys rotated while retaining queued mail? What is the largest relay-acceptable envelope and what happens when relay rejects it? Do relays support expiration, or must recipients ignore it? What is the user-visible statement about IP/timing/subscription metadata?

**Snapshots:** Who can sign a snapshot, how is its event frontier proven, how can a late peer distinguish authorized compaction from censored history, and how is conflicting snapshot evidence reported? A small device cannot retain unlimited history, but it also cannot trust an unverified volunteer node as authoritative.

**Radio privacy:** What is the token rotation window, advertising footprint and receiver dedupe model across OS states? Do trusted-contact rendezvous hints reintroduce linkability? Captures and threat analysis must precede claims of unlinkability.
