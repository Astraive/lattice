# Architectural decisions and unresolved choices

This index tracks decisions. Create one `ADR-xxx-title.md` per resolved item with **context → alternatives → decision → consequences → validation → date/status**; retain superseded ADRs. Until then, these entries are explicit open work, not hidden decisions.

| ADR | Issue | Current safe rule | Blocking IDs | Gate |
| --- | --- | --- | --- | --- |
| ADR-001 | Concurrent MLS Commit order, policy conflict, fork recovery | Accepted fail-closed policy: no winner selection; conflict blocks mutations and requires new-group recovery. | SPC-006–007, LAT-007 | Accepted; implementation evidence pending |
| ADR-002 | Does channel privacy include read confidentiality from other Space members? | Accepted policy-only channel access; read-private channel types are unsupported. | SPC-011, LAT-003 | Accepted; implementation evidence pending |
| ADR-003 | Relay kind, tags, outer identity, expiration/size and backfill | Experimental relay profile only; no Nostr-wide interop claim. | NET-010 | M5 |
| ADR-004 | Snapshot provenance, compaction, retention and history recovery | Retain dependencies; surface gaps rather than accepting unverifiable snapshot. | MSG-011, LAT-007 | M8 |
| ADR-005 | Rotating BLE advertisement/rendezvous token design | Avoid stable app identity, but do not claim anonymity/unlinkability. | NET-001, LAT-010 | M2/M8 |
| ADR-006 | One human on multiple devices and key recovery | Each installation is a separate v1 MLS member. | IDN-006 | After v1 |
| ADR-007 | Room topology and future SFU trust | Small measured peer topology only; no unlimited conference. | VOC-008 | M6/M8 |

## Existing baseline decisions

Native Kotlin/Swift mobile; shared Rust core/UniFFI; Tauri/React desktop; Rust CLI; SQLite local log; deterministic event ID independent of carrier; BLE text/control; supported local IP for bulk; optional untrusted Nostr-compatible mailbox; MLS group security; reviewed Noise link sessions; WebRTC/Opus voice. These are architectural baselines, not proof that a specific library or hardware combination passes verification.

## ADR-001 implementation gate

The policy is accepted in [ADR-001](ADR-001-membership-commit-conflicts.md): a current-epoch linear commit is the only automatically applied change. Missing dependencies stay pending; valid conflicting successors freeze mutation and require explicit new-group recovery. There is no timestamp/hash/arrival winner. Code and permutation vectors remain required before enabling membership changes.

## ADR-002 implementation gate

The policy is accepted in [ADR-002](ADR-002-channel-read-semantics.md): channel roles can restrict actions, but all active Space MLS members remain inside the read trust boundary. Read-private channels are unsupported; code and capability tests must reject them.

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
