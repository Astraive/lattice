# Architectural decisions and unresolved choices

This index tracks accepted decisions and unresolved choices. Each accepted choice links to an ADR recording its context, alternatives, decision, consequences, validation, and status; entries without an accepted decision remain open work.

| ADR | Issue | Current safe rule | Blocking IDs | Gate |
| --- | --- | --- | --- | --- |
| ADR-001 | Concurrent MLS Commit order, policy conflict, fork recovery | Accepted fail-closed policy: no winner selection; conflict blocks mutations and requires new-group recovery. | SPC-006–007, LAT-007 | Accepted; implementation evidence pending |
| ADR-002 | Does channel privacy include read confidentiality from other Space members? | Accepted policy-only channel access; read-private channel types are unsupported. | SPC-011, LAT-003 | Accepted; implementation evidence pending |
| ADR-003 | Relay kind, tags, outer identity, expiration/size and backfill | Accepted Nostr mailbox candidate with stable per-generation tag; no interop or deletion claim. | NET-010 | Candidate accepted; two-relay evidence pending |
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

**MLS trust and recovery:** What independent credential verifier and pinning model qualifies a device as a trusted recovery administrator? How are staged-Commit and conflict-evidence records authenticated and recovered across process/device restart without reactivating an ambiguous branch?

**Relay interoperability:** Which independent NIP-01 implementations and relays will run the required candidate vectors, and how will operators verify advertised NIP-11 message limits in practice? The profile itself remains optional until this evidence passes.

**Snapshots:** Who can sign a snapshot, how is its event frontier proven, how can a late peer distinguish authorized compaction from censored history, and how is conflicting snapshot evidence reported? A small device cannot retain unlimited history, but it also cannot trust an unverified volunteer node as authoritative.

**Radio privacy:** What is the token rotation window, advertising footprint and receiver dedupe model across OS states? Do trusted-contact rendezvous hints reintroduce linkability? Captures and threat analysis must precede claims of unlinkability.
