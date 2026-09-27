# ADR-001: fail closed on competing MLS commits

Status: accepted
Date: 2026-09-24
Requirements: SPC-006–007, LAT-007

## Context and threat

MLS epochs are linear, but partitions can produce valid competing commits. Wall-clock order, arrival order, and relay order are not consensus. Picking a branch silently can fork membership and authorization or retain secrets after removal. The initial clients are peer-to-peer and have no trusted sequencer. RFC 9750 §5.2 describes concurrency strategies but does not choose Lattice's application policy.

## Options considered

1. Add a sequencer or quorum authority, which conflicts with operation without a central account/service and still requires quorum availability.
2. Select a deterministic commit hash and recover the losing branch, which requires a complete dependency, Welcome, secret-deletion, and losing-branch delivery protocol not specified or independently verified here.
3. Accept only commits based on the single locally current epoch; retain evidence of valid conflicts, freeze sensitive mutations, and require explicit new-group rejoin to recover.

## Decision and exact scope

Choose option 3. A membership-changing commit MUST identify the locally current parent epoch and MUST pass MLS validation. A missing parent is pending. A valid commit based on another branch is recorded as conflict evidence, not applied. When two valid successors to the same epoch are observed, the group becomes `conflicted`; no client may select a winner using time, hash, arrival, or role. Membership/authorization-sensitive operations stop until recovery. Recovery creates a new MLS group through fresh explicit invitations by a currently verified administrator; it does not merge conflicting state, reissue old Welcome messages, or claim to restore omitted history. Old state remains read-only as allowed by key-retention policy. Implementations must not advertise concurrent membership-change convergence.

This profile can support sequential changes when participants have the same authenticated epoch. Partitioned or simultaneous changes intentionally sacrifice availability rather than invent consensus. A future profile may supersede this decision with a reviewed protocol and public vectors.

## Consequences and migration

Clients expose pending/conflict state and retain bounded authenticated evidence for diagnostics. They never project a member add/remove from an unaccepted branch. Old code that used timestamps or local arrival order for membership decisions is incompatible and must be removed. A recovery creates new group cryptographic state and does not silently copy inaccessible history.

## Required vectors, tests, and rollback

Test a missing parent as pending, an invalid commit as rejected, same-parent competing valid successors as explicit conflict on every permutation, absence of wall-clock branch selection, and recovery into a new group without accepting old-branch changes. No implementation may claim ADR-001 is behaviorally verified until these tests exist. Rollback disables membership mutation rather than reverting to arrival-order selection.

## References

- [RFC 9750 §5.2](https://www.rfc-editor.org/rfc/rfc9750#section-5.2)
- [Lattice protocol profile](../protocol/PROTOCOL.md#membership-and-conflict)
- [Lattice security model](../security/SECURITY_MODEL.md)
