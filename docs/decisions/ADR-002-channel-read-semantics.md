# ADR-002: channel access is not cryptographic read isolation

Status: accepted
Date: 2026-09-24
Requirements: SPC-005, SPC-011

## Context and threat

All members of a Space MLS group can derive that group's application secrets. A channel label, UI permission, or Space-wide exporter cannot conceal channel plaintext from a malicious Space member. A second independent MLS group or a reviewed subordinate key protocol would add membership, recovery, offline synchronization, and key-deletion state not present in the current profile.

## Options considered

1. Restrict channel read/write visibility with app policy while acknowledging that every Space member holding Space MLS state can decrypt shared Space content.
2. Create a separate MLS group per channel with explicit join/removal and a tested atomic relationship to Space membership.
3. Design and independently review a subordinate channel-key protocol.

## Decision and exact scope

Choose option 1 for this profile. A channel may apply authorization rules for who can send, attach, moderate, or join voice. It MUST NOT be advertised, rendered, exported, or serialized as read-private or confidential from other active Space members. UI controls and policy denial do not imply confidentiality. All Space members in the same MLS epoch are within the content key trust boundary. Read-private channels are unsupported and MUST fail closed if requested as a required feature.

## Consequences and migration

Remove or reject any read-private channel type, key icon, or privacy claim that lacks separate cryptographic membership. Existing channel metadata remains a logical view and policy scope; it is not an independent encryption domain. A future independent-group design requires a superseding ADR, group lifecycle protocol, public vectors, and removal/partition tests.

## Required vectors, tests, and rollback

Verify that channel authorization only gates actions, no API labels this mode read-private, and unknown required read-isolation capability is rejected. Rollback removes the unsupported feature; it never silently weakens its confidentiality semantics.

## References

- [Space and channel requirements](../features/spaces.md#channel-types-and-privacy-semantics)
- [Lattice security model](../security/SECURITY_MODEL.md#cryptographic-layers)
