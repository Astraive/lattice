# Spaces, channels and permissions — SPC

A Space is a replicated membership and policy domain with authenticated genesis and MLS state. A channel is a logical view; voice and text differ in runtime behavior. The v1 prototype may start with a single text channel, but it must not imply unrestricted v1 authorization.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| SPC-001 | A device shall create a random-ID Space and signed genesis locally while offline. | Two equal display names yield different IDs; genesis verifies on a joining device. | M1 |
| SPC-002 | A Space shall contain ordered text and voice channel metadata and announcement type. | Authorized create/rename/archive operations converge after reorder. | M1/M3 |
| SPC-003 | A joining device shall verify genesis/inviter and be explicitly added by authorized member. | Forged invite or unapproved KeyPackage cannot produce visible member. | M2/M3 |
| SPC-004 | Roles shall include owner/admin/moderator/member plus custom permission masks. | Effective permission computed consistently on two replicas. | M3 |
| SPC-005 | Channel overrides shall gate send/attach/voice actions without bypassing Space rules. | Denied author event is rejected after sync, including from a stale UI. | M3 |
| SPC-006 | Add/remove/ban shall bind an authorized event to a valid MLS transition. | Removed device cannot decrypt later valid epoch messages; earlier data remains accessible. | M3 |
| SPC-007 | Concurrent privileged operations shall use agreed causal policy and explicit conflict state. | Partition permutation tests converge or show a defined conflict; no timestamp winner. | M3; ADR-001 |
| SPC-008 | Moderators shall tombstone content and record distinguishable moderation action. | Authorized moderation hides normal view; invalid moderator cannot. | M3 |
| SPC-009 | Invite policy shall support expiry and optional use limits without relying on relay truth. | Expired/wrong-policy invitations fail on peer sync; offline simultaneous uses defined. | M3 |
| SPC-010 | Member lists shall distinguish active member, pending join, removed, banned and unsynchronized state. | Two partitions show honest local status and resolve after synchronization. | M3 |
| SPC-011 | Channels advertised as read-private shall have keys unavailable to other Space members. | Non-member Space device cannot derive channel content key; blocked until ADR-002. | M3; ADR-002 |

Representative permissions: Space/channel/role manage; invite/remove/ban; message send/attach/moderate; thread create; mention everyone; pin; join/speak/moderate voice; retention; relay recommendation. Custom roles are bitsets over versioned permission identifiers, not arbitrary scripts. Space relay recommendations never override an installation’s network policy. See [architecture.md](../architecture.md#7-security-membership-and-authorization) and [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750) for application access-control responsibilities.

## Space state model

`unseen → invited → join pending → active → leaving/removed/banned` is the local membership view. A join request can be pending while an inviter is offline. A removal can be valid in one partition while another member still operates on an older epoch; clients represent this as unsynchronized or conflicting, never universal instantaneous revocation. Each installation is a distinct cryptographic leaf. The Space genesis binds random ID, protocol version, creator, policy baseline, channel baseline and MLS group parameters. Changes occur through authenticated immutable events, not direct row edits.

The current Rust core creates a one-member candidate generation, atomically persists its signed Genesis event and encrypted initial-policy snapshot, lists snapshots in bounded 32-entry keyset pages, and restores each generation after rechecking its event, protected MLS group, and snapshot authentication. `SpaceReducer::authorize_recovery_genesis` authorizes a new group root from the prior generation's retained common policy when its creator has `SPACE_MANAGE` and `MEMBER_INVITE`; the proof is bound to that exact MLS-authenticated root event. The core can atomically validate a parent-epoch MemberTransition against the exact staged Commit and MLS-authenticated KeyPackage digest, merge that Commit, and store both exact signed event records with AEAD-protected replay evidence. Restore replays accepted transitions and their intervening policy events when every MLS epoch from Genesis has a recorded transition. Distinct valid sibling Commits are durably recorded with their exact signed controls and revalidated on restore; neither branch is applied, and the conflicted generation blocks message and membership mutations. An authorized owner can create and restore a one-member recovery generation from retained common policy. It preserves channel descriptors supported by the recovery schema, drops custom-role definitions, resets membership to the owner, and rejects restoration chains deeper than 32 generations. Existing members do not automatically rejoin; new invitations/Welcome joins, standalone policy history, and epochs committed outside the accepted-transition path remain unsupported.

## Authorization algorithm

For each privileged event, load its declared causal dependencies and relevant accepted policy epoch, verify author signature/MLS provenance, check that the required permission is held at that context, then apply the operation in a deterministic state machine. A remote wall timestamp and the author’s current UI role are insufficient. Concurrent role removal and channel action need a specified causal outcome; if the safe policy cannot order them, persist an explicit conflict until an authorized resolution. An owner cannot merely pick a branch by having the newest device clock.

| Operation | Required permission | Additional constraints |
| --- | --- | --- |
| Create/archive/rename channel | `CHANNEL_MANAGE` | Immutable channel ID; no reuse after tombstone. |
| Define or edit role | `ROLE_MANAGE` | Prevent policy self-escalation under stale state; protect owner invariant. |
| Invite/add member | `MEMBER_INVITE` | Validate invite/genesis/credential/KeyPackage and corresponding MLS Commit. |
| Remove/ban member | `MEMBER_REMOVE`/`MEMBER_BAN` | MLS epoch transition and prospective-key exclusion. |
| Publish message/attachment | `MESSAGE_SEND`/`MESSAGE_ATTACH` | Apply channel override, membership and retention bounds. |
| Author delete | `MESSAGE_SEND` | Tombstone the author's own message. |
| Moderator removal | `MESSAGE_MODERATE` | Preserve a reason-bearing moderator event and audit lineage. |
| Join/speak in voice | `VOICE_JOIN`/`VOICE_SPEAK` | Evaluate current room incarnation and membership state. |

## Channel types and privacy semantics

- **Text:** durable events, replies and threads, ordered view over event IDs.
- **Announcement:** ordinary members may read, selected roles may publish; this is an authorization rule, not necessarily separate encryption.
- **Voice:** durable channel metadata with ephemeral call/session state and separate media path.
- **Read-private (blocked):** requires ADR-002 to choose per-channel MLS group or another reviewed restricted-key profile. A visual lock icon must not imply cryptographic privacy while every Space member can derive its exporter key.

## Moderation and conflict examples

Member A is banned on a partition: previously decrypted messages cannot be recalled; post-removal valid epochs should exclude A. If another admin simultaneously invites A from the old epoch, ADR-001 must establish which Commit, Welcome and branch are accepted. A moderator tombstones a message: honest clients hide it after receiving the event, but an offline peer may continue to display the old view until sync. A role update that revokes `CHANNEL_MANAGE` is verified against its causal policy context; delayed arrival cannot let an invalid later operation silently succeed.

Space owners can suggest relay URLs and retention defaults, but each device controls network/privacy policy and storage limits. A volunteer persistent node has no privileged membership merely because it is online.
