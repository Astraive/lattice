# Candidate 1: Space permissions and reduction

**Status:** executable candidate, not a frozen interoperability contract. This document does not claim that the candidate is implemented, interoperable, or requirement-verified. Payload layouts and existing event kinds are in [`06-spaces.md`](06-spaces.md) and [`05-events.md`](05-events.md).

## Permission registry version 1

All permission masks are unsigned 64-bit CBOR integers. Body version `1` selects this fixed registry; there is no separately negotiated registry version. Bits not assigned below MUST be zero. Unknown bits, negative values, and non-integer masks are rejected. A future registry change requires a new reviewed body version; receivers MUST NOT guess unknown bits.

| Bit | Name | Scope |
| ---: | --- | --- |
| 0 | `SPACE_MANAGE` | Required with the operation-specific bit for every post-root kind-6 policy operation. Recovery genesis instead requires the local recovery gate. |
| 1 | `CHANNEL_MANAGE` | Create, update, and archive channel metadata. |
| 2 | `ROLE_MANAGE` | Define custom roles and change role assignments. |
| 3 | `MEMBER_INVITE` | Create invites and admit an invited member. |
| 4 | `MEMBER_REMOVE` | Remove a member. |
| 5 | `MEMBER_BAN` | Ban a member. |
| 6 | `MESSAGE_SEND` | Send a message or reaction, or edit the sender's own message. |
| 7 | `MESSAGE_ATTACH` | Attach a file to a message. |
| 8 | `MESSAGE_MODERATE` | Tombstone another member's content. |
| 9 | `THREAD_CREATE` | Create a thread. |
| 10 | `MENTION_EVERYONE` | Use an everyone mention. |
| 11 | `MESSAGE_PIN` | Pin or unpin a message. |
| 12 | `VOICE_JOIN` | Join a voice channel or publish a voice signal. |
| 13 | `VOICE_SPEAK` | Publish voice media. |
| 14 | `VOICE_MODERATE` | Moderate a voice participant. |
| 15 | `RETENTION_MANAGE` | Change Space retention policy. |
| 16 | `RELAY_RECOMMEND` | Publish a relay recommendation. A recommendation never overrides local network policy. |

The channel-action mask is `0x0000000000007fc0` (bits 6 through 14). Text and announcement channels accept only `0x0000000000000fc0` (bits 6 through 11); voice channels accept only `0x0000000000007000` (bits 12 through 14). Default and per-role channel masks MUST fit the selected channel type's mask. No channel override can grant space management, membership, role, retention, or relay authority.
Bits `RETENTION_MANAGE` and `RELAY_RECOMMEND` have no corresponding payload operation in `06-spaces.md`; assigning either bit alone does not authorize an unlisted event or operation.

## Built-in role identities and grants

Role IDs are exactly 16 bytes. The four reserved identities are fixed values, not random IDs:

| Role | Role ID, hexadecimal | Grant mask |
| --- | --- | --- |
| Owner | `00000000000000000000000000000001` | `0x000000000001ffff` |
| Administrator | `00000000000000000000000000000002` | `0x000000000001cd3f` |
| Moderator | `00000000000000000000000000000003` | `0x0000000000004900` |
| Member | `00000000000000000000000000000004` | `0x00000000000032c0` |

The masks list only grants from that role. Every active non-owner has the member baseline implicitly, so a separately stored member assignment is invalid. Administrator and moderator are assignable roles; the owner and member roles are not. A member may also hold custom roles. Roles are additive except for custom-role denies below.

The owner identity is assigned only to the creator in a valid genesis or recovery genesis. There is exactly one owner in a generation. Owner assignment, removal, ban, or transfer is unsupported. The owner cannot be affected by custom-role denies or channel overrides. Ownership changes require a new recovery generation with explicit trust checks; no ordinary policy event can transfer it.

Custom role IDs are CSPRNG-generated 16-byte values. Reject any reserved, previously used, or duplicate ID. Custom descriptors and assignment schemas are defined in `06-spaces.md`; roles have no scripts, inherited parents, or extension fields.

## Effective Space permissions

For an active non-owner member, let `R` be the member baseline, every assigned built-in role, and every assigned custom role. Let `A` be the bitwise OR of grants from `R`, including custom allow masks. Let `D` be the bitwise OR of custom deny masks in `R`. The effective Space mask is:

```text
S = A & !D & 0x000000000001ffff
```

A deny from any assigned custom role wins over grants from every role. Built-in roles have no deny mask. The owner has the known mask unconditionally, including in every channel. Removed and banned members have no effective mask. An invitee has no effective mask before an accepted member transition and corresponding valid MLS commit.

A role ID must refer to a built-in or existing custom role. The reducer rejects assignment to a non-active member, assignment of owner/member, or assignment of a missing custom role. It rejects a new role descriptor or channel override with an unknown bit, disallowed bit, malformed role reference, or duplicate entry.

## Channel overrides and precedence

For the selected channel, collect its default allow and deny masks plus the masks in each override whose role is held by the member. Let `CA` be the OR of those allow masks and `CD` the OR of those deny masks. Then:

```text
channel_effective = if owner { 0x000000000001ffff } else { S & !(CD & !CA) }
```

The channel allow mask overrides a channel deny for the same bit, including a default deny, when any held role grants that bit in its channel override. Space permissions remain the ceiling: channel allow cannot add a bit missing from `S`, and a Space-level deny has already removed the bit from `S`. Thus an announcement channel can deny `MESSAGE_SEND` by default and allow it for selected roles without giving those roles a permission they lack at Space level. The owner bypasses channel masks and has the known mask in every non-archived channel. A channel's type, archived state, and overrides do not affect MLS decryption.

Reject actions in an unknown or archived channel. A text or announcement action uses that channel's effective mask. Voice actions use the voice channel's effective mask. A permission decision uses the roles, custom masks, channel descriptor, and membership state at the event's causal policy context, not the author's current UI state.

In this Space profile, kinds `1` through `5` and `8` require a non-null channel ID for a non-archived text or announcement channel; kind `9` requires a non-null channel ID for a non-archived voice channel. Kinds `6` and `7` require a null channel ID. Reject an event whose kind and channel type do not match.

## Authorization for candidate operations

Every kind-6 policy operation except genesis and recovery genesis requires an active, non-banned author and the full policy-head dependency rule in `06-spaces.md`. Check the author against the pre-operation state. The operation-specific requirements are:

| Payload operation | Required Space bits |
| --- | --- |
| Invite | `SPACE_MANAGE` and `MEMBER_INVITE` |
| Member admit | `SPACE_MANAGE` and `MEMBER_INVITE` |
| Member remove | `SPACE_MANAGE` and `MEMBER_REMOVE` |
| Member ban | `SPACE_MANAGE` and `MEMBER_BAN` |
| Set channel | `SPACE_MANAGE` and `CHANNEL_MANAGE` |
| Set channel order | `SPACE_MANAGE` and `CHANNEL_MANAGE` |
| Set custom role | `SPACE_MANAGE` and `ROLE_MANAGE` |
| Set role assignment | `SPACE_MANAGE` and `ROLE_MANAGE` |

Genesis has no existing Space role check; the creator is recorded as owner. Recovery genesis is not authorized by a role read from a conflicted branch. It requires the local recovery gate described in `06-spaces.md`, which must establish that the creator is an administrator trusted for the prior Space. A signature proves key possession only. MLS key equality is not X.509 chain validation, credential trust, human identity, or human pinning.

For channel-scoped application actions, evaluate these candidate requirements at the event's policy context:

| Existing event/action | Required channel-effective bits |
| --- | --- |
| Kind 1 message | `MESSAGE_SEND`; `THREAD_CREATE` if it creates a thread; `MENTION_EVERYONE` if used. |
| Kind 2 edit | `MESSAGE_SEND` for the author's own message; otherwise `MESSAGE_MODERATE`. |
| Kind 3 tombstone | `MESSAGE_MODERATE`. |
| Kind 4 reaction | `MESSAGE_SEND`. |
| Kind 5 pin | `MESSAGE_PIN`. |
| Kind 8 file manifest | `MESSAGE_SEND` and `MESSAGE_ATTACH`. |
| Kind 9 voice signal | `VOICE_JOIN`; publishing voice media also requires `VOICE_SPEAK`. |

An operation with more than one action requires every listed bit. This table assigns no new event kind or message-body schema. An implementation that cannot identify the action from its already-defined event semantics MUST reject rather than infer permission from a UI action or event timestamp. Voice moderation requires `VOICE_MODERATE` in the voice channel context.

## No self-escalation and owner protection

Role changes are evaluated against the author and affected members before and after the proposed operation:

- A role-assignment operation MUST NOT grant any role to its author. It may remove the author's own role if the author remains authorized under the pre-operation check.
- A custom-role definition MUST have an allow mask that is a subset of the author's pre-operation effective Space mask. After replacement, the author's effective mask MUST NOT increase. For every member assigned that role, the resulting effective mask MUST be a subset of the author's pre-operation effective mask. This rule also applies when changing a role already assigned to other members.
- A channel update MUST NOT increase the author's effective channel mask for the affected channel. For a newly created channel, compare against the author's Space mask `S`; for an existing channel, compare against its prior channel-effective mask. This check applies to all channel-action bits.
- A role-assignment grant to another member is allowed only if that member's resulting effective mask is a subset of the author's pre-operation effective mask. A revoke does not grant authority and is allowed when the author passes the operation check.
- No operation may create a second owner, change the owner fingerprint, assign the owner role, remove or ban the owner, or reduce the owner's permissions.

Reject a role change that fails any check as a whole. Do not partially apply masks or assignments. These checks prevent direct self-grants and indirect escalation through a changed custom role or delegated role.

## Causal dependencies, state, and conflicts

Treat the kind-6 policy records in one MLS group generation as a single causal policy log. Genesis or RecoveryGenesis establishes revision `0`; each accepted post-root policy operation increments the revision once. If the revision is `2^64-1`, fail closed and accept no further policy operation. An operation MUST include the full current policy-head set as ancestors of its event parents. The same rule applies to permission-sensitive application events so that stale role, membership, invite, or channel state cannot authorize them. A missing ancestor leaves the event pending. An event with a complete graph but a missing current head is rejected as incomplete.

Two distinct, individually well-formed and authorized policy operations from the same complete head set conflict. Apply neither, restore the projection to their common prior state, and quarantine all permission-sensitive descendants as specified in `06-spaces.md`. Do not choose using wall time, Lamport hints, relay or arrival order, author sequence, role, event ID, or hash. Stop privileged mutations and permission-sensitive actions until a fresh group is established through the recovery-genesis process. The administrator explicitly rebuilds policy and re-invites members; no old branch, MLS Welcome, or omitted history is silently merged.

For competing valid MLS commits based on one epoch, keep both as conflict evidence and stop group mutation as required by [ADR-001](../../docs/decisions/ADR-001-membership-commit-conflicts.md). A missing commit parent is pending. A valid commit from a different branch is not applied. Recovery creates a fresh MLS group and requires explicit, locally trusted administrator action; no timestamp, arrival, hash, or role selects the old branch. Multiple trusted recovery roots remain separate candidates as specified in `06-spaces.md`.

## Channel confidentiality boundary

Channels are logical policy scopes within one Space MLS group. Every active member of that group generation is within the channel content key trust boundary, regardless of channel type, role, deny mask, or UI. Read-private and equivalent confidentiality claims are unsupported and MUST fail closed, as required by [ADR-002](../../docs/decisions/ADR-002-channel-read-semantics.md). Channel permissions can deny actions such as sending, attaching, or joining voice. They cannot conceal plaintext from another active Space member or substitute for a separate cryptographic membership system.
