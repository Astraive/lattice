# Candidate 1: Space and membership payloads

**Status:** executable candidate, not a frozen interoperability contract. `lattice-core` implements the kind-6 policy reducer and conflict checks, but its membership transition and recovery gates fail closed without typed MLS/trust proofs. This spec does not establish interoperability or verify every Space requirement. It defines candidate plaintext records for the existing signed event kinds in [`05-events.md`](05-events.md).

## Event and encoding boundary

A Space-policy payload is the plaintext of an MLS-protected application message. After the group implementation has authenticated and decrypted the exact event ciphertext, the plaintext MUST be exactly one canonical CBOR integer-key map from [`02-encoding.md`](02-encoding.md) and at most 262,144 bytes. After MLS protection, outer event key `9` MUST remain a byte string no larger than 262,144 bytes, and the complete signed event preimage MUST remain within 1 MiB; reject a payload whose protected form exceeds either bound. The shared profile also limits any string to 262,144 bytes, a map or array to 4,096 entries, and nesting to 32 containers. Check lengths before allocation.

Use event kind `6` (Membership) for the payload operations in this document. Such events have a null outer channel ID. Use kind `7` (MLS control) for MLS control messages; those events also have a null channel ID. An MLS control body is not one of these application maps and MUST be validated by the MLS implementation. Kinds `1` through `5`, `8`, and `9` carry a channel ID subject to the channel type rules in `07-permissions.md`. No event kinds are added here. A kind-6 signature or successfully decoded payload alone proves neither membership nor permission. The receiver also needs the MLS ciphertext, group, epoch, credential, and policy checks described in [`08-mls.md`](08-mls.md) and `07-permissions.md`.

The outer event retains the exact schema in `05-events.md`: version `1`, the 16-byte Space ID, null channel ID for kind `6`, author fingerprint, positive author sequence, Lamport and wall-time hints, at most 64 unique bytewise-sorted parent IDs, kind `6`, protected ciphertext, 32-byte MLS group reference, and MLS epoch. Receivers validate every outer field against the signed bytes and MLS result; body fields do not replace or extend the outer map.

For Genesis or RecoveryGenesis, the MLS group parameters come from the validated MLS group state that protected the application message; they are not additional fields in this body. The reducer receives that validated group context and checks its reference and epoch against outer keys `10` and `11`. This candidate does not choose an MLS ciphersuite or infer one from application data.

Each body map has key `0` = unsigned body schema version `1` and key `1` = unsigned operation code. Each operation below has an exact key set. Reject an unknown version, operation, key, missing key, type, width, enum, or limit. There are no extension keys or ignored fields. A future extension needs a new reviewed body version or operation with defined semantics. All maps use strictly increasing unsigned keys and the canonical encoding rules in `02-encoding.md`.

## IDs and common values

- Each Space ID, channel ID, custom role ID, invite ID, and recovery ID is exactly 16 bytes. Producers generate IDs with the operating-system CSPRNG. Reject an ID collision in its namespace and never reuse an entity ID. Recovery genesis retains the existing Space ID; it does not create or reuse a different Space ID.
- Member identity is the full 32-byte identity-bundle fingerprint from [`03-identity.md`](03-identity.md). It is not a display name.
- An event reference is the full 32-byte event ID from `02-encoding.md`.
- An MLS group reference is exactly 32 bytes as specified by [`08-mls.md`](08-mls.md).
- Names are UTF-8 text of 1 through 128 encoded bytes, with no U+0000. Names are display-only byte strings; implementations MUST NOT use normalization, case folding, or names as identifiers.
- Channel types are `0` text, `1` announcement, and `2` voice. Value `3` (read-private) and all unknown values are rejected. Channel type is immutable after creation.

Per generation, retain at most 256 channel IDs, 256 custom role IDs, 4,096 distinct member fingerprints, and 4,096 distinct invite IDs, including archived, removed, and consumed records. Permit at most 256 assigned roles per member, counting assigned built-in administrator/moderator roles and custom roles. Reject a new record or assignment above these limits; do not evict old IDs or reuse them. These limits are additional to the CBOR profile bounds in `02-encoding.md`.

## Kind-6 body schemas

The body map includes keys `0` and `1` in every case. Additional keys are exactly those listed for the selected operation.

| Operation | Code | Additional keys |
| --- | ---: | --- |
| Genesis | 0 | `2..=3` |
| Recovery genesis | 1 | `2..=6` |
| Invite | 2 | `2..=6` |
| Set channel | 3 | `2` |
| Set custom role | 4 | `2` |
| Set role assignment | 5 | `2..=4` |
| Member transition | 6 | `2..=5` |
| Set channel order | 7 | `2` |

### Genesis, code 0

Exact map keys: `{0,1,2,3}`.

| Key | Type and rule |
| ---: | --- |
| 2 | Creator identity fingerprint, 32 bytes; MUST equal the outer event author. |
| 3 | Array of 1 through 64 initial channel descriptors, with unique IDs. |

The outer event MUST be kind `6`, have a null channel ID, no parents, epoch `0`, and a random 16-byte Space ID. Its author MUST equal key `2`. The creator is the initial and only active member and receives the protected owner identity defined in `07-permissions.md`. The MLS group is fresh and initially contains only that creator. Body version `1` and the permission registry in `07-permissions.md` define the policy baseline. Initial descriptors may refer only to the four built-in roles because custom roles do not yet exist.

A producer creates the MLS group and genesis as one local creation operation. A receiver MUST check the outer fields against the decrypted payload and the MLS state; it MUST NOT infer MLS membership from the payload.

### Recovery genesis, code 1

Exact map keys: `{0,1,2,3,4,5,6}`.

| Key | Type and rule |
| ---: | --- |
| 2 | Creator identity fingerprint, 32 bytes; MUST equal the outer event author. |
| 3 | Prior MLS group reference, 32 bytes. |
| 4 | Prior generation's root kind-6 event ID, 32 bytes. |
| 5 | Random recovery ID, 16 bytes. |
| 6 | Array of 1 through 64 initial channel descriptors, with unique IDs. |

The outer event MUST be kind `6`, have a null channel ID, no parents, and epoch `0`. It retains the prior Space ID but uses a newly created MLS group whose group reference differs from payload key `3` and every group reference already used for that Space. Payload key `3` MUST identify the prior group reference. Payload key `4` MUST reference the prior generation's root kind-6 event, whose body operation is Genesis (`0`) or RecoveryGenesis (`1`), in that same Space and group. Payload key `5` MUST be unused for this Space. The new generation starts with only the recovery creator as active owner. It carries no old membership, role assignments, invitations, channel state, or history into the new group; explicitly invite members again. Old-generation state remains separate and read-only. Initial channel descriptors can refer only to the four built-in roles.

A receiver accepts recovery only when its local recovery gate confirms that the creator is an administrator trusted for the prior Space by that installation's credential and pinning policy. The payload and event signature do not prove this fact. A receiver without that confirmation rejects the recovery genesis. This is a new-group rejoin, not a winner selection or merge of old branches. It follows the fail-closed recovery path in [ADR-001](../../docs/decisions/ADR-001-membership-commit-conflicts.md).

The Rust reducer contract takes a separate recovery authorization input containing the prior Space ID, prior group reference, and trusted administrator fingerprint. It accepts recovery genesis only when the input Space ID equals outer key `1`, the input group reference equals payload key `3`, and the input administrator fingerprint equals payload key `2` and outer key `3`. The local credential/pinning verifier must also supply the authorization, and payload key `4` must resolve to the prior generation root described above. Missing or mismatched authorization rejects recovery. This context is not encoded as a field and is not inferred from MLS key equality.

Two accepted recovery genesis events that name the same prior Space and group but use different new group references are separate candidate generations. Do not merge them or automatically choose one by time, arrival, event ID, or role. A device joins only the fresh group named by an explicitly trusted invitation; if it has not chosen a candidate, it reports recovery as unresolved rather than one active generation. Within a Space, one group reference identifies at most one root event; distinct roots for a reused group reference conflict and neither is accepted.

### Invite, code 2

Exact map keys: `{0,1,2,3,4,5,6}`.

| Key | Type and rule |
| ---: | --- |
| 2 | Random invite ID, 16 bytes. |
| 3 | Invited identity fingerprint, 32 bytes. |
| 4 | SHA-256 of the exact encoded MLS KeyPackage bytes, 32 bytes. |
| 5 | Null or unsigned exclusive expiry policy revision. |
| 6 | Null or unsigned maximum use count in `1..=65535`. |

An invite is a policy record, not a KeyPackage, Welcome, MLS membership change, bearer secret, or proof of identity trust. Verify the target fingerprint and KeyPackage against the actual MLS operation before admission. Invite expiry uses policy revisions, not the event wall-time hint: a generation's Genesis or RecoveryGenesis establishes revision `0`, and each accepted post-root kind-6 policy operation advances the revision by one. When issuing an invite at revision `r`, a non-null expiry MUST be greater than `r+1`; an admission is eligible only when the current revision is less than the expiry. Null means no expiry. A null use count means unlimited uses. Count a use only when the corresponding member-admission transition is accepted. Expired or exhausted invites fail closed. This candidate defines no wall-clock expiry.

Before applying a member-admission transition, check the invite's expiry against the current pre-transition policy revision. A transition is eligible only when that revision is strictly less than the non-null expiry; the transition then advances the revision once.

An invite ID is unique within the generation and cannot be reused after expiry, exhaustion, or admission. Reject creation of a 4,097th distinct invite. Expiry revision and use count are reducer state, not event timestamps; policy-revision overflow is fail-closed as specified in `07-permissions.md`.

Every use is bound to the same target fingerprint and KeyPackage hash. A finite use count limits repeated accepted admissions of that target after removal; an invite ID never authorizes another fingerprint or acts as a multi-target capability.

An invite target MUST NOT be active or banned. A removed member may receive a new invite; an active member cannot invite itself.

### Set channel, code 3

Exact map keys: `{0,1,2}`. Key `2` is one complete channel descriptor as defined below. If the ID is new, create the channel. Otherwise replace its mutable fields; its type MUST stay unchanged. Archive by setting `archived` true. There is no delete operation, and an archived ID is never reused. The reducer MUST reject a create beyond 256 channels.

Creating a channel appends its ID to the stored channel order. Updating or archiving an existing channel preserves its position. Archived IDs remain in the order and are not displayed among active channels. The initial channel descriptor array defines the initial order.

### Set custom role, code 4

Exact map keys: `{0,1,2}`. Key `2` is one complete custom role descriptor as defined below. Create or replace the descriptor with that ID. Built-in IDs cannot be defined or changed. There is no delete operation, and an ID is never reused. The reducer MUST reject a create beyond 256 custom roles.

### Set role assignment, code 5

Exact map keys: `{0,1,2,3,4}`.

| Key | Type and rule |
| ---: | --- |
| 2 | Active member fingerprint, 32 bytes. |
| 3 | Role ID, 16 bytes. Built-in member and owner IDs are not assignable; moderator, administrator, and existing custom roles are assignable. |
| 4 | Boolean: `true` assigns, `false` removes the assignment. |

Each `(member fingerprint, role ID)` pair has one assignment state. Repeating the current state is an idempotent no-op only when the event itself is an identical replay; a new event repeating the assignment is rejected as a redundant state change. The owner role and the member baseline cannot be removed or reassigned.

### Member transition, code 6

Exact map keys: `{0,1,2,3,4,5}`.

| Key | Type and rule |
| ---: | --- |
| 2 | Action: `0` admit, `1` remove, `2` ban. Other values are rejected. |
| 3 | Target member fingerprint, 32 bytes. |
| 4 | Null or invite event ID, 32 bytes. Required for admission; MUST be null for removal and ban. |
| 5 | MLS control event ID, 32 bytes, required for every action. |

The referenced invite, when required, MUST be an ancestor of this event, have the same target fingerprint, and remain unexpired and below its use limit at the current pre-transition policy revision. The referenced kind-7 event MUST also be an ancestor, have the same Space ID and author, and name the currently accepted MLS group reference and parent epoch in its outer fields. The kind-7 commit MUST be validated by the MLS implementation as the exact commit for the stated target and action. Its outer epoch and the kind-6 MemberTransition event's outer epoch are both the commit's parent epoch. Keep the commit staged: do not merge a membership-changing commit until its matching authorized MemberTransition is validated. Accept the policy transition and merge the exact staged commit as one durable state change; if either validation fails, apply neither. Missing parents or a missing linked event remain pending. The member-transition author must be authorized against the pre-transition policy state as specified in `07-permissions.md`.
Each membership-changing kind-7 commit MUST add or remove exactly one target and MUST have exactly one matching MemberTransition; otherwise it remains staged and cannot be merged. For an admission, the MLS Add MUST use the KeyPackage whose exact encoded bytes hash to the referenced invite's key `4`.
For action `0`, the matching MLS delta is one Add. For actions `1` and `2`, it is one Remove; action `2` additionally records the terminal application ban.

An active member cannot be admitted twice. Removal and ban require an active target other than the author; the owner cannot be removed or banned. Removal makes the target removed, and an unbanned removed member may be admitted again through a new invite and valid commit. Ban is terminal in this generation. There is no unban operation.

Count all distinct member fingerprints, including invited, active, removed, and banned records, toward the 4,096-member generation limit. No status transition deletes a member record.

An active state requires both an accepted member-admission transition and its matching validated MLS commit. An identity is locally `invited` only while at least one matching invite is unexpired, unexhausted, and has a remaining use. Join-pending and unsynchronized are local MLS or sync conditions, not policy grants; this payload schema does not claim that a join request or UI state is membership.

### Set channel order, code 7

Exact map keys: `{0,1,2}`. Key `2` is an array of 1 through 256 channel IDs, each exactly 16 bytes. It MUST contain every channel ID in the generation exactly once, including archived channels. Reject a missing, duplicate, unknown, or reused ID. The array order is the complete replacement order. No position is inferred from timestamps, arrival order, or ID sorting.

## Nested descriptors

A channel descriptor is a map with exactly keys `{0,1,2,3,4,5,6}`:

| Key | Type and rule |
| ---: | --- |
| 0 | Channel ID, 16 bytes. |
| 1 | Channel type: `0` text, `1` announcement, `2` voice. |
| 2 | Name, common name rule above. |
| 3 | Boolean archived state. |
| 4 | Unsigned 64-bit channel default allow mask. |
| 5 | Unsigned 64-bit channel default deny mask. |
| 6 | Array of at most 64 role override maps, strictly sorted by role ID bytes, with no duplicate role IDs. |

Each role override is exactly `{0: role_id, 1: allow_mask, 2: deny_mask}`. The role ID is 16 bytes and MUST refer to a built-in or already defined custom role. Masks use the type-specific channel-action subset in `07-permissions.md`; unknown bits and allow/deny overlap within one mask pair are rejected. Text and announcement channels accept only content-action bits; voice channels accept only voice-action bits. At genesis, only built-in role IDs may appear. Channel overrides affect actions, not who can decrypt content. Read-private semantics are prohibited by [ADR-002](../../docs/decisions/ADR-002-channel-read-semantics.md).

A custom role descriptor is a map with exactly keys `{0,1,2,3}`:

| Key | Type and rule |
| ---: | --- |
| 0 | Custom role ID, 16 bytes; MUST NOT equal a built-in ID. |
| 1 | Name, common name rule above. |
| 2 | Unsigned 64-bit allow mask. |
| 3 | Unsigned 64-bit deny mask. |

Masks use permission registry version 1 in `07-permissions.md`. Reject unknown bits and any bit set in both masks. Role descriptors have no scripts or extension behavior.

## Policy ordering and conflict state

The reducer maintains a generation-local policy revision and the maximal accepted kind-6 policy event IDs, called the policy heads. Genesis or RecoveryGenesis is the first head of its generation and establishes revision `0`; each accepted post-root policy operation MUST change policy state and advances the revision exactly once. Reject a new event that would leave state unchanged; an identical event-ID replay remains idempotent under `05-events.md`. Each post-root state-changing kind-6 operation MUST include the full current policy-head set in the transitive ancestor set of its outer event parents. A head may be a direct parent or an ancestor. Kind-7 control events do not replace policy heads. A MemberTransition must also include its referenced kind-7 control event in its ancestor set.

If a required parent is not yet available, keep the event pending and do not authorize or project it. Once the relevant graph is available, an operation that omits any current head is rejected as incomplete. If two or more distinct, individually well-formed and authorized policy operations descend from the same full head set without depending on one another, accept neither, retain their event IDs as conflict evidence, and mark the generation `policy-conflicted`. Invalid or unauthorized events are rejected and do not create policy conflicts. Do not resolve by wall time, Lamport value, arrival order, relay order, signature bytes, or event-ID/hash order. While conflicted, reject policy mutations and permission-sensitive actions. Sorting evidence IDs for storage does not select a branch.

The per-generation conflict witness cache holds at most 64 exact signed-event records for policy and MLS control conflicts. Keep the 64 lowest event IDs in bytewise order as candidates are observed; this is a bounded diagnostic sample only and never selects a policy or MLS branch. The conflict latch remains set independently of which witnesses fit in the cache.

On discovery of a policy fork, restore the reducer projection to the policy state at the siblings' common full head set and apply neither sibling or any descendant. Quarantine permission-sensitive events whose causal policy context descends from either branch; they cannot affect the old generation's authorized view. Keep immutable signed bytes, but do not display an event as authorized solely because one replica projected it before learning of the fork.

A valid MLS commit based on a non-current epoch is retained as conflict evidence, not applied. Two valid commits succeeding the same epoch put the MLS group in `conflicted`; freeze membership and other authorization-sensitive state changes. A missing commit parent is pending. No client may choose a commit using time, arrival, hash, or role. Recover by the recovery-genesis process above, using a fresh MLS group and explicit new invitations. Do not reissue old Welcome messages or claim to restore history omitted from the recovered generation.

Every receiver retains old event bytes and keeps generations separate by their MLS group reference. The event signature proves possession of the embedded signing key only. MLS key equality does not establish X.509 chain trust, a human identity, or human pinning.
