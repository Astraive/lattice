//! Candidate Space policy reduction for the executable contracts in
//! `protocol/specs/06-spaces.md` and `07-permissions.md`.
//!
//! This module is a policy projection and authorization gate, not an MLS
//! engine. Kind-6 policy messages enter through [`crate::MlsBoundEvent`];
//! kind-1–5 and kind-8 actions use event fields and exact MLS-produced plaintext.
//! Authorized message, edit, tombstone, reaction, and pin actions have a
//! deterministic in-memory projection. Durable projection storage and voice
//! authorization are not implemented.
//!
//! MLS admission validates credential trust and group references before
//! producing [`crate::MlsBoundEvent`]. The core transaction path stages the
//! exact MLS Commit, validates its parent-epoch transition against policy, and
//! atomically merges the Commit with both durable signed event records. Each
//! [`SpaceReducer`] remains a candidate generation; callers keep generations
//! separate by MLS group reference. Recovery authorization uses the prior
//! reducer's retained common policy and binds one exact MLS-authenticated
//! recovery Genesis.
//! Accepted membership transitions replay their protected policy history.
//! Welcome bootstrap import restores one pinned-inviter checkpoint; general
//! event-history replay and user-facing invitation delivery remain incomplete.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use lattice_events::{EventKind, VerifiedSignatureOnlyEvent};
use lattice_files::AttachmentManifest;
use lattice_protocol::{Value, decode_canonical};

use crate::MlsBoundEvent;
pub mod message_projection;

pub const MAX_SPACE_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_CHANNELS: usize = 256;
pub const MAX_CUSTOM_ROLES: usize = 256;
pub const MAX_MEMBERS: usize = 4_096;
pub const MAX_INVITES: usize = 4_096;
pub const MAX_ASSIGNED_ROLES_PER_MEMBER: usize = 256;
pub const MAX_CHANNEL_OVERRIDES: usize = 64;
pub const MAX_INITIAL_CHANNELS: usize = 64;
pub const MAX_PARENTS: usize = 64;
pub const MAX_CONFLICT_WITNESSES: usize = 64;
const MAX_GRAPH_EVENTS: usize = 16_384;
const MAX_PENDING_EVENTS: usize = 256;
const MAX_POLICY_HISTORY: usize = 64;
const MAX_MESSAGE_HISTORY_BYTES: usize = 16 * 1024 * 1024;
const SPACE_PERMISSION_MASK: u64 = 0x0000_0000_0001_ffff;
const VOICE_PERMISSION_MASK: u64 = 0x0000_0000_0000_7000;
const CONTENT_CHANNEL_MASK: u64 = 0x0000_0000_0000_0fc0;
const SPACE_MANAGE: u64 = 1 << 0;
const CHANNEL_MANAGE: u64 = 1 << 1;
const ROLE_MANAGE: u64 = 1 << 2;
const MEMBER_INVITE: u64 = 1 << 3;
pub(crate) const INVITE_PERMISSION_REQUIREMENTS: u64 = SPACE_MANAGE | MEMBER_INVITE;
const MEMBER_REMOVE: u64 = 1 << 4;
const MEMBER_BAN: u64 = 1 << 5;
const MESSAGE_SEND: u64 = 1 << 6;
const MESSAGE_ATTACH: u64 = 1 << 7;
const MESSAGE_MODERATE: u64 = 1 << 8;
const THREAD_CREATE: u64 = 1 << 9;
const MENTION_EVERYONE: u64 = 1 << 10;
const MESSAGE_PIN: u64 = 1 << 11;
const MEMBER_BASELINE: u64 = 0x0000_0000_0000_32c0;
const ADMINISTRATOR_GRANTS: u64 = 0x0000_0000_0001_cd3f;
const MODERATOR_GRANTS: u64 = 0x0000_0000_0000_4900;
const OWNER_GRANTS: u64 = SPACE_PERMISSION_MASK;
const BUILTIN_ROLE_IDS: [[u8; 16]; 4] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
];

pub type SpaceId = [u8; 16];
pub type GroupReference = [u8; 32];
pub type EventReference = [u8; 32];
pub type Fingerprint = [u8; 32];
pub type EntityId = [u8; 16];

/// Stable encrypted-payload target for a message mention.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MentionTarget {
    /// Full device identity fingerprint; display names are never resolved on wire.
    Identity(Fingerprint),
    /// Stable Space role identifier.
    Role(EntityId),
}

/// Maximum distinct identity/role references on one message.
pub const MAX_MESSAGE_MENTIONS: usize = 64;

/// The fixed channel type registry in candidate protocol version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelType {
    Text,
    Announcement,
    Voice,
}

/// Permission masks for one role override in a channel descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleOverride {
    pub role_id: EntityId,
    pub allow: u64,
    pub deny: u64,
}

/// Complete candidate channel descriptor. IDs and types are immutable once
/// created; the remaining fields may be replaced by an authorized operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub id: EntityId,
    pub channel_type: ChannelType,
    pub name: String,
    pub archived: bool,
    pub default_allow: u64,
    pub default_deny: u64,
    pub role_overrides: Vec<RoleOverride>,
}

/// Candidate custom role descriptor. Roles have no inheritance or scripts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomRole {
    pub id: EntityId,
    pub name: String,
    pub allow: u64,
    pub deny: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberStatus {
    Invited,
    Active,
    Removed,
    Banned,
}

/// Member projection; assigned role IDs exclude the implicit member baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    pub fingerprint: Fingerprint,
    pub status: MemberStatus,
    pub assigned_roles: Vec<EntityId>,
}

/// Invite record and its policy-revision-based use accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invite {
    pub id: EntityId,
    pub event_id: EventReference,
    pub target: Fingerprint,
    pub key_package_hash: [u8; 32],
    pub expires_at_revision: Option<u64>,
    pub max_uses: Option<u16>,
    pub uses: u16,
}

/// Read-only candidate policy state for one MLS generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpacePolicy {
    pub space_id: SpaceId,
    pub group_reference: GroupReference,
    pub root_event_id: EventReference,
    pub root_author: Fingerprint,
    pub revision: u64,
    pub heads: Vec<EventReference>,
    pub channels: Vec<Channel>,
    /// Full channel order including archived channel IDs.
    pub channel_order: Vec<EntityId>,
    pub custom_roles: Vec<CustomRole>,
    pub members: Vec<Member>,
    pub invites: Vec<Invite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictEvidence {
    pub event_id: EventReference,
    /// Exact original signed outer event bytes, retained without reconstruction.
    pub signed_event: Arc<[u8]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReducerStatus {
    AwaitingGenesis,
    Active { revision: u64 },
    PolicyConflicted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyResult {
    Applied {
        revision: u64,
    },
    /// One or more outer-parent graph dependencies are not available yet.
    Pending,
    /// This exact authenticated event ID was already accepted.
    Replay {
        revision: u64,
    },
    Rejected(RejectReason),
    PolicyConflicted,
}

/// Result of checking one authenticated, decrypted application event against
/// the reducer's current complete policy state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventAuthorization {
    Authorized { required_permissions: u64 },
    Pending,
    Rejected(RejectReason),
    PolicyConflicted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingResult {
    pub event_id: EventReference,
    pub result: ApplyResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    UnauthenticatedEvent,
    WrongEventKind,
    NonNullChannel,
    InvalidOuterParents,
    PayloadTooLarge,
    InvalidCanonicalPayload,
    InvalidSchema,
    InvalidValue,
    CreatorMismatch,
    InvalidGenesisContext,
    InvalidRecoveryAuthorization,
    WrongGeneration,
    MissingPolicy,
    IncompletePolicyHeads,
    Unauthorized,
    SelfEscalation,
    OwnerProtected,
    UnknownEntity,
    DuplicateEntity,
    InvalidTransition,
    InvalidControlRelation,
    NoStateChange,
    RevisionOverflow,
    LimitExceeded,
    GraphConflict,
    InvalidTarget,
    WrongChannelType,
    UnsupportedAction,
}

/// Opaque authorization derived from an active prior Space policy and one exact
/// MLS-bound recovery Genesis event.
///
/// Only [`SpaceReducer::authorize_recovery_genesis`] can construct this value.
/// It proves the old generation's current invite permission and binds recovery
/// to one event and one new group reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAuthorization {
    prior_space_id: SpaceId,
    prior_group_reference: GroupReference,
    prior_root_event_id: EventReference,
    trusted_administrator: Fingerprint,
    recovery_id: EntityId,
    new_group_reference: GroupReference,
    recovery_event_id: EventReference,
}

/// Attachment manifest admitted by this reducer for one exact signed event.
///
/// Only [`SpaceReducer::authorized_attachment_manifest`] can construct this
/// capability. It binds receiver creation to the reducer-retained manifest;
/// filenames and MIME hints remain untrusted display metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedAttachmentManifest {
    event_id: EventReference,
    manifest: AttachmentManifest,
}

impl AuthorizedAttachmentManifest {
    #[must_use]
    pub fn event_id(&self) -> &EventReference {
        &self.event_id
    }

    #[must_use]
    pub fn manifest(&self) -> &AttachmentManifest {
        &self.manifest
    }

    /// # Errors
    ///
    /// Returns `AttachmentError` if the retained manifest fails its bounds
    /// validation.
    pub fn transfer_id(
        &self,
    ) -> Result<lattice_files::AttachmentTransferId, lattice_files::AttachmentError> {
        self.manifest.transfer_id(&self.event_id)
    }

    /// # Errors
    ///
    /// Returns `AttachmentError` if the staging limit is smaller than the
    /// manifest size or the retained manifest fails validation.
    pub fn new_receiver(
        &self,
        staging_limit: u64,
    ) -> Result<lattice_files::AttachmentReceiver, lattice_files::AttachmentError> {
        lattice_files::AttachmentReceiver::new(self.manifest.clone(), staging_limit)
    }

    /// # Errors
    ///
    /// Returns `AttachmentError` if the staging limit is insufficient, the
    /// manifest is invalid, or the supplied store cannot be initialized.
    pub fn new_streamed_receiver<S: std::io::Read + std::io::Write + std::io::Seek>(
        &self,
        staging_limit: u64,
        storage: S,
    ) -> Result<lattice_files::StreamedAttachmentReceiver<S>, lattice_files::AttachmentError> {
        lattice_files::StreamedAttachmentReceiver::new(
            self.manifest.clone(),
            staging_limit,
            storage,
        )
    }
}

/// Member action recorded by an admitted kind-6 policy transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberAction {
    Admit,
    Remove,
    Ban,
}

/// Internal relation tying one signed control event to an MLS proof.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedMlsControlRelation {
    space_id: SpaceId,
    group_reference: GroupReference,
    control_event_id: EventReference,
    author: Fingerprint,
    parent_epoch: u64,
    mls_action: lattice_mls::api::MlsMembershipAction,
    target: Fingerprint,
    key_package_hash: Option<[u8; 32]>,
}

/// Candidate policy reducer. State, graph, pending work, and conflict evidence
/// are generation-local and bounded. Up to 64 accepted post-root mutations are
/// retained for rollback; further writes fail closed rather than prune history.
/// The reducer never selects policy using wall-time, Lamport, author sequence,
/// arrival order, or event-ID order.
#[derive(Clone, Default)]
pub struct SpaceReducer {
    policy: Option<SpacePolicy>,
    history_base: Option<SpacePolicy>,
    root_signed_event: Option<Arc<[u8]>>,
    graph: BTreeMap<EventReference, GraphNode>,
    bootstrap_anchors: BTreeSet<EventReference>,
    pending: Vec<PendingPolicy>,
    history: Vec<AcceptedPolicyEvent>,
    conflicted: bool,
    conflict_evidence: Vec<ConflictEvidence>,
    quarantined_event_ids: Vec<EventReference>,
    message_history_bytes: usize,
}

impl SpaceReducer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn status(&self) -> ReducerStatus {
        if self.conflicted {
            ReducerStatus::PolicyConflicted
        } else if let Some(policy) = self.policy.as_ref() {
            ReducerStatus::Active {
                revision: policy.revision,
            }
        } else {
            ReducerStatus::AwaitingGenesis
        }
    }

    #[must_use]
    pub fn policy(&self) -> Option<&SpacePolicy> {
        self.policy.as_ref()
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keeps signed checkpoint validation together.
    /// Reconstructs a joined generation from an inviter-signed bootstrap checkpoint.
    ///
    /// Historical policy/MLS acceptance is attested by the pinned inviter;
    /// this method validates the signed root, snapshot consistency, invite,
    /// signed head anchors, inviter authority in the attested snapshot, and
    /// recipient's active membership without claiming historical MLS replay.
    pub(crate) fn from_welcome_bootstrap(
        root: &VerifiedSignatureOnlyEvent,
        genesis_plaintext: &[u8],
        snapshot: SpacePolicy,
        invite_event: &VerifiedSignatureOnlyEvent,
        invite_plaintext: &[u8],
        head_events: &[VerifiedSignatureOnlyEvent],
        last_control_event: Option<&VerifiedSignatureOnlyEvent>,
        inviter: &Fingerprint,
        target: &Fingerprint,
        current_epoch: u64,
    ) -> Result<Self, RejectReason> {
        if root.kind() != EventKind::Membership
            || root.channel_id().is_some()
            || !root.parents().is_empty()
            || root.mls_epoch() != 0
            || root.space_id() != &snapshot.space_id
            || root.mls_group_reference() != &snapshot.group_reference
            || root.event_id().as_bytes() != &snapshot.root_event_id
            || root.author_fingerprint() != &snapshot.root_author
            || genesis_plaintext.len() > MAX_SPACE_PAYLOAD_BYTES
        {
            return Err(RejectReason::InvalidGenesisContext);
        }
        let payload = decode_canonical(genesis_plaintext)
            .map_err(|_| RejectReason::InvalidCanonicalPayload)?;
        let (creator, baseline_channels) = match parse_operation(&payload)? {
            Operation::Genesis { creator, channels } => (creator, channels),
            Operation::RecoveryGenesis {
                creator, channels, ..
            } if creator == *inviter => (creator, channels),
            _ => return Err(RejectReason::InvalidGenesisContext),
        };
        if creator != *root.author_fingerprint()
            || snapshot.root_author != creator
            || snapshot.heads.is_empty()
            || snapshot.heads.len() != head_events.len()
            || snapshot.heads.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RejectReason::CreatorMismatch);
        }

        let baseline_ids = baseline_channels
            .iter()
            .map(|channel| channel.id)
            .collect::<BTreeSet<_>>();
        if baseline_ids.len() != baseline_channels.len()
            || baseline_channels.iter().any(|baseline| {
                !snapshot.channels.iter().any(|current| {
                    current.id == baseline.id && current.channel_type == baseline.channel_type
                })
            })
        {
            return Err(RejectReason::InvalidValue);
        }
        let mut reducer = Self::new();
        reducer.register_event(root, None, false)?;
        let channel_order = baseline_channels
            .iter()
            .map(|channel| channel.id)
            .collect::<Vec<_>>();
        let baseline = SpacePolicy {
            space_id: *root.space_id(),
            group_reference: *root.mls_group_reference(),
            root_event_id: *root.event_id().as_bytes(),
            root_author: creator,
            revision: 0,
            heads: vec![*root.event_id().as_bytes()],
            channels: baseline_channels,
            channel_order,
            custom_roles: Vec::new(),
            members: vec![Member {
                fingerprint: creator,
                status: MemberStatus::Active,
                assigned_roles: vec![BUILTIN_ROLE_IDS[0]],
            }],
            invites: Vec::new(),
        };
        reducer.history_base = Some(baseline);
        reducer.root_signed_event = Some(Arc::from(root.encoded_bytes()));

        if snapshot.space_id != *root.space_id()
            || snapshot.group_reference != *root.mls_group_reference()
            || snapshot.root_event_id != *root.event_id().as_bytes()
            || snapshot.root_author != creator
            || snapshot.revision == 0 && snapshot.heads != [snapshot.root_event_id]
            || snapshot
                .members
                .iter()
                .find(|member| member.fingerprint == *target)
                .is_none_or(|member| member.status != MemberStatus::Active)
            || snapshot
                .members
                .iter()
                .find(|member| member.fingerprint == *inviter)
                .is_none_or(|member| member.status != MemberStatus::Active)
            || effective_space(&snapshot, inviter) & (SPACE_MANAGE | MEMBER_INVITE)
                != (SPACE_MANAGE | MEMBER_INVITE)
        {
            return Err(RejectReason::InvalidTransition);
        }

        if invite_event.kind() != EventKind::Membership
            || invite_event.channel_id().is_some()
            || invite_event.space_id() != root.space_id()
            || invite_event.mls_group_reference() != root.mls_group_reference()
            || invite_event.author_fingerprint() != inviter
        {
            return Err(RejectReason::InvalidTransition);
        }
        let invite_payload = decode_canonical(invite_plaintext)
            .map_err(|_| RejectReason::InvalidCanonicalPayload)?;
        let Operation::Invite {
            id,
            target: invite_target,
            key_package_hash,
            expires_at_revision,
            max_uses,
        } = parse_operation(&invite_payload)?
        else {
            return Err(RejectReason::InvalidTransition);
        };
        let invite_id = *invite_event.event_id().as_bytes();
        if invite_target != *target
            || snapshot.invites.iter().all(|invite| {
                invite.id != id
                    || invite.event_id != invite_id
                    || invite.target != invite_target
                    || invite.key_package_hash != key_package_hash
                    || invite.expires_at_revision != expires_at_revision
                    || invite.max_uses != max_uses
                    || invite.uses == 0
            })
        {
            return Err(RejectReason::InvalidTransition);
        }
        reducer.register_event(invite_event, None, false)?;
        reducer.bootstrap_anchors.insert(invite_id);

        for (expected_id, head) in snapshot.heads.iter().zip(head_events) {
            if head.kind() != EventKind::Membership
                || head.channel_id().is_some()
                || head.space_id() != root.space_id()
                || head.mls_group_reference() != root.mls_group_reference()
                || head.event_id().as_bytes() != expected_id
            {
                return Err(RejectReason::IncompletePolicyHeads);
            }
            reducer.register_event(head, None, false)?;
            reducer.bootstrap_anchors.insert(*expected_id);
        }
        match last_control_event {
            Some(event)
                if event.kind() == EventKind::MlsControl
                    && event.channel_id().is_none()
                    && event.space_id() == root.space_id()
                    && event.mls_group_reference() == root.mls_group_reference()
                    && current_epoch > 0
                    && event.mls_epoch().checked_add(1) == Some(current_epoch) =>
            {
                let event_id = *event.event_id().as_bytes();
                reducer.register_event(event, None, false)?;
                reducer.bootstrap_anchors.insert(event_id);
            }
            None if current_epoch == 0 => {}
            _ => return Err(RejectReason::InvalidControlRelation),
        }
        if current_epoch > 0 && last_control_event.is_none() {
            return Err(RejectReason::InvalidControlRelation);
        }
        reducer.policy = Some(snapshot.clone());
        reducer.history_base = Some(snapshot);
        Ok(reducer)
    }

    pub(crate) fn has_projected_message(&self, event_id: &EventReference) -> bool {
        self.graph
            .get(event_id)
            .is_some_and(|node| node.kind == EventKind::Message && node.application_authorized)
    }
    pub(crate) fn mark_membership_conflicted(
        &mut self,
        first: &VerifiedSignatureOnlyEvent,
        second: &VerifiedSignatureOnlyEvent,
    ) {
        self.conflicted = true;
        for event in [first, second] {
            let event_id = *event.event_id().as_bytes();
            self.insert_conflict_evidence(ConflictEvidence {
                event_id,
                signed_event: Arc::from(event.encoded_bytes()),
            });
            self.quarantined_event_ids.push(event_id);
        }
        self.sort_quarantined();
    }

    /// Returns the exact accepted policy events after a previously checkpointed
    /// revision. Replay is refused when this reducer has unresolved or conflicted
    /// state, or when retained history does not begin at its checkpoint.
    pub(crate) fn policy_replay_events_after(
        &self,
        base_revision: u64,
    ) -> Result<Vec<SpacePolicyReplayEvent>, RejectReason> {
        let policy = self.policy.as_ref().ok_or(RejectReason::MissingPolicy)?;
        if self.conflicted
            || !self.pending.is_empty()
            || !self.conflict_evidence.is_empty()
            || !self.quarantined_event_ids.is_empty()
            || self
                .history_base
                .as_ref()
                .is_none_or(|base| base_revision < base.revision)
            || base_revision > policy.revision
        {
            return Err(RejectReason::InvalidTransition);
        }
        let mut expected_revision = base_revision;
        let mut events = Vec::new();
        for event in self
            .history
            .iter()
            .filter(|event| event.base_revision >= base_revision)
        {
            if event.base_revision != expected_revision {
                return Err(RejectReason::InvalidTransition);
            }
            events.push(SpacePolicyReplayEvent {
                event_bytes: event.signed_event.to_vec(),
                plaintext: event.plaintext.to_vec(),
            });
            expected_revision = expected_revision
                .checked_add(1)
                .ok_or(RejectReason::RevisionOverflow)?;
        }
        if expected_revision != policy.revision {
            return Err(RejectReason::InvalidTransition);
        }
        Ok(events)
    }
    pub(crate) fn policy_replay_base_revision(&self) -> Result<u64, RejectReason> {
        self.history_base
            .as_ref()
            .map(|base| base.revision)
            .ok_or(RejectReason::MissingPolicy)
    }
    /// Materializes the authorized message actions retained by this reducer.
    ///
    /// This in-memory projection preserves every edit/tombstone, applies
    /// reaction and pin removals by tag, and is not durable history.
    #[must_use]
    pub fn message_history(&self, channel_id: &EntityId) -> message_projection::MessageHistory {
        message_projection::project_channel(&self.graph, channel_id)
    }
    /// Return a receiver capability only for a manifest authorized from an
    /// MLS-bound event retained by this reducer.
    #[must_use]
    pub fn authorized_attachment_manifest(
        &self,
        event_id: &EventReference,
    ) -> Option<AuthorizedAttachmentManifest> {
        let node = self.graph.get(event_id)?;
        if !node.mls_bound || !node.application_authorized || node.kind != EventKind::FileManifest {
            return None;
        }
        let manifest = node.attachment_manifest.as_ref()?;
        Some(AuthorizedAttachmentManifest {
            event_id: *event_id,
            manifest: manifest.clone(),
        })
    }
    /// Returns a candidate Space mask unless this generation is conflicted.
    /// A returned mask is not an authorization grant until integration gates
    /// described in the module documentation are connected.
    #[must_use]
    pub fn effective_space_permissions(&self, member: &Fingerprint) -> Option<u64> {
        if self.conflicted {
            return None;
        }
        self.policy
            .as_ref()
            .map(|policy| effective_space(policy, member))
    }

    /// Returns `None` for a conflicted generation, unknown/archived channel,
    /// or inactive member. Returned masks remain candidate-only.
    #[must_use]
    pub fn effective_channel_permissions(
        &self,
        member: &Fingerprint,
        channel_id: &EntityId,
    ) -> Option<u64> {
        if self.conflicted {
            return None;
        }
        let policy = self.policy.as_ref()?;
        if member_status(policy, member) != Some(MemberStatus::Active) {
            return None;
        }
        let channel = find_channel(policy, channel_id)?;
        if channel.archived {
            return None;
        }
        Some(channel_effective(policy, channel, member))
    }

    #[must_use]
    pub fn conflict_evidence(&self) -> &[ConflictEvidence] {
        &self.conflict_evidence
    }

    #[must_use]
    pub fn quarantined_event_ids(&self) -> &[EventReference] {
        &self.quarantined_event_ids
    }

    /// Records an authenticated signed event only as an outer-parent graph
    /// dependency. This does not authorize it or establish its MLS state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed parent lists, conflicting metadata for
    /// an already observed ID, or an exceeded graph bound.
    pub fn observe_graph_event(
        &mut self,
        event: &VerifiedSignatureOnlyEvent,
    ) -> Result<(), RejectReason> {
        self.register_event(event, None, false)
    }

    /// Records a signed kind-7 event only when a staged MLS proof matches it.
    ///
    /// The proof binds the exact TLS Commit bytes, group, parent epoch, author,
    /// changed member, and (for an Add) exact `KeyPackage` hash. It is produced by
    /// `GroupState::take_staged_membership_change`; passing it consumes the
    /// one-shot proof, which exists only while that Commit is staged.
    ///
    /// # Errors
    ///
    /// Returns an error when the signed event does not exactly match the MLS
    /// proof, or the generation graph reaches its bound.
    pub fn observe_validated_control_event(
        &mut self,
        event: &VerifiedSignatureOnlyEvent,
        proof: lattice_mls::api::ValidatedMlsMembershipChange,
    ) -> Result<(), RejectReason> {
        let binding = proof
            .into_control_binding(
                event.mls_group_reference(),
                event.mls_epoch(),
                event.author_fingerprint(),
                event.protected_body(),
            )
            .ok_or(RejectReason::InvalidControlRelation)?;
        if event.kind() != EventKind::MlsControl || event.channel_id().is_some() {
            return Err(RejectReason::InvalidControlRelation);
        }
        let relation = ValidatedMlsControlRelation {
            space_id: *event.space_id(),
            group_reference: *event.mls_group_reference(),
            control_event_id: *event.event_id().as_bytes(),
            author: *event.author_fingerprint(),
            parent_epoch: event.mls_epoch(),
            mls_action: binding.action(),
            target: *binding.target(),
            key_package_hash: binding.key_package_hash().copied(),
        };
        self.register_event(event, Some(relation), true)
    }

    /// Reconstructs a previously validated relation from AEAD-protected local
    /// evidence. Callers must authenticate the evidence with the device-local
    /// storage key before invoking this method.
    pub(crate) fn observe_persisted_control_event(
        &mut self,
        event: &VerifiedSignatureOnlyEvent,
        action: lattice_mls::api::MlsMembershipAction,
        target: Fingerprint,
        key_package_hash: Option<[u8; 32]>,
    ) -> Result<(), RejectReason> {
        if event.kind() != EventKind::MlsControl
            || event.channel_id().is_some()
            || (action == lattice_mls::api::MlsMembershipAction::Add) != key_package_hash.is_some()
        {
            return Err(RejectReason::InvalidControlRelation);
        }
        self.register_event(
            event,
            Some(ValidatedMlsControlRelation {
                space_id: *event.space_id(),
                group_reference: *event.mls_group_reference(),
                control_event_id: *event.event_id().as_bytes(),
                author: *event.author_fingerprint(),
                parent_epoch: event.mls_epoch(),
                mls_action: action,
                target,
                key_package_hash,
            }),
            true,
        )
    }

    /// Authorizes one recovery Genesis using the prior generation's retained
    /// common policy and the event's MLS-authenticated creator.
    ///
    /// The supplied event must be a root Membership event at epoch zero in a
    /// distinct group and must contain the exact recovery references. The
    /// creator must currently hold both Space management and member-invite
    /// permissions in this reducer. The returned proof is bound to this event;
    /// it cannot authorize another root or group.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason::InvalidRecoveryAuthorization`] when the event is
    /// not a valid recovery root for this generation or its author lacks the
    /// required permission. Returns the relevant payload/schema error when the
    /// recovery operation cannot be decoded.
    pub fn authorize_recovery_genesis(
        &self,
        event: &MlsBoundEvent,
    ) -> Result<RecoveryAuthorization, RejectReason> {
        let policy = self
            .policy
            .as_ref()
            .ok_or(RejectReason::InvalidRecoveryAuthorization)?;
        let verified = event.event();
        if verified.kind() != EventKind::Membership
            || verified.channel_id().is_some()
            || verified.space_id() != &policy.space_id
            || verified.mls_group_reference() == &policy.group_reference
            || verified.mls_epoch() != 0
            || !verified.parents().is_empty()
            || event.plaintext().len() > MAX_SPACE_PAYLOAD_BYTES
        {
            return Err(RejectReason::InvalidRecoveryAuthorization);
        }
        let payload = decode_canonical(event.plaintext())
            .map_err(|_| RejectReason::InvalidCanonicalPayload)?;
        let Operation::RecoveryGenesis {
            creator,
            prior_group,
            prior_root,
            recovery_id,
            ..
        } = parse_operation(&payload)?
        else {
            return Err(RejectReason::InvalidRecoveryAuthorization);
        };
        if creator != *verified.author_fingerprint()
            || prior_group != policy.group_reference
            || prior_root != policy.root_event_id
        {
            return Err(RejectReason::InvalidRecoveryAuthorization);
        }
        require_permission(policy, creator, SPACE_MANAGE | MEMBER_INVITE)
            .map_err(|_| RejectReason::InvalidRecoveryAuthorization)?;
        Ok(RecoveryAuthorization {
            prior_space_id: policy.space_id,
            prior_group_reference: policy.group_reference,
            prior_root_event_id: policy.root_event_id,
            trusted_administrator: creator,
            recovery_id,
            new_group_reference: *verified.mls_group_reference(),
            recovery_event_id: *verified.event_id().as_bytes(),
        })
    }

    /// Applies one exact kind-6 candidate application payload. Event metadata
    /// comes exclusively from `MlsBoundEvent`; canonical CBOR is decoded from
    /// its exact MLS-produced plaintext. No caller-supplied `verified` flag or
    /// outer metadata is accepted.
    pub fn apply(
        &mut self,
        event: &MlsBoundEvent,
        recovery: Option<&RecoveryAuthorization>,
    ) -> ApplyResult {
        let verified_event = event.event();
        if verified_event.kind() != EventKind::Membership {
            return ApplyResult::Rejected(RejectReason::WrongEventKind);
        }
        if verified_event.channel_id().is_some() {
            return ApplyResult::Rejected(RejectReason::NonNullChannel);
        }
        if event.plaintext().len() > MAX_SPACE_PAYLOAD_BYTES {
            return ApplyResult::Rejected(RejectReason::PayloadTooLarge);
        }
        let id = *verified_event.event_id().as_bytes();
        if self.is_accepted(id) {
            let revision = self.policy.as_ref().map_or(0, |policy| policy.revision);
            return ApplyResult::Replay { revision };
        }
        if self
            .pending
            .iter()
            .any(|pending| pending.metadata.event_id == id)
        {
            return ApplyResult::Pending;
        }
        if self.conflicted {
            return ApplyResult::PolicyConflicted;
        }
        if let Err(reason) = self.register_event(verified_event, None, true) {
            return ApplyResult::Rejected(reason);
        }
        let Ok(payload) = decode_canonical(event.plaintext()) else {
            return ApplyResult::Rejected(RejectReason::InvalidCanonicalPayload);
        };
        let operation = match parse_operation(&payload) {
            Ok(operation) => operation,
            Err(reason) => return ApplyResult::Rejected(reason),
        };
        let pending = PendingPolicy {
            metadata: EventMetadata::from_verified(verified_event),
            operation,
            recovery: recovery.cloned(),
            plaintext: Arc::from(event.plaintext().to_vec()),
        };
        match self.apply_ready(&pending) {
            ApplyResult::Pending => {
                if self.pending.len() >= MAX_PENDING_EVENTS {
                    return ApplyResult::Rejected(RejectReason::LimitExceeded);
                }
                self.pending.push(pending);
                ApplyResult::Pending
            }
            result => result,
        }
    }

    /// Authorizes an authenticated application event and latches its in-memory action.
    ///
    /// The event and its exact MLS plaintext are sourced from `MlsBoundEvent`.
    /// This candidate gate requires every current policy head in the event's
    /// transitive parent graph and rejects payload actions without a supported
    /// exact schema.
    pub fn authorize_application_event(&mut self, event: &MlsBoundEvent) -> EventAuthorization {
        let verified_event = event.event();
        if !matches!(
            verified_event.kind(),
            EventKind::Message
                | EventKind::Edit
                | EventKind::Tombstone
                | EventKind::Reaction
                | EventKind::Pin
                | EventKind::FileManifest
                | EventKind::VoiceSignal
        ) {
            return EventAuthorization::Rejected(RejectReason::WrongEventKind);
        }
        if event.plaintext().len() > MAX_SPACE_PAYLOAD_BYTES {
            return EventAuthorization::Rejected(RejectReason::PayloadTooLarge);
        }
        if self.conflicted {
            return EventAuthorization::PolicyConflicted;
        }
        if let Err(reason) = self.register_event(verified_event, None, true) {
            return EventAuthorization::Rejected(reason);
        }
        let metadata = EventMetadata::from_verified(verified_event);
        let ancestors = match self.ancestor_set(&metadata) {
            Ok(ancestors) => ancestors,
            Err(AncestorError::Pending) => return EventAuthorization::Pending,
            Err(AncestorError::Rejected(reason)) => {
                return EventAuthorization::Rejected(reason);
            }
        };
        let Some(policy) = self.policy.as_ref() else {
            return EventAuthorization::Rejected(RejectReason::MissingPolicy);
        };
        if policy.space_id != metadata.space_id
            || policy.group_reference != metadata.group_reference
        {
            return EventAuthorization::Rejected(RejectReason::WrongGeneration);
        }
        if !policy.heads.iter().all(|head| ancestors.contains(head)) {
            return EventAuthorization::Rejected(RejectReason::IncompletePolicyHeads);
        }
        let Some(channel_id) = verified_event.channel_id() else {
            return EventAuthorization::Rejected(RejectReason::NonNullChannel);
        };
        let Some(channel) = find_channel(policy, channel_id) else {
            return EventAuthorization::Rejected(RejectReason::UnknownEntity);
        };
        if channel.archived {
            return EventAuthorization::Rejected(RejectReason::UnknownEntity);
        }
        let (action, attachment_manifest) =
            match parse_application_action(verified_event.kind(), event.plaintext()) {
                Ok(parsed) => parsed,
                Err(reason) => return EventAuthorization::Rejected(reason),
            };
        if channel.channel_type == ChannelType::Voice {
            return EventAuthorization::Rejected(RejectReason::WrongChannelType);
        }
        let required_permissions =
            match application_permissions(&action, &metadata, &self.graph, &ancestors, policy) {
                Ok(required) => required,
                Err(reason) => return EventAuthorization::Rejected(reason),
            };
        if member_status(policy, &metadata.author) != Some(MemberStatus::Active)
            || channel_effective(policy, channel, &metadata.author) & required_permissions
                != required_permissions
        {
            return EventAuthorization::Rejected(RejectReason::Unauthorized);
        }
        if let Err(reason) =
            self.retain_application_action(metadata.event_id, action, attachment_manifest)
        {
            return EventAuthorization::Rejected(reason);
        }
        EventAuthorization::Authorized {
            required_permissions,
        }
    }

    fn retain_application_action(
        &mut self,
        event_id: EventReference,
        action: ApplicationAction,
        attachment_manifest: Option<AttachmentManifest>,
    ) -> Result<(), RejectReason> {
        let reaction_tag = match &action {
            ApplicationAction::Reaction {
                target,
                token,
                add: true,
                ..
            } => Some(ReactionTag {
                target: *target,
                token: token.clone(),
            }),
            _ => None,
        };
        let current_node = self.graph.get(&event_id);
        if reaction_tag.as_ref().is_some_and(|reaction_tag| {
            current_node
                .and_then(|node| node.reaction_tag.as_ref())
                .is_some_and(|existing| existing != reaction_tag)
        }) {
            return Err(RejectReason::GraphConflict);
        }
        if attachment_manifest.is_some() != matches!(&action, ApplicationAction::FileManifest) {
            return Err(RejectReason::GraphConflict);
        }
        if current_node
            .and_then(|node| node.attachment_manifest.as_ref())
            .is_some_and(|existing| Some(existing) != attachment_manifest.as_ref())
        {
            return Err(RejectReason::GraphConflict);
        }
        let current_action = current_node.and_then(|node| node.application_action.as_ref());
        if current_action.is_some_and(|existing| existing != &action) {
            return Err(RejectReason::GraphConflict);
        }
        let manifest_bytes = attachment_manifest.as_ref().map_or(0, |manifest| {
            manifest.filename.len()
                + manifest.mime_type.as_ref().map_or(0, String::len)
                + manifest.chunk_hashes.len() * std::mem::size_of::<[u8; 32]>()
        });
        let additional_history_bytes = if current_action.is_none() {
            action.retained_bytes() + manifest_bytes
        } else {
            0
        };
        let next_history_bytes = self
            .message_history_bytes
            .checked_add(additional_history_bytes)
            .ok_or(RejectReason::LimitExceeded)?;
        if next_history_bytes > MAX_MESSAGE_HISTORY_BYTES {
            return Err(RejectReason::LimitExceeded);
        }
        let node = self
            .graph
            .get_mut(&event_id)
            .ok_or(RejectReason::GraphConflict)?;
        node.application_authorized = true;
        node.application_action = Some(action);
        if attachment_manifest.is_some() {
            node.attachment_manifest = attachment_manifest;
        }
        if reaction_tag.is_some() {
            node.reaction_tag = reaction_tag;
        }
        self.message_history_bytes = next_history_bytes;
        Ok(())
    }

    /// Re-attempts retained pending kind-6 operations after graph dependencies
    /// have arrived. Pending order is not authority: any valid siblings latch a
    /// conflict and neither branch remains projected.
    #[must_use]
    pub fn retry_pending(&mut self) -> Vec<PendingResult> {
        let pending = std::mem::take(&mut self.pending);
        let mut remaining = Vec::new();
        let mut results = Vec::new();
        for item in pending {
            if self.conflicted {
                results.push(PendingResult {
                    event_id: item.metadata.event_id,
                    result: ApplyResult::PolicyConflicted,
                });
                continue;
            }
            let result = self.apply_ready(&item);
            if result == ApplyResult::Pending {
                remaining.push(item);
            } else {
                results.push(PendingResult {
                    event_id: item.metadata.event_id,
                    result,
                });
            }
        }
        self.pending = remaining;
        results
    }

    fn register_event(
        &mut self,
        event: &VerifiedSignatureOnlyEvent,
        relation: Option<ValidatedMlsControlRelation>,
        mls_bound: bool,
    ) -> Result<(), RejectReason> {
        let id = *event.event_id().as_bytes();
        let parents = event
            .parents()
            .iter()
            .map(|parent| *parent.as_bytes())
            .collect::<Vec<_>>();
        if parents.len() > MAX_PARENTS || parents.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RejectReason::InvalidOuterParents);
        }
        if relation.is_some() && event.kind() != EventKind::MlsControl {
            return Err(RejectReason::InvalidControlRelation);
        }
        if let Some(relation) = relation.as_ref()
            && (relation.control_event_id != id
                || relation.space_id != *event.space_id()
                || relation.group_reference != *event.mls_group_reference()
                || relation.author != *event.author_fingerprint()
                || relation.parent_epoch != event.mls_epoch()
                || event.channel_id().is_some()
                || (relation.mls_action == lattice_mls::api::MlsMembershipAction::Add)
                    != relation.key_package_hash.is_some())
        {
            return Err(RejectReason::InvalidControlRelation);
        }
        let node = GraphNode {
            space_id: *event.space_id(),
            group_reference: *event.mls_group_reference(),
            author: *event.author_fingerprint(),
            kind: event.kind(),
            epoch: event.mls_epoch(),
            lamport: event.lamport(),
            author_sequence: event.author_sequence(),
            parents,
            channel_id: event.channel_id().copied(),
            control_relation: relation,
            mls_bound,
            application_authorized: false,
            application_action: None,
            attachment_manifest: None,
            reaction_tag: None,
        };
        if let Some(previous) = self.graph.get(&id) {
            if previous.space_id != node.space_id
                || previous.group_reference != node.group_reference
                || previous.author != node.author
                || previous.kind != node.kind
                || previous.epoch != node.epoch
                || previous.lamport != node.lamport
                || previous.author_sequence != node.author_sequence
                || previous.parents != node.parents
                || previous.channel_id != node.channel_id
                || previous.control_relation.is_some()
                    && node.control_relation.is_some()
                    && previous.control_relation != node.control_relation
            {
                return Err(RejectReason::GraphConflict);
            }
            let mut upgraded = previous.clone();
            if node.control_relation.is_some() {
                upgraded.control_relation = node.control_relation;
            }
            upgraded.mls_bound |= node.mls_bound;
            upgraded.application_authorized |= node.application_authorized;
            if &upgraded != previous {
                self.graph.insert(id, upgraded);
            }
            return Ok(());
        }
        if self.graph.len() >= MAX_GRAPH_EVENTS {
            return Err(RejectReason::LimitExceeded);
        }
        self.graph.insert(id, node);
        Ok(())
    }

    fn apply_ready(&mut self, pending: &PendingPolicy) -> ApplyResult {
        let id = pending.metadata.event_id;
        if self.is_accepted(id) {
            let revision = self.policy.as_ref().map_or(0, |policy| policy.revision);
            return ApplyResult::Replay { revision };
        }
        let ancestors = match self.ancestor_set(&pending.metadata) {
            Ok(ancestors) => ancestors,
            Err(AncestorError::Pending) => return ApplyResult::Pending,
            Err(AncestorError::Rejected(reason)) => return ApplyResult::Rejected(reason),
        };
        match pending.operation.clone() {
            Operation::Genesis { creator, channels } => {
                self.apply_genesis(pending, creator, channels)
            }
            Operation::RecoveryGenesis {
                creator,
                prior_group,
                prior_root,
                recovery_id,
                channels,
            } => self.apply_recovery_genesis(
                pending,
                creator,
                prior_group,
                prior_root,
                recovery_id,
                channels,
            ),
            operation => self.apply_post_root(pending, operation, &ancestors),
        }
    }

    fn apply_genesis(
        &mut self,
        pending: &PendingPolicy,
        creator: Fingerprint,
        channels: Vec<Channel>,
    ) -> ApplyResult {
        let metadata = &pending.metadata;
        if !metadata.parents.is_empty() || metadata.epoch != 0 {
            return ApplyResult::Rejected(RejectReason::InvalidGenesisContext);
        }
        if creator != metadata.author {
            return ApplyResult::Rejected(RejectReason::CreatorMismatch);
        }
        if pending.recovery.is_some() {
            return ApplyResult::Rejected(RejectReason::InvalidRecoveryAuthorization);
        }
        if channels.is_empty() || channels.len() > MAX_INITIAL_CHANNELS {
            return ApplyResult::Rejected(RejectReason::InvalidValue);
        }
        if channels.iter().any(|channel| {
            channel
                .role_overrides
                .iter()
                .any(|item| !is_builtin_role(&item.role_id))
        }) {
            return ApplyResult::Rejected(RejectReason::UnknownEntity);
        }
        if self.conflicted {
            return ApplyResult::PolicyConflicted;
        }
        if let Some(policy) = self.policy.as_ref() {
            if policy.space_id != metadata.space_id
                || policy.group_reference != metadata.group_reference
            {
                return ApplyResult::Rejected(RejectReason::WrongGeneration);
            }
            return self.handle_second_root(pending);
        }
        let channel_order = channels.iter().map(|channel| channel.id).collect();
        let policy = SpacePolicy {
            space_id: metadata.space_id,
            group_reference: metadata.group_reference,
            root_event_id: metadata.event_id,
            root_author: creator,
            revision: 0,
            heads: vec![metadata.event_id],
            channels,
            channel_order,
            custom_roles: Vec::new(),
            members: vec![Member {
                fingerprint: creator,
                status: MemberStatus::Active,
                assigned_roles: vec![BUILTIN_ROLE_IDS[0]],
            }],
            invites: Vec::new(),
        };
        self.history_base = Some(policy.clone());
        self.policy = Some(policy);
        self.root_signed_event = Some(metadata.signed_event.clone());
        self.history.clear();
        ApplyResult::Applied { revision: 0 }
    }

    fn apply_recovery_genesis(
        &mut self,
        pending: &PendingPolicy,
        creator: Fingerprint,
        prior_group: GroupReference,
        prior_root: EventReference,
        recovery_id: EntityId,
        channels: Vec<Channel>,
    ) -> ApplyResult {
        let metadata = &pending.metadata;
        let Some(authorization) = pending.recovery.as_ref() else {
            return ApplyResult::Rejected(RejectReason::InvalidRecoveryAuthorization);
        };
        if !metadata.parents.is_empty()
            || metadata.epoch != 0
            || creator != metadata.author
            || authorization.prior_space_id != metadata.space_id
            || authorization.prior_group_reference != prior_group
            || authorization.prior_root_event_id != prior_root
            || authorization.trusted_administrator != creator
            || authorization.recovery_id != recovery_id
            || authorization.new_group_reference != metadata.group_reference
            || authorization.recovery_event_id != metadata.event_id
            || metadata.group_reference == prior_group
        {
            return ApplyResult::Rejected(RejectReason::InvalidRecoveryAuthorization);
        }
        if self.conflicted {
            return ApplyResult::PolicyConflicted;
        }
        if channels.is_empty() || channels.len() > MAX_INITIAL_CHANNELS {
            return ApplyResult::Rejected(RejectReason::InvalidValue);
        }
        if channels.iter().any(|channel| {
            channel
                .role_overrides
                .iter()
                .any(|item| !is_builtin_role(&item.role_id))
        }) {
            return ApplyResult::Rejected(RejectReason::UnknownEntity);
        }
        if let Some(policy) = self.policy.as_ref() {
            if policy.space_id != metadata.space_id
                || policy.group_reference != metadata.group_reference
            {
                return ApplyResult::Rejected(RejectReason::WrongGeneration);
            }
            return self.handle_second_root(pending);
        }
        let channel_order = channels.iter().map(|channel| channel.id).collect();
        let policy = SpacePolicy {
            space_id: metadata.space_id,
            group_reference: metadata.group_reference,
            root_event_id: metadata.event_id,
            root_author: creator,
            revision: 0,
            heads: vec![metadata.event_id],
            channels,
            channel_order,
            custom_roles: Vec::new(),
            members: vec![Member {
                fingerprint: creator,
                status: MemberStatus::Active,
                assigned_roles: vec![BUILTIN_ROLE_IDS[0]],
            }],
            invites: Vec::new(),
        };
        self.history_base = Some(policy.clone());
        self.policy = Some(policy);
        self.root_signed_event = Some(metadata.signed_event.clone());
        self.history.clear();
        ApplyResult::Applied { revision: 0 }
    }

    fn handle_second_root(&mut self, pending: &PendingPolicy) -> ApplyResult {
        let Some(policy) = self.policy.as_ref() else {
            return ApplyResult::PolicyConflicted;
        };
        if policy.space_id != pending.metadata.space_id
            || policy.group_reference != pending.metadata.group_reference
        {
            return ApplyResult::Rejected(RejectReason::WrongGeneration);
        }
        let old_root_id = policy.root_event_id;
        let old_root = ConflictEvidence {
            event_id: old_root_id,
            signed_event: self
                .root_signed_event
                .clone()
                .unwrap_or_else(|| Arc::from([])),
        };
        self.insert_conflict_evidence(old_root);
        self.insert_conflict_evidence(ConflictEvidence {
            event_id: pending.metadata.event_id,
            signed_event: pending.metadata.signed_event.clone(),
        });
        self.conflicted = true;
        self.policy = None;
        self.history_base = None;
        self.root_signed_event = None;
        self.history.clear();
        self.quarantined_event_ids.clear();
        self.quarantined_event_ids.push(old_root_id);
        self.quarantined_event_ids.push(pending.metadata.event_id);
        self.sort_quarantined();
        ApplyResult::PolicyConflicted
    }

    fn apply_post_root(
        &mut self,
        pending: &PendingPolicy,
        operation: Operation,
        ancestors: &std::collections::BTreeSet<EventReference>,
    ) -> ApplyResult {
        if self.conflicted {
            return ApplyResult::PolicyConflicted;
        }
        let Some(policy) = self.policy.as_ref() else {
            return ApplyResult::Rejected(RejectReason::MissingPolicy);
        };
        if policy.space_id != pending.metadata.space_id
            || policy.group_reference != pending.metadata.group_reference
        {
            return ApplyResult::Rejected(RejectReason::WrongGeneration);
        }
        let base_revision = policy.revision;
        let Some(revision) = base_revision.checked_add(1) else {
            return ApplyResult::Rejected(RejectReason::RevisionOverflow);
        };
        if !policy.heads.iter().all(|head| ancestors.contains(head)) {
            return self.detect_policy_fork(pending, &operation, ancestors);
        }
        if self.history.len() >= MAX_POLICY_HISTORY {
            return ApplyResult::Rejected(RejectReason::LimitExceeded);
        }
        let Some(policy) = self.policy.as_mut() else {
            return ApplyResult::Rejected(RejectReason::MissingPolicy);
        };
        match apply_operation(
            policy,
            pending.metadata.author,
            pending.metadata.event_id,
            &operation,
            &self.graph,
            ancestors,
            pending.metadata.epoch,
        ) {
            Ok(()) => {
                let base_heads = policy.heads.clone();
                policy.revision = revision;
                policy.heads.clear();
                policy.heads.push(pending.metadata.event_id);
                self.history.push(AcceptedPolicyEvent {
                    event_id: pending.metadata.event_id,
                    base_heads,
                    parents: pending.metadata.parents.clone(),
                    base_revision,
                    author: pending.metadata.author,
                    epoch: pending.metadata.epoch,
                    operation,
                    signed_event: pending.metadata.signed_event.clone(),
                    plaintext: pending.plaintext.clone(),
                });
                ApplyResult::Applied { revision }
            }
            Err(reason) => ApplyResult::Rejected(reason),
        }
    }

    fn detect_policy_fork(
        &mut self,
        pending: &PendingPolicy,
        operation: &Operation,
        ancestors: &std::collections::BTreeSet<EventReference>,
    ) -> ApplyResult {
        // The latest causally shared accepted head is the common base. This
        // determines only which prior projection to restore; it chooses neither
        // sibling branch.
        let common_index = self
            .history
            .iter()
            .enumerate()
            .filter(|(_, accepted)| {
                !ancestors.contains(&accepted.event_id)
                    && accepted
                        .base_heads
                        .iter()
                        .all(|head| ancestors.contains(head))
            })
            .max_by_key(|(_, accepted)| accepted.base_revision)
            .map(|(index, _)| index);
        let Some(index) = common_index else {
            return ApplyResult::Rejected(RejectReason::IncompletePolicyHeads);
        };
        let Some(mut sibling_projection) = self.replay_prefix(index) else {
            return ApplyResult::Rejected(RejectReason::GraphConflict);
        };
        if sibling_projection.revision.checked_add(1).is_none() {
            return ApplyResult::Rejected(RejectReason::RevisionOverflow);
        }
        if let Err(reason) = apply_operation(
            &mut sibling_projection,
            pending.metadata.author,
            pending.metadata.event_id,
            operation,
            &self.graph,
            ancestors,
            pending.metadata.epoch,
        ) {
            return ApplyResult::Rejected(reason);
        }
        let fork = self.history[index].clone();
        let Some(restored) = self.replay_prefix(index) else {
            return ApplyResult::Rejected(RejectReason::GraphConflict);
        };
        let mut quarantined = self.history[index..]
            .iter()
            .map(|accepted| accepted.event_id)
            .collect::<Vec<_>>();
        quarantined.push(pending.metadata.event_id);
        quarantined.sort_unstable();
        quarantined.dedup();
        self.quarantined_event_ids = quarantined;
        self.insert_conflict_evidence(ConflictEvidence {
            event_id: fork.event_id,
            signed_event: fork.signed_event,
        });
        self.insert_conflict_evidence(ConflictEvidence {
            event_id: pending.metadata.event_id,
            signed_event: pending.metadata.signed_event.clone(),
        });
        self.history.truncate(index);
        self.conflicted = true;
        self.policy = Some(restored);
        ApplyResult::PolicyConflicted
    }

    fn replay_prefix(&self, length: usize) -> Option<SpacePolicy> {
        let mut policy = self.history_base.as_ref()?.clone();
        if length > self.history.len() {
            return None;
        }
        for record in self.history.iter().take(length) {
            if policy.revision != record.base_revision || policy.heads != record.base_heads {
                return None;
            }
            let metadata = EventMetadata {
                space_id: policy.space_id,
                group_reference: policy.group_reference,
                event_id: record.event_id,
                author: record.author,
                epoch: record.epoch,
                parents: record.parents.clone(),
                signed_event: record.signed_event.clone(),
            };
            let ancestors = self.ancestor_set(&metadata).ok()?;
            let next_revision = policy.revision.checked_add(1)?;
            apply_operation(
                &mut policy,
                record.author,
                record.event_id,
                &record.operation,
                &self.graph,
                &ancestors,
                record.epoch,
            )
            .ok()?;
            policy.revision = next_revision;
            policy.heads.clear();
            policy.heads.push(record.event_id);
        }
        Some(policy)
    }

    fn ancestor_set(
        &self,
        metadata: &EventMetadata,
    ) -> Result<std::collections::BTreeSet<EventReference>, AncestorError> {
        let mut ancestors = std::collections::BTreeSet::new();
        let mut active = std::collections::BTreeSet::new();
        let mut visited = std::collections::BTreeSet::new();
        let mut stack = metadata
            .parents
            .iter()
            .rev()
            .map(|id| (*id, false))
            .collect::<Vec<_>>();
        while let Some((id, exiting)) = stack.pop() {
            if exiting {
                active.remove(&id);
                visited.insert(id);
                continue;
            }
            if visited.contains(&id) {
                continue;
            }
            if !active.insert(id) {
                return Err(AncestorError::Rejected(RejectReason::GraphConflict));
            }
            let Some(node) = self.graph.get(&id) else {
                return Err(AncestorError::Pending);
            };
            if node.space_id != metadata.space_id
                || node.group_reference != metadata.group_reference
            {
                return Err(AncestorError::Rejected(RejectReason::WrongGeneration));
            }
            ancestors.insert(id);
            if ancestors.len() > MAX_GRAPH_EVENTS {
                return Err(AncestorError::Rejected(RejectReason::LimitExceeded));
            }
            if self.bootstrap_anchors.contains(&id) {
                visited.insert(id);
                continue;
            }
            stack.push((id, true));
            for parent in node.parents.iter().rev() {
                stack.push((*parent, false));
            }
        }
        Ok(ancestors)
    }

    fn insert_conflict_evidence(&mut self, evidence: ConflictEvidence) {
        if let Some(existing) = self
            .conflict_evidence
            .iter_mut()
            .find(|item| item.event_id == evidence.event_id)
        {
            *existing = evidence;
        } else {
            self.conflict_evidence.push(evidence);
        }
        self.conflict_evidence
            .sort_unstable_by_key(|item| item.event_id);
        self.conflict_evidence.truncate(MAX_CONFLICT_WITNESSES);
    }

    fn sort_quarantined(&mut self) {
        self.quarantined_event_ids.sort_unstable();
        self.quarantined_event_ids.dedup();
        self.quarantined_event_ids.truncate(MAX_CONFLICT_WITNESSES);
    }

    fn is_accepted(&self, id: EventReference) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| policy.root_event_id == id)
            || self.history.iter().any(|record| record.event_id == id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventMetadata {
    space_id: SpaceId,
    group_reference: GroupReference,
    event_id: EventReference,
    author: Fingerprint,
    epoch: u64,
    parents: Vec<EventReference>,
    signed_event: Arc<[u8]>,
}

impl EventMetadata {
    fn from_verified(event: &VerifiedSignatureOnlyEvent) -> Self {
        Self {
            space_id: *event.space_id(),
            group_reference: *event.mls_group_reference(),
            event_id: *event.event_id().as_bytes(),
            author: *event.author_fingerprint(),
            epoch: event.mls_epoch(),
            parents: event
                .parents()
                .iter()
                .map(|parent| *parent.as_bytes())
                .collect(),
            signed_event: Arc::from(event.encode().to_vec()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GraphNode {
    space_id: SpaceId,
    group_reference: GroupReference,
    author: Fingerprint,
    kind: EventKind,
    epoch: u64,
    lamport: u64,
    author_sequence: u64,
    parents: Vec<EventReference>,
    channel_id: Option<EntityId>,
    control_relation: Option<ValidatedMlsControlRelation>,
    mls_bound: bool,
    application_authorized: bool,
    application_action: Option<ApplicationAction>,
    attachment_manifest: Option<AttachmentManifest>,
    reaction_tag: Option<ReactionTag>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReactionTag {
    target: EventReference,
    token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingPolicy {
    metadata: EventMetadata,
    operation: Operation,
    recovery: Option<RecoveryAuthorization>,
    plaintext: Arc<[u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedPolicyEvent {
    event_id: EventReference,
    parents: Vec<EventReference>,
    base_heads: Vec<EventReference>,
    base_revision: u64,
    author: Fingerprint,
    epoch: u64,
    operation: Operation,
    signed_event: Arc<[u8]>,
    plaintext: Arc<[u8]>,
}

/// Exact signed policy event bytes and the locally authenticated MLS plaintext
/// needed to replay an accepted policy projection after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpacePolicyReplayEvent {
    pub(crate) event_bytes: Vec<u8>,
    pub(crate) plaintext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AncestorError {
    Pending,
    Rejected(RejectReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Operation {
    Genesis {
        creator: Fingerprint,
        channels: Vec<Channel>,
    },
    RecoveryGenesis {
        creator: Fingerprint,
        prior_group: GroupReference,
        prior_root: EventReference,
        recovery_id: EntityId,
        channels: Vec<Channel>,
    },
    Invite {
        id: EntityId,
        target: Fingerprint,
        key_package_hash: [u8; 32],
        expires_at_revision: Option<u64>,
        max_uses: Option<u16>,
    },
    SetChannel(Channel),
    SetCustomRole(CustomRole),
    SetRoleAssignment {
        member: Fingerprint,
        role_id: EntityId,
        assign: bool,
    },
    MemberTransition {
        action: MemberAction,
        target: Fingerprint,
        invite_event_id: Option<EventReference>,
        control_event_id: EventReference,
    },
    SetChannelOrder(Vec<EntityId>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ApplicationAction {
    Message {
        content: Arc<str>,
        thread_root: Option<EventReference>,
        mention_everyone: bool,
        mentions: Vec<MentionTarget>,
        attachments: Vec<EventReference>,
    },
    Edit {
        target: EventReference,
        content: Arc<str>,
    },
    Tombstone {
        target: EventReference,
        moderation_reason: Option<String>,
    },
    Reaction {
        target: EventReference,
        token: String,
        add: bool,
        tag: Option<EventReference>,
    },
    Pin {
        target: EventReference,
        add: bool,
        tag: Option<EventReference>,
    },
    FileManifest,
}
impl ApplicationAction {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Message {
                content, mentions, ..
            } => content
                .len()
                .saturating_add(mentions.len().saturating_mul(33)),
            Self::Edit { content, .. } => content.len(),
            Self::Tombstone {
                moderation_reason, ..
            } => moderation_reason.as_ref().map_or(0, String::len),
            Self::Reaction { token, .. } => token.len(),
            Self::Pin { .. } | Self::FileManifest => 0,
        }
    }
}

// Keep the exhaustive authorization transition table together for auditability.
#[allow(clippy::too_many_lines)]
fn apply_operation(
    policy: &mut SpacePolicy,
    author: Fingerprint,
    event_id: EventReference,
    operation: &Operation,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
    event_epoch: u64,
) -> Result<(), RejectReason> {
    match operation {
        Operation::Genesis { .. } | Operation::RecoveryGenesis { .. } => {
            Err(RejectReason::InvalidGenesisContext)
        }
        Operation::Invite {
            id,
            target,
            key_package_hash,
            expires_at_revision,
            max_uses,
        } => {
            require_permission(policy, author, SPACE_MANAGE | MEMBER_INVITE)?;
            if policy.invites.len() >= MAX_INVITES {
                return Err(RejectReason::LimitExceeded);
            }
            if policy.invites.iter().any(|invite| invite.id == *id) {
                return Err(RejectReason::DuplicateEntity);
            }
            if *target == author && active_member(policy, target) {
                return Err(RejectReason::InvalidTransition);
            }
            if active_member(policy, target)
                || member_status(policy, target) == Some(MemberStatus::Banned)
            {
                return Err(RejectReason::InvalidTransition);
            }
            if let Some(expiry) = expires_at_revision {
                let minimum = policy
                    .revision
                    .checked_add(1)
                    .ok_or(RejectReason::RevisionOverflow)?;
                if *expiry <= minimum {
                    return Err(RejectReason::InvalidValue);
                }
            }
            if policy
                .members
                .iter()
                .all(|member| member.fingerprint != *target)
                && policy.members.len() >= MAX_MEMBERS
            {
                return Err(RejectReason::LimitExceeded);
            }
            if policy
                .members
                .iter()
                .all(|member| member.fingerprint != *target)
            {
                policy.members.push(Member {
                    fingerprint: *target,
                    status: MemberStatus::Invited,
                    assigned_roles: Vec::new(),
                });
            }
            policy.invites.push(Invite {
                id: *id,
                event_id,
                target: *target,
                key_package_hash: *key_package_hash,
                expires_at_revision: *expires_at_revision,
                max_uses: *max_uses,
                uses: 0,
            });
            Ok(())
        }
        Operation::SetChannel(channel) => {
            require_permission(policy, author, SPACE_MANAGE | CHANNEL_MANAGE)?;
            validate_channel_roles(policy, channel)?;
            let current = find_channel(policy, &channel.id);
            if let Some(previous) = current {
                if previous.channel_type != channel.channel_type {
                    return Err(RejectReason::InvalidValue);
                }
                if previous == channel {
                    return Err(RejectReason::NoStateChange);
                }
                let before = channel_effective(policy, previous, &author);
                let after = channel_effective(policy, channel, &author);
                if after & !before != 0 {
                    return Err(RejectReason::SelfEscalation);
                }
                let index = policy
                    .channels
                    .iter()
                    .position(|current| current.id == channel.id)
                    .ok_or(RejectReason::UnknownEntity)?;
                policy.channels[index] = channel.clone();
            } else {
                if policy.channels.len() >= MAX_CHANNELS {
                    return Err(RejectReason::LimitExceeded);
                }
                let space_mask = effective_space(policy, &author);
                let after = channel_effective(policy, channel, &author);
                if after & !space_mask != 0 {
                    return Err(RejectReason::SelfEscalation);
                }
                policy.channels.push(channel.clone());
                policy.channel_order.push(channel.id);
            }
            Ok(())
        }
        Operation::SetCustomRole(role) => {
            require_permission(policy, author, SPACE_MANAGE | ROLE_MANAGE)?;
            if is_builtin_role(&role.id) {
                return Err(RejectReason::InvalidValue);
            }
            let author_before = effective_space(policy, &author);
            if role.allow & !author_before != 0 {
                return Err(RejectReason::SelfEscalation);
            }
            let existing = policy
                .custom_roles
                .iter()
                .position(|current| current.id == role.id);
            if let Some(index) = existing {
                if policy.custom_roles[index] == *role {
                    return Err(RejectReason::NoStateChange);
                }
            } else if policy.custom_roles.len() >= MAX_CUSTOM_ROLES {
                return Err(RejectReason::LimitExceeded);
            }
            for member in &policy.members {
                if member.assigned_roles.contains(&role.id)
                    && effective_space_with_role(policy, &member.fingerprint, role) & !author_before
                        != 0
                {
                    return Err(RejectReason::SelfEscalation);
                }
            }
            if effective_space_with_role(policy, &author, role) & !author_before != 0 {
                return Err(RejectReason::SelfEscalation);
            }
            if let Some(index) = existing {
                policy.custom_roles[index] = role.clone();
            } else {
                policy.custom_roles.push(role.clone());
            }
            Ok(())
        }
        Operation::SetRoleAssignment {
            member,
            role_id,
            assign,
        } => {
            require_permission(policy, author, SPACE_MANAGE | ROLE_MANAGE)?;
            let Some(member_index) = policy
                .members
                .iter()
                .position(|record| record.fingerprint == *member)
            else {
                return Err(RejectReason::UnknownEntity);
            };
            if policy.members[member_index].status != MemberStatus::Active {
                return Err(RejectReason::InvalidTransition);
            }
            if *member == policy.root_author {
                return Err(RejectReason::OwnerProtected);
            }
            if *role_id == BUILTIN_ROLE_IDS[0] || *role_id == BUILTIN_ROLE_IDS[3] {
                return Err(RejectReason::OwnerProtected);
            }
            if !is_builtin_role(role_id)
                && !policy.custom_roles.iter().any(|role| role.id == *role_id)
            {
                return Err(RejectReason::UnknownEntity);
            }
            let currently_assigned = policy.members[member_index]
                .assigned_roles
                .contains(role_id);
            if currently_assigned == *assign {
                return Err(RejectReason::NoStateChange);
            }
            if *assign && *member == author {
                return Err(RejectReason::SelfEscalation);
            }
            if *assign
                && !currently_assigned
                && policy.members[member_index].assigned_roles.len()
                    >= MAX_ASSIGNED_ROLES_PER_MEMBER
            {
                return Err(RejectReason::LimitExceeded);
            }
            if *assign {
                let author_mask = effective_space(policy, &author);
                if effective_space_with_assignment(policy, member, role_id, true) & !author_mask
                    != 0
                {
                    return Err(RejectReason::SelfEscalation);
                }
                policy.members[member_index].assigned_roles.push(*role_id);
            } else {
                policy.members[member_index]
                    .assigned_roles
                    .retain(|assigned| assigned != role_id);
            }
            Ok(())
        }
        Operation::MemberTransition {
            action,
            target,
            invite_event_id,
            control_event_id,
        } => {
            let control = graph
                .get(control_event_id)
                .and_then(|node| node.control_relation.as_ref())
                .ok_or(RejectReason::InvalidControlRelation)?;
            let control_node = graph
                .get(control_event_id)
                .ok_or(RejectReason::InvalidControlRelation)?;
            let proof_matches_action = match action {
                MemberAction::Admit => {
                    control.mls_action == lattice_mls::api::MlsMembershipAction::Add
                }
                MemberAction::Remove | MemberAction::Ban => {
                    control.mls_action == lattice_mls::api::MlsMembershipAction::Remove
                }
            };
            if control_node.kind != EventKind::MlsControl
                || !ancestors.contains(control_event_id)
                || control.space_id != policy.space_id
                || control.group_reference != policy.group_reference
                || control.author != author
                || control.parent_epoch != event_epoch
                || control_node.epoch != event_epoch
                || control.target != *target
                || !proof_matches_action
            {
                return Err(RejectReason::InvalidControlRelation);
            }
            let required = match action {
                MemberAction::Admit => SPACE_MANAGE | MEMBER_INVITE,
                MemberAction::Remove => SPACE_MANAGE | MEMBER_REMOVE,
                MemberAction::Ban => SPACE_MANAGE | MEMBER_BAN,
            };
            require_permission(policy, author, required)?;
            let member_index = policy
                .members
                .iter()
                .position(|member| member.fingerprint == *target);
            match action {
                MemberAction::Admit => {
                    let Some(invite_event_id) = invite_event_id else {
                        return Err(RejectReason::InvalidTransition);
                    };
                    if !ancestors.contains(invite_event_id) {
                        return Err(RejectReason::InvalidTransition);
                    }
                    if member_status(policy, target) == Some(MemberStatus::Active)
                        || member_status(policy, target) == Some(MemberStatus::Banned)
                    {
                        return Err(RejectReason::InvalidTransition);
                    }
                    let invite_index = policy
                        .invites
                        .iter()
                        .position(|invite| invite.event_id == *invite_event_id)
                        .ok_or(RejectReason::UnknownEntity)?;
                    let invite = &policy.invites[invite_index];
                    if invite.target != *target
                        || invite
                            .expires_at_revision
                            .is_some_and(|expiry| policy.revision >= expiry)
                        || invite
                            .max_uses
                            .is_some_and(|maximum| invite.uses >= maximum)
                        || control.key_package_hash != Some(invite.key_package_hash)
                    {
                        return Err(RejectReason::InvalidTransition);
                    }
                    let use_count = policy.invites[invite_index]
                        .uses
                        .checked_add(1)
                        .ok_or(RejectReason::LimitExceeded)?;
                    if member_index.is_none() && policy.members.len() >= MAX_MEMBERS {
                        return Err(RejectReason::LimitExceeded);
                    }
                    if let Some(index) = member_index {
                        policy.members[index].status = MemberStatus::Active;
                    } else {
                        policy.members.push(Member {
                            fingerprint: *target,
                            status: MemberStatus::Active,
                            assigned_roles: Vec::new(),
                        });
                    }
                    policy.invites[invite_index].uses = use_count;
                    Ok(())
                }
                MemberAction::Remove | MemberAction::Ban => {
                    if invite_event_id.is_some()
                        || control.key_package_hash.is_some()
                        || *target == author
                    {
                        return Err(RejectReason::InvalidTransition);
                    }
                    if member_status(policy, target) != Some(MemberStatus::Active) {
                        return Err(RejectReason::InvalidTransition);
                    }
                    if *target == policy.root_author {
                        return Err(RejectReason::OwnerProtected);
                    }
                    let index = member_index.ok_or(RejectReason::UnknownEntity)?;
                    policy.members[index].status = if *action == MemberAction::Remove {
                        MemberStatus::Removed
                    } else {
                        MemberStatus::Banned
                    };
                    Ok(())
                }
            }
        }
        Operation::SetChannelOrder(order) => {
            require_permission(policy, author, SPACE_MANAGE | CHANNEL_MANAGE)?;
            if order.len() != policy.channels.len()
                || order
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != order.len()
                || policy
                    .channels
                    .iter()
                    .any(|channel| !order.contains(&channel.id))
            {
                return Err(RejectReason::InvalidValue);
            }
            if *order == policy.channel_order {
                return Err(RejectReason::NoStateChange);
            }
            policy.channel_order.clone_from(order);
            Ok(())
        }
    }
}

fn require_permission(
    policy: &SpacePolicy,
    author: Fingerprint,
    required: u64,
) -> Result<(), RejectReason> {
    let Some(member) = policy
        .members
        .iter()
        .find(|member| member.fingerprint == author)
    else {
        return Err(RejectReason::Unauthorized);
    };
    if member.status != MemberStatus::Active
        || effective_space(policy, &author) & required != required
    {
        return Err(RejectReason::Unauthorized);
    }
    Ok(())
}

pub(crate) fn effective_space(policy: &SpacePolicy, fingerprint: &Fingerprint) -> u64 {
    if *fingerprint == policy.root_author {
        return OWNER_GRANTS;
    }
    let Some(member) = policy
        .members
        .iter()
        .find(|member| member.fingerprint == *fingerprint && member.status == MemberStatus::Active)
    else {
        return 0;
    };
    let mut allow = MEMBER_BASELINE;
    let mut deny = 0;
    for role_id in &member.assigned_roles {
        if *role_id == BUILTIN_ROLE_IDS[1] {
            allow |= ADMINISTRATOR_GRANTS;
        } else if *role_id == BUILTIN_ROLE_IDS[2] {
            allow |= MODERATOR_GRANTS;
        } else if let Some(role) = policy.custom_roles.iter().find(|role| role.id == *role_id) {
            allow |= role.allow;
            deny |= role.deny;
        }
    }
    allow & !deny & SPACE_PERMISSION_MASK
}

fn effective_space_with_role(
    policy: &SpacePolicy,
    fingerprint: &Fingerprint,
    replacement: &CustomRole,
) -> u64 {
    if *fingerprint == policy.root_author {
        return OWNER_GRANTS;
    }
    let Some(member) = policy
        .members
        .iter()
        .find(|member| member.fingerprint == *fingerprint && member.status == MemberStatus::Active)
    else {
        return 0;
    };
    let mut allow = MEMBER_BASELINE;
    let mut deny = 0;
    for role_id in &member.assigned_roles {
        if *role_id == BUILTIN_ROLE_IDS[1] {
            allow |= ADMINISTRATOR_GRANTS;
        } else if *role_id == BUILTIN_ROLE_IDS[2] {
            allow |= MODERATOR_GRANTS;
        } else if *role_id == replacement.id {
            allow |= replacement.allow;
            deny |= replacement.deny;
        } else if let Some(role) = policy.custom_roles.iter().find(|role| role.id == *role_id) {
            allow |= role.allow;
            deny |= role.deny;
        }
    }
    allow & !deny & SPACE_PERMISSION_MASK
}

fn effective_space_with_assignment(
    policy: &SpacePolicy,
    fingerprint: &Fingerprint,
    role_id: &EntityId,
    assign: bool,
) -> u64 {
    if *fingerprint == policy.root_author {
        return OWNER_GRANTS;
    }
    let Some(member) = policy
        .members
        .iter()
        .find(|member| member.fingerprint == *fingerprint && member.status == MemberStatus::Active)
    else {
        return 0;
    };
    let mut allow = MEMBER_BASELINE;
    let mut deny = 0;
    for candidate in &member.assigned_roles {
        let held = if candidate == role_id { assign } else { true };
        if !held {
            continue;
        }
        if *candidate == BUILTIN_ROLE_IDS[1] {
            allow |= ADMINISTRATOR_GRANTS;
        } else if *candidate == BUILTIN_ROLE_IDS[2] {
            allow |= MODERATOR_GRANTS;
        } else if let Some(role) = policy
            .custom_roles
            .iter()
            .find(|role| role.id == *candidate)
        {
            allow |= role.allow;
            deny |= role.deny;
        }
    }
    if assign && !member.assigned_roles.contains(role_id) {
        if *role_id == BUILTIN_ROLE_IDS[1] {
            allow |= ADMINISTRATOR_GRANTS;
        } else if *role_id == BUILTIN_ROLE_IDS[2] {
            allow |= MODERATOR_GRANTS;
        } else if let Some(role) = policy.custom_roles.iter().find(|role| role.id == *role_id) {
            allow |= role.allow;
            deny |= role.deny;
        }
    }
    allow & !deny & SPACE_PERMISSION_MASK
}

fn channel_effective(policy: &SpacePolicy, channel: &Channel, author: &Fingerprint) -> u64 {
    if *author == policy.root_author {
        return OWNER_GRANTS;
    }
    let Some(member) = policy
        .members
        .iter()
        .find(|member| member.fingerprint == *author && member.status == MemberStatus::Active)
    else {
        return 0;
    };
    let space = effective_space(policy, author);
    let mut allow = channel.default_allow;
    let mut deny = channel.default_deny;
    for override_entry in &channel.role_overrides {
        if member.assigned_roles.contains(&override_entry.role_id) {
            allow |= override_entry.allow;
            deny |= override_entry.deny;
        }
    }
    space & !(deny & !allow)
}

fn member_status(policy: &SpacePolicy, fingerprint: &Fingerprint) -> Option<MemberStatus> {
    policy
        .members
        .iter()
        .find(|member| member.fingerprint == *fingerprint)
        .map(|member| member.status)
}

fn active_member(policy: &SpacePolicy, fingerprint: &Fingerprint) -> bool {
    member_status(policy, fingerprint) == Some(MemberStatus::Active)
}

fn find_channel<'a>(policy: &'a SpacePolicy, id: &EntityId) -> Option<&'a Channel> {
    policy.channels.iter().find(|channel| channel.id == *id)
}

fn validate_channel_roles(policy: &SpacePolicy, channel: &Channel) -> Result<(), RejectReason> {
    for override_entry in &channel.role_overrides {
        if !is_builtin_role(&override_entry.role_id)
            && !policy
                .custom_roles
                .iter()
                .any(|role| role.id == override_entry.role_id)
        {
            return Err(RejectReason::UnknownEntity);
        }
    }
    Ok(())
}

fn parse_operation(payload: &Value) -> Result<Operation, RejectReason> {
    let Value::Map(entries) = payload else {
        return Err(RejectReason::InvalidSchema);
    };
    if entries.len() < 2 || entries[0].0 != 0 || entries[1].0 != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    if unsigned(&entries[0].1)? != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    match unsigned(&entries[1].1)? {
        0 => parse_genesis(payload),
        1 => parse_recovery_genesis(payload),
        2 => parse_invite(payload),
        3 => parse_set_channel(payload),
        4 => parse_custom_role_operation(payload),
        5 => parse_role_assignment(payload),
        6 => parse_member_transition(payload),
        7 => parse_channel_order(payload),
        _ => Err(RejectReason::InvalidSchema),
    }
}

fn parse_genesis(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3])?;
    let creator = fixed_bytes(fields[2])?;
    let channels = parse_channel_array(fields[3], true)?;
    ensure_unique_channels(&channels)?;
    Ok(Operation::Genesis { creator, channels })
}

fn parse_recovery_genesis(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3, 4, 5, 6])?;
    let creator = fixed_bytes(fields[2])?;
    let prior_group = fixed_bytes(fields[3])?;
    let prior_root = fixed_bytes(fields[4])?;
    let recovery_id = fixed_bytes(fields[5])?;
    let channels = parse_channel_array(fields[6], true)?;
    ensure_unique_channels(&channels)?;
    Ok(Operation::RecoveryGenesis {
        creator,
        prior_group,
        prior_root,
        recovery_id,
        channels,
    })
}

fn parse_invite(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3, 4, 5, 6])?;
    let id = fixed_bytes(fields[2])?;
    let target = fixed_bytes(fields[3])?;
    let key_package_hash = fixed_bytes(fields[4])?;
    let expires_at_revision = match fields[5] {
        Value::Null => None,
        value => Some(unsigned(value)?),
    };
    let max_uses = match fields[6] {
        Value::Null => None,
        Value::Unsigned(value) if (1..=u64::from(u16::MAX)).contains(value) => {
            Some(u16::try_from(*value).map_err(|_| RejectReason::InvalidValue)?)
        }
        _ => return Err(RejectReason::InvalidValue),
    };
    Ok(Operation::Invite {
        id,
        target,
        key_package_hash,
        expires_at_revision,
        max_uses,
    })
}

fn parse_set_channel(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2])?;
    Ok(Operation::SetChannel(parse_channel(fields[2])?))
}

fn parse_custom_role_operation(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2])?;
    Ok(Operation::SetCustomRole(parse_custom_role(fields[2])?))
}

fn parse_role_assignment(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3, 4])?;
    let member = fixed_bytes(fields[2])?;
    let role_id = fixed_bytes(fields[3])?;
    let assign = boolean(fields[4])?;
    Ok(Operation::SetRoleAssignment {
        member,
        role_id,
        assign,
    })
}

fn parse_member_transition(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3, 4, 5])?;
    let action = match unsigned(fields[2])? {
        0 => MemberAction::Admit,
        1 => MemberAction::Remove,
        2 => MemberAction::Ban,
        _ => return Err(RejectReason::InvalidValue),
    };
    let target = fixed_bytes(fields[3])?;
    let invite_event_id = match fields[4] {
        Value::Null => None,
        value => Some(fixed_bytes(value)?),
    };
    let control_event_id = fixed_bytes(fields[5])?;
    if (action == MemberAction::Admit) != invite_event_id.is_some() {
        return Err(RejectReason::InvalidValue);
    }
    Ok(Operation::MemberTransition {
        action,
        target,
        invite_event_id,
        control_event_id,
    })
}

fn parse_channel_order(payload: &Value) -> Result<Operation, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2])?;
    let Value::Array(ids) = fields[2] else {
        return Err(RejectReason::InvalidValue);
    };
    if ids.is_empty() || ids.len() > MAX_CHANNELS {
        return Err(RejectReason::InvalidValue);
    }
    let mut order = Vec::with_capacity(ids.len());
    for id in ids {
        order.push(fixed_bytes(id)?);
    }
    if order
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != order.len()
    {
        return Err(RejectReason::DuplicateEntity);
    }
    Ok(Operation::SetChannelOrder(order))
}

fn parse_application_action(
    kind: EventKind,
    plaintext: &[u8],
) -> Result<(ApplicationAction, Option<AttachmentManifest>), RejectReason> {
    let payload = decode_canonical(plaintext).map_err(|_| RejectReason::InvalidCanonicalPayload)?;
    match kind {
        EventKind::Message => parse_message_action(&payload).map(|action| (action, None)),
        EventKind::Edit => parse_edit_action(&payload).map(|action| (action, None)),
        EventKind::Tombstone => parse_tombstone_action(&payload).map(|action| (action, None)),
        EventKind::Reaction => parse_reaction_action(&payload).map(|action| (action, None)),
        EventKind::Pin => parse_pin_action(&payload).map(|action| (action, None)),
        EventKind::FileManifest => parse_file_manifest_action(&payload)
            .map(|manifest| (ApplicationAction::FileManifest, Some(manifest))),
        EventKind::VoiceSignal => Err(RejectReason::UnsupportedAction),
        EventKind::Membership | EventKind::MlsControl => Err(RejectReason::WrongEventKind),
    }
}

fn parse_message_action(payload: &Value) -> Result<ApplicationAction, RejectReason> {
    let version = match payload {
        Value::Map(fields) if fields.first().is_some_and(|(key, _)| *key == 0) => {
            unsigned(&fields[0].1)?
        }
        _ => return Err(RejectReason::InvalidSchema),
    };
    let fields = match version {
        1 => exact_map(payload, &[0, 1, 2, 3, 4])?,
        2 => exact_map(payload, &[0, 1, 2, 3, 4, 5])?,
        _ => return Err(RejectReason::InvalidSchema),
    };
    let Value::Text(content) = fields[1] else {
        return Err(RejectReason::InvalidValue);
    };
    if content.len() > MAX_SPACE_PAYLOAD_BYTES {
        return Err(RejectReason::PayloadTooLarge);
    }
    let thread_root = match fields[2] {
        Value::Null => None,
        value => Some(fixed_bytes(value)?),
    };
    let mention_everyone = boolean(fields[3])?;
    let Value::Array(attachment_values) = fields[4] else {
        return Err(RejectReason::InvalidValue);
    };
    if attachment_values.len() > MAX_PARENTS {
        return Err(RejectReason::LimitExceeded);
    }
    let attachments = attachment_values
        .iter()
        .map(fixed_bytes::<32>)
        .collect::<Result<Vec<EventReference>, _>>()?;
    if attachments.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RejectReason::InvalidValue);
    }
    let mentions = if version == 1 {
        Vec::new()
    } else {
        parse_mentions(fields[5])?
    };
    Ok(ApplicationAction::Message {
        content: Arc::from(content.as_str()),
        thread_root,
        mention_everyone,
        mentions,
        attachments,
    })
}

fn parse_mentions(value: &Value) -> Result<Vec<MentionTarget>, RejectReason> {
    let Value::Array(values) = value else {
        return Err(RejectReason::InvalidValue);
    };
    if values.len() > MAX_MESSAGE_MENTIONS {
        return Err(RejectReason::LimitExceeded);
    }
    let mut mentions = Vec::with_capacity(values.len());
    for value in values {
        let Value::Array(fields) = value else {
            return Err(RejectReason::InvalidValue);
        };
        if fields.len() != 2 {
            return Err(RejectReason::InvalidValue);
        }
        let target = match unsigned(&fields[0])? {
            0 => MentionTarget::Identity(fixed_bytes(&fields[1])?),
            1 => MentionTarget::Role(fixed_bytes(&fields[1])?),
            _ => return Err(RejectReason::InvalidValue),
        };
        mentions.push(target);
    }
    if mentions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RejectReason::InvalidValue);
    }
    Ok(mentions)
}

fn parse_edit_action(payload: &Value) -> Result<ApplicationAction, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2])?;
    if unsigned(fields[0])? != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    let Value::Text(content) = fields[2] else {
        return Err(RejectReason::InvalidValue);
    };
    if content.len() > MAX_SPACE_PAYLOAD_BYTES {
        return Err(RejectReason::PayloadTooLarge);
    }
    Ok(ApplicationAction::Edit {
        target: fixed_bytes(fields[1])?,
        content: Arc::from(content.as_str()),
    })
}

fn parse_tombstone_action(payload: &Value) -> Result<ApplicationAction, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3])?;
    if unsigned(fields[0])? != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    let moderation_reason = match (unsigned(fields[2])?, fields[3]) {
        (0, Value::Null) => None,
        (1, Value::Text(reason)) if !reason.trim().is_empty() && reason.len() <= 512 => {
            Some(reason.clone())
        }
        _ => return Err(RejectReason::InvalidValue),
    };
    Ok(ApplicationAction::Tombstone {
        target: fixed_bytes(fields[1])?,
        moderation_reason,
    })
}

fn parse_reaction_action(payload: &Value) -> Result<ApplicationAction, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3, 4])?;
    if unsigned(fields[0])? != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    let Value::Text(token) = fields[2] else {
        return Err(RejectReason::InvalidValue);
    };
    if token.is_empty() || token.len() > 64 {
        return Err(RejectReason::InvalidValue);
    }
    let add = match unsigned(fields[3])? {
        0 => true,
        1 => false,
        _ => return Err(RejectReason::InvalidValue),
    };
    let tag = match (add, fields[4]) {
        (true, Value::Null) => None,
        (false, value) => Some(fixed_bytes(value)?),
        _ => return Err(RejectReason::InvalidValue),
    };
    Ok(ApplicationAction::Reaction {
        target: fixed_bytes(fields[1])?,
        token: token.clone(),
        add,
        tag,
    })
}

fn parse_pin_action(payload: &Value) -> Result<ApplicationAction, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3])?;
    if unsigned(fields[0])? != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    let add = boolean(fields[2])?;
    let tag = match (add, fields[3]) {
        (true, Value::Null) => None,
        (false, value) => Some(fixed_bytes(value)?),
        _ => return Err(RejectReason::InvalidValue),
    };
    Ok(ApplicationAction::Pin {
        target: fixed_bytes(fields[1])?,
        add,
        tag,
    })
}

fn parse_file_manifest_action(payload: &Value) -> Result<AttachmentManifest, RejectReason> {
    let fields = exact_map(payload, &[0, 1, 2, 3, 4, 5])?;
    if unsigned(fields[0])? != 1 {
        return Err(RejectReason::InvalidSchema);
    }
    let Value::Text(filename) = fields[1] else {
        return Err(RejectReason::InvalidValue);
    };
    if filename.contains('\0') {
        return Err(RejectReason::InvalidValue);
    }
    let mime_type = match fields[2] {
        Value::Null => None,
        Value::Text(mime_type) if !mime_type.contains('\0') => Some(mime_type.clone()),
        _ => return Err(RejectReason::InvalidValue),
    };
    let file_size = unsigned(fields[3])?;
    let file_hash = fixed_bytes(fields[4])?;
    let Value::Array(chunk_values) = fields[5] else {
        return Err(RejectReason::InvalidValue);
    };
    if chunk_values.len() > lattice_files::MAX_CHUNKS {
        return Err(RejectReason::LimitExceeded);
    }
    let chunk_hashes = chunk_values
        .iter()
        .map(fixed_bytes::<32>)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = AttachmentManifest {
        filename: filename.clone(),
        mime_type,
        file_size,
        file_hash,
        chunk_hashes,
    };
    manifest
        .validate()
        .map_err(|_| RejectReason::InvalidValue)?;
    Ok(manifest)
}

fn application_permissions(
    action: &ApplicationAction,
    metadata: &EventMetadata,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
    policy: &SpacePolicy,
) -> Result<u64, RejectReason> {
    let channel_id = graph
        .get(&metadata.event_id)
        .and_then(|node| node.channel_id)
        .ok_or(RejectReason::NonNullChannel)?;
    let mut required = match action {
        ApplicationAction::Message { .. } => MESSAGE_SEND,
        ApplicationAction::FileManifest => MESSAGE_SEND | MESSAGE_ATTACH,
        ApplicationAction::Edit { target, .. } => {
            edit_permissions(*target, metadata, channel_id, graph, ancestors)?
        }
        ApplicationAction::Tombstone {
            target,
            moderation_reason,
        } => tombstone_permissions(
            *target,
            moderation_reason.is_some(),
            metadata,
            channel_id,
            graph,
            ancestors,
        )?,
        ApplicationAction::Reaction { .. } => {
            reaction_permissions(action, metadata, channel_id, graph, ancestors)?
        }
        ApplicationAction::Pin { target, add, tag } => {
            pin_permissions(*target, *add, *tag, metadata, channel_id, graph, ancestors)?
        }
    };
    if let ApplicationAction::Message { mentions, .. } = action {
        if mentions.iter().any(|mention| match mention {
            MentionTarget::Identity(_) => false,
            MentionTarget::Role(role_id) => {
                !is_builtin_role(role_id)
                    && !policy.custom_roles.iter().any(|role| &role.id == role_id)
            }
        }) {
            return Err(RejectReason::UnknownEntity);
        }
        required |= message_extra_permissions(action, metadata, channel_id, graph, ancestors)?;
    }
    Ok(required)
}

fn edit_permissions(
    target: EventReference,
    metadata: &EventMetadata,
    channel_id: EntityId,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
) -> Result<u64, RejectReason> {
    let target_node = application_target(
        target,
        EventKind::Message,
        metadata,
        channel_id,
        graph,
        ancestors,
    )?;
    Ok(if target_node.author == metadata.author {
        MESSAGE_SEND
    } else {
        MESSAGE_MODERATE
    })
}

fn tombstone_permissions(
    target: EventReference,
    has_moderation_reason: bool,
    metadata: &EventMetadata,
    channel_id: EntityId,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
) -> Result<u64, RejectReason> {
    let target_node = application_target(
        target,
        EventKind::Message,
        metadata,
        channel_id,
        graph,
        ancestors,
    )?;
    if has_moderation_reason {
        Ok(MESSAGE_MODERATE)
    } else if target_node.author == metadata.author {
        Ok(MESSAGE_SEND)
    } else {
        Err(RejectReason::Unauthorized)
    }
}

fn reaction_permissions(
    action: &ApplicationAction,
    metadata: &EventMetadata,
    channel_id: EntityId,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
) -> Result<u64, RejectReason> {
    let ApplicationAction::Reaction {
        target,
        token,
        add,
        tag,
    } = action
    else {
        return Err(RejectReason::WrongEventKind);
    };
    let _ = application_target(
        *target,
        EventKind::Message,
        metadata,
        channel_id,
        graph,
        ancestors,
    )?;
    if *add {
        if tag.is_some() {
            return Err(RejectReason::InvalidValue);
        }
    } else {
        let tag_node = application_target(
            tag.ok_or(RejectReason::InvalidTarget)?,
            EventKind::Reaction,
            metadata,
            channel_id,
            graph,
            ancestors,
        )?;
        if tag_node.author != metadata.author
            || tag_node
                .reaction_tag
                .as_ref()
                .is_none_or(|reaction| reaction.target != *target || reaction.token != *token)
        {
            return Err(RejectReason::InvalidTarget);
        }
    }
    Ok(MESSAGE_SEND)
}

fn pin_permissions(
    target: EventReference,
    add: bool,
    tag: Option<EventReference>,
    metadata: &EventMetadata,
    channel_id: EntityId,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
) -> Result<u64, RejectReason> {
    let _ = application_target(
        target,
        EventKind::Message,
        metadata,
        channel_id,
        graph,
        ancestors,
    )?;
    if add {
        if tag.is_some() {
            return Err(RejectReason::InvalidValue);
        }
    } else {
        let tag_node = application_target(
            tag.ok_or(RejectReason::InvalidTarget)?,
            EventKind::Pin,
            metadata,
            channel_id,
            graph,
            ancestors,
        )?;
        if !matches!(
            tag_node.application_action.as_ref(),
            Some(ApplicationAction::Pin {
                target: tag_target,
                add: true,
                ..
            }) if tag_target == &target
        ) {
            return Err(RejectReason::InvalidTarget);
        }
    }
    Ok(MESSAGE_PIN)
}

fn message_extra_permissions(
    action: &ApplicationAction,
    metadata: &EventMetadata,
    channel_id: EntityId,
    graph: &BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
) -> Result<u64, RejectReason> {
    let ApplicationAction::Message {
        thread_root,
        mention_everyone,
        mentions,
        attachments,
        ..
    } = action
    else {
        return Err(RejectReason::WrongEventKind);
    };
    let mut required = 0;
    if let Some(thread_root) = thread_root {
        let _ = application_target(
            *thread_root,
            EventKind::Message,
            metadata,
            channel_id,
            graph,
            ancestors,
        )?;
        required |= THREAD_CREATE;
    }
    if *mention_everyone
        || mentions
            .iter()
            .any(|mention| matches!(mention, MentionTarget::Role(_)))
    {
        required |= MENTION_EVERYONE;
    }
    for attachment in attachments {
        let _ = application_target(
            *attachment,
            EventKind::FileManifest,
            metadata,
            channel_id,
            graph,
            ancestors,
        )?;
        required |= MESSAGE_ATTACH;
    }
    Ok(required)
}

fn application_target<'a>(
    target: EventReference,
    expected_kind: EventKind,
    metadata: &EventMetadata,
    channel_id: EntityId,
    graph: &'a BTreeMap<EventReference, GraphNode>,
    ancestors: &std::collections::BTreeSet<EventReference>,
) -> Result<&'a GraphNode, RejectReason> {
    if !ancestors.contains(&target) {
        return Err(RejectReason::InvalidTarget);
    }
    let node = graph.get(&target).ok_or(RejectReason::InvalidTarget)?;
    if node.kind != expected_kind
        || !node.mls_bound
        || !node.application_authorized
        || node.space_id != metadata.space_id
        || node.group_reference != metadata.group_reference
        || node.channel_id != Some(channel_id)
    {
        return Err(RejectReason::InvalidTarget);
    }
    Ok(node)
}

fn exact_map<'a>(value: &'a Value, keys: &[u64]) -> Result<Vec<&'a Value>, RejectReason> {
    let Value::Map(entries) = value else {
        return Err(RejectReason::InvalidSchema);
    };
    if entries.len() != keys.len()
        || entries
            .iter()
            .zip(keys)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(RejectReason::InvalidSchema);
    }
    Ok(entries.iter().map(|(_, value)| value).collect())
}

fn parse_channel_array(value: &Value, genesis: bool) -> Result<Vec<Channel>, RejectReason> {
    let Value::Array(values) = value else {
        return Err(RejectReason::InvalidValue);
    };
    if values.is_empty() || values.len() > MAX_INITIAL_CHANNELS {
        return Err(RejectReason::InvalidValue);
    }
    let mut channels = Vec::with_capacity(values.len());
    for value in values {
        let channel = parse_channel(value)?;
        if genesis
            && channel
                .role_overrides
                .iter()
                .any(|item| !is_builtin_role(&item.role_id))
        {
            return Err(RejectReason::UnknownEntity);
        }
        channels.push(channel);
    }
    Ok(channels)
}

fn ensure_unique_channels(channels: &[Channel]) -> Result<(), RejectReason> {
    let mut ids = std::collections::BTreeSet::new();
    if channels.iter().any(|channel| !ids.insert(channel.id)) {
        Err(RejectReason::DuplicateEntity)
    } else {
        Ok(())
    }
}

fn parse_channel(value: &Value) -> Result<Channel, RejectReason> {
    let fields = exact_map(value, &[0, 1, 2, 3, 4, 5, 6])?;
    let id = fixed_bytes(fields[0])?;
    let channel_type = match unsigned(fields[1])? {
        0 => ChannelType::Text,
        1 => ChannelType::Announcement,
        2 => ChannelType::Voice,
        _ => return Err(RejectReason::InvalidValue),
    };
    let name = text_name(fields[2])?;
    let archived = boolean(fields[3])?;
    let allow = unsigned(fields[4])?;
    let deny = unsigned(fields[5])?;
    let mask = match channel_type {
        ChannelType::Text | ChannelType::Announcement => CONTENT_CHANNEL_MASK,
        ChannelType::Voice => VOICE_PERMISSION_MASK,
    };
    validate_masks(allow, deny, mask)?;
    let Value::Array(overrides) = fields[6] else {
        return Err(RejectReason::InvalidValue);
    };
    if overrides.len() > MAX_CHANNEL_OVERRIDES {
        return Err(RejectReason::LimitExceeded);
    }
    let mut role_overrides = Vec::with_capacity(overrides.len());
    let mut prior_id: Option<EntityId> = None;
    for value in overrides {
        let fields = exact_map(value, &[0, 1, 2])?;
        let role_id = fixed_bytes(fields[0])?;
        if prior_id.is_some_and(|prior| prior >= role_id) {
            return Err(RejectReason::InvalidValue);
        }
        prior_id = Some(role_id);
        let allow = unsigned(fields[1])?;
        let deny = unsigned(fields[2])?;
        validate_masks(allow, deny, mask)?;
        role_overrides.push(RoleOverride {
            role_id,
            allow,
            deny,
        });
    }
    Ok(Channel {
        id,
        channel_type,
        name,
        archived,
        default_allow: allow,
        default_deny: deny,
        role_overrides,
    })
}

fn parse_custom_role(value: &Value) -> Result<CustomRole, RejectReason> {
    let fields = exact_map(value, &[0, 1, 2, 3])?;
    let id = fixed_bytes(fields[0])?;
    if is_builtin_role(&id) {
        return Err(RejectReason::InvalidValue);
    }
    let name = text_name(fields[1])?;
    let allow = unsigned(fields[2])?;
    let deny = unsigned(fields[3])?;
    validate_masks(allow, deny, SPACE_PERMISSION_MASK)?;
    Ok(CustomRole {
        id,
        name,
        allow,
        deny,
    })
}

fn validate_masks(allow: u64, deny: u64, allowed: u64) -> Result<(), RejectReason> {
    if (allow | deny) & !allowed != 0 || allow & deny != 0 {
        Err(RejectReason::InvalidValue)
    } else {
        Ok(())
    }
}

fn text_name(value: &Value) -> Result<String, RejectReason> {
    let Value::Text(name) = value else {
        return Err(RejectReason::InvalidValue);
    };
    if name.is_empty() || name.len() > 128 || name.contains('\0') {
        return Err(RejectReason::InvalidValue);
    }
    Ok(name.clone())
}

fn unsigned(value: &Value) -> Result<u64, RejectReason> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(RejectReason::InvalidValue),
    }
}

fn boolean(value: &Value) -> Result<bool, RejectReason> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(RejectReason::InvalidValue),
    }
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], RejectReason> {
    let Value::Bytes(bytes) = value else {
        return Err(RejectReason::InvalidValue);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| RejectReason::InvalidValue)
}

fn is_builtin_role(role_id: &EntityId) -> bool {
    BUILTIN_ROLE_IDS.contains(role_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlsBoundEvent;
    use lattice_events::{EventDraft, VerifiedSignatureOnlyEvent};
    use lattice_identity::DeviceIdentity;
    use lattice_protocol::{EventId, encode_canonical};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_APPLICATION_SEQUENCE: AtomicU64 = AtomicU64::new(2);

    // Owning fixture payloads keeps each test's encoded event construction self-contained.
    #[allow(clippy::needless_pass_by_value)]
    fn make_bound_event(
        identity: &DeviceIdentity,
        space: SpaceId,
        group: GroupReference,
        epoch: u64,
        parents: Vec<EventReference>,
        payload: Value,
    ) -> MlsBoundEvent {
        let plaintext = encode_canonical(&payload).unwrap();
        let protected_body = plaintext.clone();
        let draft = EventDraft {
            space_id: space,
            channel_id: None,
            author_sequence: 1,
            lamport: 999,
            wall_time_hint: 123,
            parents: parents.into_iter().map(EventId::from_bytes).collect(),
            kind: EventKind::Membership,
            protected_body,
            mls_group_reference: group,
            mls_epoch: epoch,
        };
        let event = VerifiedSignatureOnlyEvent::create(identity, draft).unwrap();
        // Tests exercise the reducer boundary directly; the production
        // constructor is `bind_mls_application` after real MLS processing.
        MlsBoundEvent { event, plaintext }
    }

    fn make_application_event(
        identity: &DeviceIdentity,
        space: SpaceId,
        channel: EntityId,
        group: GroupReference,
        parents: Vec<EventReference>,
        kind: EventKind,
        payload: &Value,
    ) -> MlsBoundEvent {
        let plaintext = encode_canonical(payload).unwrap();
        let author_sequence = NEXT_APPLICATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let draft = EventDraft {
            space_id: space,
            channel_id: Some(channel),
            author_sequence,
            lamport: author_sequence.saturating_add(999),
            wall_time_hint: 0,
            parents: parents.into_iter().map(EventId::from_bytes).collect(),
            kind,
            protected_body: plaintext.clone(),
            mls_group_reference: group,
            mls_epoch: 0,
        };
        let event = VerifiedSignatureOnlyEvent::create(identity, draft).unwrap();
        MlsBoundEvent { event, plaintext }
    }

    fn channel_descriptor(id: EntityId) -> Value {
        Value::Map(vec![
            (0, Value::Bytes(id.to_vec())),
            (1, Value::Unsigned(0)),
            (2, Value::Text("general".into())),
            (3, Value::Bool(false)),
            (4, Value::Unsigned(0)),
            (5, Value::Unsigned(0)),
            (6, Value::Array(Vec::new())),
        ])
    }

    fn genesis_payload(creator: Fingerprint, channel: EntityId) -> Value {
        Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(0)),
            (2, Value::Bytes(creator.to_vec())),
            (3, Value::Array(vec![channel_descriptor(channel)])),
        ])
    }

    fn policy(ids: impl IntoIterator<Item = (u64, Value)>) -> Value {
        Value::Map(ids.into_iter().collect())
    }

    #[test]
    fn genesis_binds_creator_to_authenticated_outer_author() {
        let identity = DeviceIdentity::generate().unwrap();
        let creator = identity.public_bundle().fingerprint();
        let mut wrong = creator;
        wrong[0] ^= 1;
        let group = [7; 32];
        let space = [8; 16];
        let event = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(wrong, [9; 16]),
        );
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&event, None),
            ApplyResult::Rejected(RejectReason::CreatorMismatch)
        );
        assert_eq!(reducer.status(), ReducerStatus::AwaitingGenesis);
        let valid = make_bound_event(
            &identity,
            [16; 16],
            group,
            0,
            Vec::new(),
            genesis_payload(creator, [17; 16]),
        );
        assert_eq!(
            reducer.apply(&valid, None),
            ApplyResult::Applied { revision: 0 }
        );
        assert_eq!(reducer.policy().unwrap().root_author, creator);
    }

    fn recovery_genesis_payload(
        creator: Fingerprint,
        prior_group: GroupReference,
        prior_root: EventReference,
        recovery_id: EntityId,
        channel: EntityId,
    ) -> Value {
        policy([
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(1)),
            (2, Value::Bytes(creator.to_vec())),
            (3, Value::Bytes(prior_group.to_vec())),
            (4, Value::Bytes(prior_root.to_vec())),
            (5, Value::Bytes(recovery_id.to_vec())),
            (6, Value::Array(vec![channel_descriptor(channel)])),
        ])
    }

    #[test]
    fn recovery_requires_current_admin_and_binds_one_new_group_root() {
        let identity = DeviceIdentity::generate().unwrap();
        let creator = identity.public_bundle().fingerprint();
        let space = [18; 16];
        let prior_group = [19; 32];
        let new_group = [20; 32];
        let genesis = make_bound_event(
            &identity,
            space,
            prior_group,
            0,
            Vec::new(),
            genesis_payload(creator, [21; 16]),
        );
        let prior_root = *genesis.event().event_id().as_bytes();
        let mut prior = SpaceReducer::new();
        assert_eq!(
            prior.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );

        let recovery_id = [22; 16];
        let recovery = make_bound_event(
            &identity,
            space,
            new_group,
            0,
            Vec::new(),
            recovery_genesis_payload(creator, prior_group, prior_root, recovery_id, [23; 16]),
        );
        let authorization = prior
            .authorize_recovery_genesis(&recovery)
            .expect("the active owner may recover into a new group");
        let mut recovered = SpaceReducer::new();
        assert_eq!(
            recovered.apply(&recovery, Some(&authorization)),
            ApplyResult::Applied { revision: 0 }
        );
        let policy = recovered.policy().expect("recovery root is active");
        assert_eq!(policy.space_id, space);
        assert_eq!(policy.group_reference, new_group);
        assert_eq!(policy.root_author, creator);

        let other_group = make_bound_event(
            &identity,
            space,
            [24; 32],
            0,
            Vec::new(),
            recovery_genesis_payload(creator, prior_group, prior_root, recovery_id, [25; 16]),
        );
        assert_eq!(
            recovered.apply(&other_group, Some(&authorization)),
            ApplyResult::Rejected(RejectReason::InvalidRecoveryAuthorization)
        );

        let outsider = DeviceIdentity::generate().unwrap();
        let outsider_fingerprint = outsider.public_bundle().fingerprint();
        let unauthorized = make_bound_event(
            &outsider,
            space,
            [26; 32],
            0,
            Vec::new(),
            recovery_genesis_payload(
                outsider_fingerprint,
                prior_group,
                prior_root,
                [27; 16],
                [28; 16],
            ),
        );
        assert_eq!(
            prior.authorize_recovery_genesis(&unauthorized),
            Err(RejectReason::InvalidRecoveryAuthorization)
        );
    }

    #[test]
    fn rejects_malformed_exact_keys_in_nested_descriptors() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.public_bundle().fingerprint();
        let Value::Map(mut malformed_channel) = channel_descriptor([1; 16]) else {
            unreachable!()
        };
        malformed_channel.push((7, Value::Null));
        let payload = policy([
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(0)),
            (2, Value::Bytes(author.to_vec())),
            (3, Value::Array(vec![Value::Map(malformed_channel)])),
        ]);
        let event = make_bound_event(&identity, [2; 16], [3; 32], 0, Vec::new(), payload);
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&event, None),
            ApplyResult::Rejected(RejectReason::InvalidSchema)
        );
    }

    #[test]
    fn heads_and_revision_advance_only_for_authorized_state_changes() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.public_bundle().fingerprint();
        let group = [4; 32];
        let space = [5; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, [6; 16]),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );
        let channel = Value::Map(vec![
            (0, Value::Bytes([6; 16].to_vec())),
            (1, Value::Unsigned(0)),
            (2, Value::Text("renamed".into())),
            (3, Value::Bool(false)),
            (4, Value::Unsigned(0)),
            (5, Value::Unsigned(0)),
            (6, Value::Array(Vec::new())),
        ]);
        let update = make_bound_event(
            &identity,
            space,
            group,
            0,
            vec![root_id],
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(3)),
                (2, channel),
            ]),
        );
        assert_eq!(
            reducer.apply(&update, None),
            ApplyResult::Applied { revision: 1 }
        );
        assert_eq!(
            reducer.policy().unwrap().heads,
            vec![*update.event().event_id().as_bytes()]
        );
        assert_eq!(reducer.policy().unwrap().revision, 1);
        let stale = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(3)),
                (
                    2,
                    Value::Map(vec![
                        (0, Value::Bytes([6; 16].to_vec())),
                        (1, Value::Unsigned(0)),
                        (2, Value::Text("stale".into())),
                        (3, Value::Bool(false)),
                        (4, Value::Unsigned(0)),
                        (5, Value::Unsigned(0)),
                        (6, Value::Array(Vec::new())),
                    ]),
                ),
            ]),
        );
        assert_eq!(
            reducer.apply(&stale, None),
            ApplyResult::Rejected(RejectReason::IncompletePolicyHeads)
        );
        assert_eq!(reducer.policy().unwrap().revision, 1);
    }

    #[test]
    fn missing_transitive_graph_dependency_stays_pending() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.fingerprint();
        let group = [31; 32];
        let space = [32; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, [33; 16]),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );

        let parent = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id: space,
                channel_id: Some([33; 16]),
                author_sequence: 2,
                lamport: 0,
                wall_time_hint: 0,
                parents: vec![EventId::from_bytes(root_id)],
                kind: EventKind::Message,
                protected_body: b"graph-parent".to_vec(),
                mls_group_reference: group,
                mls_epoch: 0,
            },
        )
        .unwrap();
        let parent_id = *parent.event_id().as_bytes();
        let update = make_bound_event(
            &identity,
            space,
            group,
            0,
            vec![parent_id],
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(3)),
                (
                    2,
                    Value::Map(vec![
                        (0, Value::Bytes([33; 16].to_vec())),
                        (1, Value::Unsigned(0)),
                        (2, Value::Text("pending".into())),
                        (3, Value::Bool(false)),
                        (4, Value::Unsigned(0)),
                        (5, Value::Unsigned(0)),
                        (6, Value::Array(Vec::new())),
                    ]),
                ),
            ]),
        );
        let update_id = *update.event().event_id().as_bytes();
        assert_eq!(reducer.apply(&update, None), ApplyResult::Pending);
        reducer.observe_graph_event(&parent).unwrap();
        let outcomes = reducer.retry_pending();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].event_id, update_id);
        assert_eq!(outcomes[0].result, ApplyResult::Applied { revision: 1 });
    }

    #[test]
    fn denied_operation_does_not_advance_policy() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let outsider = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.fingerprint();
        let target = [10; 32];
        let group = [11; 32];
        let space = [12; 16];
        let genesis = make_bound_event(
            &owner_identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(owner, [13; 16]),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);
        let invite = policy([
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(2)),
            (2, Value::Bytes([14; 16].to_vec())),
            (3, Value::Bytes(target.to_vec())),
            (4, Value::Bytes([15; 32].to_vec())),
            (5, Value::Null),
            (6, Value::Null),
        ]);
        let event = make_bound_event(&outsider, space, group, 0, vec![root_id], invite);
        assert_eq!(
            reducer.apply(&event, None),
            ApplyResult::Rejected(RejectReason::Unauthorized)
        );
        assert_eq!(reducer.policy().unwrap().revision, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Keep exact proof, ban, and re-invite checks together.
    fn remove_and_ban_require_remove_proof_and_bans_block_reinvite() {
        let owner_identity = DeviceIdentity::generate().expect("owner identity");
        let owner = owner_identity.fingerprint();
        let target = [0x37; 32];
        let space_id = [0x38; 16];
        let group_reference = [0x39; 32];
        let genesis = make_bound_event(
            &owner_identity,
            space_id,
            group_reference,
            0,
            Vec::new(),
            genesis_payload(owner, [0x3A; 16]),
        );
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );
        let mut base_policy = reducer.policy().expect("Genesis policy").clone();
        base_policy.members.push(Member {
            fingerprint: target,
            status: MemberStatus::Active,
            assigned_roles: Vec::new(),
        });

        let control_event_id = [0x3B; 32];
        let make_control = |mls_action, key_package_hash| GraphNode {
            space_id,
            group_reference,
            author: owner,
            kind: EventKind::MlsControl,
            epoch: 0,
            lamport: 1,
            author_sequence: 2,
            parents: vec![*genesis.event().event_id().as_bytes()],
            channel_id: None,
            control_relation: Some(ValidatedMlsControlRelation {
                space_id,
                group_reference,
                control_event_id,
                author: owner,
                parent_epoch: 0,
                mls_action,
                target,
                key_package_hash,
            }),
            mls_bound: true,
            application_authorized: false,
            application_action: None,
            attachment_manifest: None,
            reaction_tag: None,
        };
        let mut graph = BTreeMap::new();
        graph.insert(
            control_event_id,
            make_control(lattice_mls::api::MlsMembershipAction::Remove, None),
        );
        let ancestors = BTreeSet::from([control_event_id]);
        let transition = |action| Operation::MemberTransition {
            action,
            target,
            invite_event_id: None,
            control_event_id,
        };
        let mut removed = base_policy.clone();
        assert_eq!(
            apply_operation(
                &mut removed,
                owner,
                [0x3C; 32],
                &transition(MemberAction::Remove),
                &graph,
                &ancestors,
                0,
            ),
            Ok(())
        );
        assert_eq!(
            member_status(&removed, &target),
            Some(MemberStatus::Removed)
        );

        let mut banned = base_policy.clone();
        assert_eq!(
            apply_operation(
                &mut banned,
                owner,
                [0x3D; 32],
                &transition(MemberAction::Ban),
                &graph,
                &ancestors,
                0,
            ),
            Ok(())
        );
        assert_eq!(member_status(&banned, &target), Some(MemberStatus::Banned));
        let invite = Operation::Invite {
            id: [0x3E; 16],
            target,
            key_package_hash: [0x3F; 32],
            expires_at_revision: None,
            max_uses: None,
        };
        assert_eq!(
            apply_operation(
                &mut banned,
                owner,
                [0x40; 32],
                &invite,
                &graph,
                &ancestors,
                0,
            ),
            Err(RejectReason::InvalidTransition)
        );

        graph.insert(
            control_event_id,
            make_control(lattice_mls::api::MlsMembershipAction::Add, Some([0x3F; 32])),
        );
        assert_eq!(
            apply_operation(
                &mut base_policy,
                owner,
                [0x41; 32],
                &transition(MemberAction::Ban),
                &graph,
                &ancestors,
                0,
            ),
            Err(RejectReason::InvalidControlRelation)
        );
    }

    #[test]
    fn conflicting_siblings_restore_common_state_and_pause_policy() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.public_bundle().fingerprint();
        let group = [20; 32];
        let space = [21; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, [22; 16]),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);
        let first = make_bound_event(
            &identity,
            space,
            group,
            0,
            vec![root_id],
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(3)),
                (
                    2,
                    Value::Map(vec![
                        (0, Value::Bytes([22; 16].to_vec())),
                        (1, Value::Unsigned(0)),
                        (2, Value::Text("first".into())),
                        (3, Value::Bool(false)),
                        (4, Value::Unsigned(0)),
                        (5, Value::Unsigned(0)),
                        (6, Value::Array(Vec::new())),
                    ]),
                ),
            ]),
        );
        assert_eq!(
            reducer.apply(&first, None),
            ApplyResult::Applied { revision: 1 }
        );
        let second = make_bound_event(
            &identity,
            space,
            group,
            0,
            vec![root_id],
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(3)),
                (
                    2,
                    Value::Map(vec![
                        (0, Value::Bytes([22; 16].to_vec())),
                        (1, Value::Unsigned(0)),
                        (2, Value::Text("second".into())),
                        (3, Value::Bool(false)),
                        (4, Value::Unsigned(0)),
                        (5, Value::Unsigned(0)),
                        (6, Value::Array(Vec::new())),
                    ]),
                ),
            ]),
        );
        assert_eq!(reducer.apply(&second, None), ApplyResult::PolicyConflicted);
        assert_eq!(reducer.status(), ReducerStatus::PolicyConflicted);
        assert_eq!(reducer.effective_space_permissions(&author), None);
        assert_eq!(reducer.policy().unwrap().revision, 0);
        assert_eq!(reducer.policy().unwrap().channels[0].name, "general");
        assert_eq!(reducer.conflict_evidence().len(), 2);
        let recovery_event = make_bound_event(
            &identity,
            space,
            [23; 32],
            0,
            Vec::new(),
            recovery_genesis_payload(author, group, root_id, [24; 16], [25; 16]),
        );
        let recovery = reducer
            .authorize_recovery_genesis(&recovery_event)
            .expect("the owner retains invite authority in the common policy");
        let mut recovered = SpaceReducer::new();
        assert_eq!(
            recovered.apply(&recovery_event, Some(&recovery)),
            ApplyResult::Applied { revision: 0 }
        );
        assert_eq!(recovered.policy().unwrap().group_reference, [23; 32]);
    }
    // Keeps the cross-action causality and delivery-order convergence fixture
    // together; splitting it would obscure the shared event graph.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn application_authorization_uses_policy_heads_action_bits_and_target_causality() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.fingerprint();
        let space = [40; 16];
        let group = [41; 32];
        let channel = [42; 16];
        let genesis = make_bound_event(
            &owner_identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(owner, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );

        let message_payload = policy([
            (0, Value::Unsigned(1)),
            (1, Value::Text("hello".into())),
            (2, Value::Null),
            (3, Value::Bool(false)),
            (4, Value::Array(Vec::new())),
        ]);
        let message = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::Message,
            &message_payload,
        );
        assert_eq!(
            reducer.authorize_application_event(&message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );

        let message_id = *message.event().event_id().as_bytes();

        let threaded_message = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("thread reply".into())),
                (2, Value::Bytes(message_id.to_vec())),
                (3, Value::Bool(true)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&threaded_message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND | THREAD_CREATE | MENTION_EVERYONE
            }
        );
        let edit = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Edit,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Text("edited".into())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&edit),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        let later_edit = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Edit,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Text("latest".into())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&later_edit),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        let delete_own_message = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Tombstone,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Unsigned(0)),
                (3, Value::Null),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&delete_own_message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        let reason_bearing_moderation = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Tombstone,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Unsigned(1)),
                (3, Value::Text("spam".into())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&reason_bearing_moderation),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_MODERATE
            }
        );
        let reaction = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Reaction,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Text("wave".into())),
                (3, Value::Unsigned(0)),
                (4, Value::Null),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&reaction),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        let reaction_id = *reaction.event().event_id().as_bytes();
        let remove_reaction = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![reaction_id],
            EventKind::Reaction,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Text("wave".into())),
                (3, Value::Unsigned(1)),
                (4, Value::Bytes(reaction_id.to_vec())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&remove_reaction),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );

        let pin = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Pin,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Bool(true)),
                (3, Value::Null),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&pin),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_PIN
            }
        );
        let pin_id = *pin.event().event_id().as_bytes();
        let second_pin = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Pin,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Bool(true)),
                (3, Value::Null),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&second_pin),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_PIN
            }
        );
        let second_pin_id = *second_pin.event().event_id().as_bytes();
        let remove_pin = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![pin_id],
            EventKind::Pin,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Bool(false)),
                (3, Value::Bytes(pin_id.to_vec())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&remove_pin),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_PIN
            }
        );
        let remove_wrong_tag = make_application_event(
            &owner_identity,
            space,
            channel,
            group,
            vec![message_id],
            EventKind::Reaction,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(message_id.to_vec())),
                (2, Value::Text("wave".into())),
                (3, Value::Unsigned(1)),
                (4, Value::Bytes(message_id.to_vec())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&remove_wrong_tag),
            EventAuthorization::Rejected(RejectReason::InvalidTarget)
        );
        let history = reducer.message_history(&channel);
        assert_eq!(history.messages().len(), 2);
        let projected_message = history
            .messages()
            .iter()
            .find(|projected| projected.event_id == message_id)
            .expect("authorized message is projected");
        assert_eq!(projected_message.versions().len(), 3);
        assert_eq!(
            projected_message.current_version().content.as_ref(),
            "latest"
        );
        assert!(projected_message.is_deleted());
        assert_eq!(projected_message.tombstones.len(), 2);
        assert!(projected_message.reactions.is_empty());
        assert!(projected_message.is_pinned());
        assert_eq!(projected_message.pin_tags, vec![second_pin_id]);
        assert_eq!(
            reducer.authorize_application_event(&reaction),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(reducer.message_history(&channel), history);

        let mut reordered = SpaceReducer::new();
        assert_eq!(
            reordered.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );
        assert_eq!(
            reordered.authorize_application_event(&message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&remove_reaction),
            EventAuthorization::Pending
        );
        assert_eq!(
            reordered.authorize_application_event(&remove_pin),
            EventAuthorization::Pending
        );
        assert_eq!(
            reordered.authorize_application_event(&threaded_message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND | THREAD_CREATE | MENTION_EVERYONE
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&edit),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&later_edit),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&delete_own_message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&reason_bearing_moderation),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_MODERATE
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&reaction),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&remove_reaction),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&pin),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_PIN
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&second_pin),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_PIN
            }
        );
        assert_eq!(
            reordered.authorize_application_event(&remove_pin),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_PIN
            }
        );
        assert_eq!(reordered.message_history(&channel), history);
    }
    #[test]
    fn message_projection_budget_rejects_without_latching_action() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.fingerprint();
        let space = [40; 16];
        let group = [41; 32];
        let channel = [42; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );
        reducer.message_history_bytes = MAX_MESSAGE_HISTORY_BYTES - 1;

        let oversized_history = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("oversize".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&oversized_history),
            EventAuthorization::Rejected(RejectReason::LimitExceeded)
        );
        assert!(reducer.message_history(&channel).messages().is_empty());
    }
    #[test]
    fn application_authorization_binds_file_references_to_valid_manifests() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.fingerprint();
        let space = [40; 16];
        let group = [41; 32];
        let channel = [42; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);
        let invalid_manifest = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::FileManifest,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("bad.bin".into())),
                (2, Value::Null),
                (3, Value::Unsigned(65_537)),
                (4, Value::Bytes(vec![0; 32])),
                (5, Value::Array(vec![Value::Bytes(vec![0; 32])])),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&invalid_manifest),
            EventAuthorization::Rejected(RejectReason::InvalidValue)
        );
        let file_manifest = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::FileManifest,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("one.bin".into())),
                (2, Value::Null),
                (3, Value::Unsigned(1)),
                (4, Value::Bytes(vec![0; 32])),
                (5, Value::Array(vec![Value::Bytes(vec![0; 32])])),
            ]),
        );
        let manifest_id = *file_manifest.event().event_id().as_bytes();
        assert!(
            reducer
                .authorized_attachment_manifest(&manifest_id)
                .is_none()
        );
        assert_eq!(
            reducer.authorize_application_event(&file_manifest),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND | MESSAGE_ATTACH
            }
        );
        let authorized_manifest = reducer
            .authorized_attachment_manifest(&manifest_id)
            .expect("only the authorized event yields a receiver capability");
        assert_eq!(authorized_manifest.event_id(), &manifest_id);
        let _transfer_id = authorized_manifest.transfer_id().unwrap();
        let mut receiver = authorized_manifest.new_receiver(1).unwrap();
        assert!(matches!(
            receiver.verified_bytes(),
            Err(lattice_files::AttachmentError::TransferNotAccepted)
        ));
        receiver.accept().unwrap();
        assert!(matches!(
            receiver.verified_bytes(),
            Err(lattice_files::AttachmentError::TransferIncomplete)
        ));
        let message = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![manifest_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("file".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(vec![Value::Bytes(manifest_id.to_vec())])),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND | MESSAGE_ATTACH
            }
        );
    }

    #[test]
    fn authorized_application_bytes_commit_with_the_staged_policy_graph() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.fingerprint();
        let space = [70; 16];
        let group = [71; 32];
        let channel = [72; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );
        let message = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("durably authorized".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        let event_id = *message.event().event_id().as_bytes();
        let mut store = lattice_storage::Store::open(":memory:").unwrap();
        let (staged, result) = store
            .with_transaction(|transaction| {
                crate::authorize_and_store_application_event(transaction, &reducer, &message)
            })
            .unwrap();
        assert_eq!(
            result,
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );
        reducer = staged;
        assert!(reducer.graph[&event_id].application_authorized);
        assert_eq!(
            store
                .load_event(&event_id)
                .unwrap()
                .unwrap()
                .canonical_bytes,
            message.event().encoded_bytes()
        );
        let outsider = DeviceIdentity::generate().unwrap();
        let denied = make_application_event(
            &outsider,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("must not persist".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        let denied_id = *denied.event().event_id().as_bytes();
        let (_, result) = store
            .with_transaction(|transaction| {
                crate::authorize_and_store_application_event(transaction, &reducer, &denied)
            })
            .unwrap();
        assert_eq!(
            result,
            EventAuthorization::Rejected(RejectReason::Unauthorized)
        );
        assert!(store.load_event(&denied_id).unwrap().is_none());
    }

    #[test]
    fn application_authorization_enforces_channel_permission_masks() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let member_identity = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.fingerprint();
        let member = member_identity.fingerprint();
        let space = [80; 16];
        let group = [81; 32];
        let channel = [82; 16];
        let genesis = make_bound_event(
            &owner_identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(owner, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);
        let space_policy = reducer.policy.as_mut().unwrap();
        space_policy.members.push(Member {
            fingerprint: member,
            status: MemberStatus::Active,
            assigned_roles: Vec::new(),
        });
        space_policy.channels[0].default_deny |= MESSAGE_ATTACH;

        let message = make_application_event(
            &member_identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("send remains allowed".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&message),
            EventAuthorization::Authorized {
                required_permissions: MESSAGE_SEND
            }
        );

        let manifest = make_application_event(
            &member_identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::FileManifest,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("file.bin".into())),
                (2, Value::Null),
                (3, Value::Unsigned(0)),
                (4, Value::Bytes(vec![0; 32])),
                (5, Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&manifest),
            EventAuthorization::Rejected(RejectReason::Unauthorized)
        );
    }

    #[test]
    fn application_authorization_rejects_nonmember_senders() {
        let owner_identity = DeviceIdentity::generate().unwrap();
        let outsider = DeviceIdentity::generate().unwrap();
        let owner = owner_identity.fingerprint();
        let space = [40; 16];
        let group = [41; 32];
        let channel = [42; 16];
        let genesis = make_bound_event(
            &owner_identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(owner, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);
        let denied = make_application_event(
            &outsider,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("not a member".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&denied),
            EventAuthorization::Rejected(RejectReason::Unauthorized)
        );
    }

    #[test]
    fn application_authorization_rejects_unknown_actions_and_incomplete_heads() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.fingerprint();
        let space = [50; 16];
        let group = [51; 32];
        let channel = [52; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);

        let unsupported = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![root_id],
            EventKind::VoiceSignal,
            &policy([(0, Value::Unsigned(1))]),
        );
        assert_eq!(
            reducer.authorize_application_event(&unsupported),
            EventAuthorization::Rejected(RejectReason::UnsupportedAction)
        );

        let no_policy_head = make_application_event(
            &identity,
            space,
            channel,
            group,
            Vec::new(),
            EventKind::Message,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Text("stale".into())),
                (2, Value::Null),
                (3, Value::Bool(false)),
                (4, Value::Array(Vec::new())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&no_policy_head),
            EventAuthorization::Rejected(RejectReason::IncompletePolicyHeads)
        );
    }
    #[test]
    fn unsigned_in_graph_only_message_cannot_authorize_an_edit_target() {
        let identity = DeviceIdentity::generate().unwrap();
        let author = identity.fingerprint();
        let space = [60; 16];
        let group = [61; 32];
        let channel = [62; 16];
        let genesis = make_bound_event(
            &identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(author, channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        let mut reducer = SpaceReducer::new();
        let _ = reducer.apply(&genesis, None);
        let graph_only_target = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id: space,
                channel_id: Some(channel),
                author_sequence: 2,
                lamport: 0,
                wall_time_hint: 0,
                parents: vec![EventId::from_bytes(root_id)],
                kind: EventKind::Message,
                protected_body: b"not MLS-bound".to_vec(),
                mls_group_reference: group,
                mls_epoch: 0,
            },
        )
        .unwrap();
        let target_id = *graph_only_target.event_id().as_bytes();
        reducer.observe_graph_event(&graph_only_target).unwrap();
        let edit = make_application_event(
            &identity,
            space,
            channel,
            group,
            vec![target_id],
            EventKind::Edit,
            &policy([
                (0, Value::Unsigned(1)),
                (1, Value::Bytes(target_id.to_vec())),
                (2, Value::Text("must not authorize".into())),
            ]),
        );
        assert_eq!(
            reducer.authorize_application_event(&edit),
            EventAuthorization::Rejected(RejectReason::InvalidTarget)
        );
    }
    #[allow(clippy::too_many_lines)]
    #[test]
    fn control_event_requires_exact_staged_commit_proof() {
        use lattice_events::EventDraft;
        use lattice_mls::api::{DeviceCredentialInput, GroupState, IncomingResult};
        use openmls::credentials::{Credential, CredentialType};
        use openmls_rust_crypto::OpenMlsRustCrypto;

        fn test_credential(identity: &DeviceIdentity) -> DeviceCredentialInput {
            let credential = Credential::new(
                CredentialType::X509,
                b"test-only untrusted X.509 placeholder".to_vec(),
            );
            DeviceCredentialInput::from_untrusted_x509_credential_for_tests(identity, &credential)
                .expect("test credential matches the device signer")
        }

        let provider_alice = OpenMlsRustCrypto::default();
        let provider_bob = OpenMlsRustCrypto::default();
        let alice_identity = DeviceIdentity::generate().unwrap();
        let bob_identity = DeviceIdentity::generate().unwrap();
        let charlie_identity = DeviceIdentity::generate().unwrap();
        let alice_credential = test_credential(&alice_identity);
        let bob_credential = test_credential(&bob_identity);
        let charlie_credential = test_credential(&charlie_identity);
        let mut alice =
            GroupState::create(&provider_alice, &alice_identity, &alice_credential).unwrap();
        let bob_key_package =
            GroupState::publish_key_package(&provider_bob, &bob_identity, &bob_credential).unwrap();
        let bob_add = alice
            .prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                bob_key_package.as_bytes(),
            )
            .unwrap();
        let group_id = alice.group_id();
        let bob_welcome = alice
            .accept_prepared_add(&provider_alice, &bob_add, bob_add.commit().as_bytes())
            .unwrap();
        let mut bob = GroupState::from_welcome(
            &provider_bob,
            &group_id,
            &bob_credential,
            bob_welcome.as_bytes(),
        )
        .unwrap();
        let charlie_key_package = GroupState::publish_key_package(
            &provider_alice,
            &charlie_identity,
            &charlie_credential,
        )
        .unwrap();
        let charlie_add = alice
            .prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                charlie_key_package.as_bytes(),
            )
            .unwrap();
        let commit = charlie_add.commit().as_bytes();
        assert!(matches!(
            bob.process_incoming(&provider_bob, commit),
            Ok(IncomingResult::StagedCommit { .. })
        ));
        let proof = bob.take_staged_membership_change().unwrap();
        let parent_epoch = proof.parent_epoch();
        let space = [80; 16];
        let group = alice.group_reference();
        let channel = [81; 16];
        let mut reducer = SpaceReducer::new();
        let genesis = make_bound_event(
            &alice_identity,
            space,
            group,
            0,
            Vec::new(),
            genesis_payload(alice_identity.fingerprint(), channel),
        );
        let root_id = *genesis.event().event_id().as_bytes();
        assert_eq!(
            reducer.apply(&genesis, None),
            ApplyResult::Applied { revision: 0 }
        );
        let invite_id = [82; 16];
        let target = charlie_identity.fingerprint();
        let key_package_hash = *proof.key_package_hash().unwrap();
        let invite = make_bound_event(
            &alice_identity,
            space,
            group,
            parent_epoch,
            vec![root_id],
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(2)),
                (2, Value::Bytes(invite_id.to_vec())),
                (3, Value::Bytes(target.to_vec())),
                (4, Value::Bytes(key_package_hash.to_vec())),
                (5, Value::Null),
                (6, Value::Null),
            ]),
        );
        let invite_event_id = *invite.event().event_id().as_bytes();
        assert_eq!(
            reducer.apply(&invite, None),
            ApplyResult::Applied { revision: 1 }
        );
        let make_control_event = |body: Vec<u8>, parents: Vec<EventReference>| {
            VerifiedSignatureOnlyEvent::create(
                &alice_identity,
                EventDraft {
                    space_id: space,
                    channel_id: None,
                    author_sequence: 3,
                    lamport: 0,
                    wall_time_hint: 0,
                    parents: parents.into_iter().map(EventId::from_bytes).collect(),
                    kind: EventKind::MlsControl,
                    protected_body: body,
                    mls_group_reference: group,
                    mls_epoch: parent_epoch,
                },
            )
            .unwrap()
        };
        let control = make_control_event(commit.to_vec(), vec![invite_event_id]);
        let control_id = *control.event_id().as_bytes();
        reducer
            .observe_validated_control_event(&control, proof)
            .expect("exact authenticated Commit binds to the signed control event");
        let transition = make_bound_event(
            &alice_identity,
            space,
            group,
            parent_epoch,
            vec![control_id],
            policy([
                (0, Value::Unsigned(1)),
                (1, Value::Unsigned(6)),
                (2, Value::Unsigned(0)),
                (3, Value::Bytes(target.to_vec())),
                (4, Value::Bytes(invite_event_id.to_vec())),
                (5, Value::Bytes(control_id.to_vec())),
            ]),
        );
        assert_eq!(
            reducer.apply(&transition, None),
            ApplyResult::Applied { revision: 2 }
        );
        let accepted = reducer.policy().unwrap();
        assert_eq!(member_status(accepted, &target), Some(MemberStatus::Active));
        assert_eq!(accepted.invites[0].uses, 1);
    }
}
