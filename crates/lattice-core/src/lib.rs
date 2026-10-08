//! Lattice local device core.
//!
//! The facade owns a durable store and device identity. It binds verified
//! events to MLS results and can atomically create local candidate Spaces or
//! stage application authorization with exact event bytes in a caller-owned
//! `SQLite` transaction. It also atomically validates a parent-epoch member
//! transition, merges its staged MLS Commit, and stores both exact signed event
//! Accepted local membership transitions replay their protected policy
//! history; sibling-Commit conflicts are durably recorded and revalidated on
//! restore. Authorized owners can create and restore a fresh root from retained
//! common policy; pinned Welcome imports restore their signed checkpoint and
//! locally authenticated membership-transition history.

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Transaction;

use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
use lattice_files::AttachmentManifest;
use lattice_identity::{
    BleExp0IdentitySignature, DeviceIdentity, IdentityError, IdentityPublicBundle,
    PrivateKeyProtector,
};
use lattice_mls::{
    ProtectedCodecError, ProtectedSqliteProvider,
    api::{
        CredentialTrustPolicy, DeviceCredentialInput, GroupState, IncomingResult, MlsApplication,
    },
    migrate_protected_sqlite, with_mls_storage_key,
};
use lattice_protocol::{Value, decode_canonical, encode_canonical};
use lattice_relay::profile::MailboxToken;
use lattice_storage::{
    CachedSpaceMessage, CommitOutcome, DirectMessageRecord, MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE,
    MAX_SPACE_GENESIS_PAGE_SIZE, SpaceGenesisSnapshot, SpaceMembershipConflictSnapshot,
    SpaceMembershipTransitionSnapshot, Store, StoreError,
};
pub use lattice_storage::{
    DirectMessageConversation, DirectMessageOutboxEntry, MAX_DIRECT_MESSAGE_PENDING_INVITATIONS,
    MAX_OUTBOX_PAGE_SIZE, OutboxEntry, OutboxState, PendingDirectMessageInvitation,
    SpaceGenesisCursor,
};
use openmls::credentials::Credential;
use openmls::prelude::CredentialType;
use thiserror::Error;
use zeroize::Zeroizing;

mod bootstrap_snapshot;
mod direct_message;
pub use direct_message::{
    CreatedDirectMessage, DirectMessageIngressOutcome, DirectMessagePacket,
    DirectMessagePendingInvitation, LocalDirectMessage, MAX_DIRECT_MESSAGE_PACKET_BYTES,
    MAX_DIRECT_MESSAGE_TEXT_BYTES,
};
mod identity_pin;
mod space_bootstrap;
mod space_invite;
pub use space_bootstrap::{MAX_SPACE_WELCOME_BOOTSTRAP_BYTES, SpaceWelcomeBootstrapV1};
pub use space_invite::{
    MAX_SPACE_INVITE_BYTES, MAX_SPACE_INVITE_HINTS, SpaceInviteError, SpaceInviteHint,
    SpaceInviteHintKind, SpaceInviteV1,
};
pub mod space;
/// Stable name of this local orchestration facade.
pub const CRATE_NAME: &str = "lattice-core";

/// Read-only public identity information safe for app and CLI display.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIdentityInfo {
    /// Versioned 65-byte public identity bundle.
    pub public_bundle: [u8; 65],
    /// Full domain-separated SHA-256 fingerprint of `public_bundle`.
    pub fingerprint: [u8; 32],
}

/// Maximum RFC 9420 X.509 credential content accepted for local Space creation.
pub const MAX_SPACE_CREDENTIAL_BYTES: usize = lattice_mls::api::MAX_CREDENTIAL_BYTES;
/// Maximum UTF-8 query bytes accepted by local text-history search.
pub const MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES: usize = 256;
/// Maximum matching messages returned by one local search.
pub const MAX_LOCAL_TEXT_SEARCH_RESULTS: usize = 100;
/// Maximum number of locally available one-time `KeyPackages` maintained by
/// [`Client::replenish_key_packages`].
pub const MAX_LOCAL_KEY_PACKAGE_INVENTORY: usize = 32;
/// Maximum distinct local identity/role mention targets retained in preferences.
pub const MAX_LOCAL_MUTED_MENTION_TARGETS: usize = 4096;
const MAX_SPACE_RECOVERY_DEPTH: usize = 32;

/// Caller-selected fields for one initial channel; its identifier is generated
/// by [`Client::create_space`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialChannel {
    /// Candidate channel type.
    pub channel_type: space::ChannelType,
    /// Display-only name, validated by the Space policy reducer.
    pub name: String,
    /// Initial channel-level allow mask.
    pub default_allow: u64,
    /// Initial channel-level deny mask.
    pub default_deny: u64,
    /// Sorted role-specific overrides using the candidate built-in role IDs.
    pub role_overrides: Vec<space::RoleOverride>,
}
/// Fields for one tagged reaction add or observed-tag removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextMessageReaction {
    /// Channel containing the target message.
    pub channel_id: space::EntityId,
    /// Immutable event identifier of the target message.
    pub target: [u8; 32],
    /// Reaction token to add or remove.
    pub token: String,
    /// Whether this operation adds a reaction.
    pub add: bool,
    /// Prior add-event identifier for a removal; absent for an add.
    pub tag: Option<[u8; 32]>,
}

/// Fields for one pin add or observed-tag removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMessagePin {
    /// Channel containing the target message.
    pub channel_id: space::EntityId,
    /// Immutable event identifier of the target message.
    pub target: [u8; 32],
    /// Whether this operation adds a pin.
    pub add: bool,
    /// Prior pin-add event identifier for a removal; absent for an add.
    pub tag: Option<[u8; 32]>,
}

/// Parameters shared by local reaction and pin event construction.
struct TextMessageUpdate {
    channel_id: space::EntityId,
    target: [u8; 32],
    causal_tag: Option<[u8; 32]>,
    event_kind: EventKind,
    plaintext: Vec<u8>,
}

/// Result of creating a local candidate Space and its one-member MLS generation.
pub struct CreatedSpace {
    space_id: space::SpaceId,
    group_id: Vec<u8>,
    group_reference: space::GroupReference,
    genesis_event: VerifiedSignatureOnlyEvent,
    reducer: space::SpaceReducer,
}

/// Signed offline invitation artifacts for one committed membership transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedSpaceInvite {
    invite_event_id: [u8; 32],
    target_fingerprint: [u8; 32],
    token: Vec<u8>,
    welcome_bootstrap: Vec<u8>,
}

impl CreatedSpaceInvite {
    /// Returns the signed policy Invite event identifier.
    #[must_use]
    pub const fn invite_event_id(&self) -> &[u8; 32] {
        &self.invite_event_id
    }

    /// Returns the invited device's full identity fingerprint.
    #[must_use]
    pub const fn target_fingerprint(&self) -> &[u8; 32] {
        &self.target_fingerprint
    }

    /// Returns canonical signed invite-token bytes.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Returns the signed Welcome bootstrap bytes used by `space join`.
    #[must_use]
    pub fn welcome_bootstrap(&self) -> &[u8] {
        &self.welcome_bootstrap
    }
}

/// Durable event identifiers and epochs for one committed Space member removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatedSpaceMemberRemoval {
    target_fingerprint: [u8; 32],
    control_event_id: [u8; 32],
    transition_event_id: [u8; 32],
    parent_epoch: u64,
    new_epoch: u64,
}

impl CreatedSpaceMemberRemoval {
    /// Returns the removed device's full identity fingerprint.
    #[must_use]
    pub const fn target_fingerprint(&self) -> &[u8; 32] {
        &self.target_fingerprint
    }

    /// Returns the persisted MLS Remove control event identifier.
    #[must_use]
    pub const fn control_event_id(&self) -> &[u8; 32] {
        &self.control_event_id
    }

    /// Returns the persisted Space policy transition event identifier.
    #[must_use]
    pub const fn transition_event_id(&self) -> &[u8; 32] {
        &self.transition_event_id
    }

    /// Returns the MLS epoch used to authorize the removal.
    #[must_use]
    pub const fn parent_epoch(&self) -> u64 {
        self.parent_epoch
    }

    /// Returns the MLS epoch after the exact Remove Commit was merged.
    #[must_use]
    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }
}

/// Event identifier for one locally authorized text message in the queued outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedMessage {
    event_id: [u8; 32],
}

impl QueuedMessage {
    /// Returns the immutable identifier of the committed message event.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }
}

/// Event identifier for one locally authorized attachment manifest in the outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedFileManifest {
    event_id: [u8; 32],
}

impl QueuedFileManifest {
    /// Returns the immutable identifier of the committed manifest event.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }
}
/// One locally retained, authorized text message; authored or received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalTextMessageRecord {
    pub event_id: [u8; 32],
    pub channel_id: space::EntityId,
    pub author_id: [u8; 32],
    pub author_sequence: u64,
    pub lamport: u64,
    pub content: String,
    pub outbox_state: Option<OutboxState>,
}
/// Bounded offline search result over locally retained authorized text messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalTextMessageSearchResult {
    /// Newest matching messages in chronological order.
    pub messages: Vec<LocalTextMessageRecord>,
    /// Exact number of matches in the locally retained channel cache.
    pub total_matches: usize,
    /// Number of locally retained channel messages searched.
    pub scanned_messages: usize,
}

/// Result of handling one signature-verified application event for sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncedApplicationOutcome {
    /// The event passed MLS binding and Space authorization and was committed.
    Accepted { event_id: [u8; 32] },
    /// The event is already committed with identical exact bytes.
    Duplicate { event_id: [u8; 32] },
    /// The bounded pending store retained this event until listed parents arrive.
    Pending {
        event_id: [u8; 32],
        missing_dependencies: Vec<[u8; 32]>,
    },
    /// Signed ciphertext predates the local MLS checkpoint; retained only as DAG ancestry.
    CheckpointExcluded { event_id: [u8; 32] },
}

/// Receipt for queuing a generation-scoped MLS mailbox-control event.
#[derive(Debug, Eq, PartialEq)]
pub struct PublishedSpaceRelayMailbox {
    event_id: [u8; 32],
    mailbox: MailboxToken,
}

impl PublishedSpaceRelayMailbox {
    /// Returns the local signed control-event identifier.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }

    /// Returns the protected generation mailbox selector for relay retrieval.
    #[must_use]
    pub const fn mailbox(&self) -> MailboxToken {
        self.mailbox
    }
}

impl CreatedSpace {
    /// Returns the random 16-byte Space identifier.
    #[must_use]
    pub const fn space_id(&self) -> &space::SpaceId {
        &self.space_id
    }

    /// Returns the persisted MLS group identifier needed to reopen this generation.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Returns the candidate event-visible MLS group reference.
    #[must_use]
    pub const fn group_reference(&self) -> &space::GroupReference {
        &self.group_reference
    }

    /// Returns the exact signed Genesis event.
    #[must_use]
    pub const fn genesis_event(&self) -> &VerifiedSignatureOnlyEvent {
        &self.genesis_event
    }

    /// Returns the in-memory candidate policy initialized from Genesis.
    ///
    /// This process-local view can be restored from the encrypted local Genesis
    /// snapshot; later policy mutations are not included.
    #[must_use]
    pub const fn reducer(&self) -> &space::SpaceReducer {
        &self.reducer
    }
}

/// One bounded page of verified signed events retained in an outbox.
#[must_use]
pub struct OutboxApplicationEventPage {
    events: Vec<Vec<u8>>,
    next_cursor: Option<[u8; 32]>,
}

impl OutboxApplicationEventPage {
    /// Returns exact signed event bytes for the requested Space generation.
    #[must_use]
    pub fn events(&self) -> &[Vec<u8>] {
        &self.events
    }

    /// Returns the cursor for the next outbox page, if this page was full.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<[u8; 32]> {
        self.next_cursor
    }
}

/// One bounded page of locally recoverable Space generations.
#[must_use]
pub struct RestoredSpacePage {
    spaces: Vec<CreatedSpace>,
    next_cursor: Option<SpaceGenesisCursor>,
}

impl RestoredSpacePage {
    /// Returns the verified local Space generations in this page.
    #[must_use]
    pub fn spaces(&self) -> &[CreatedSpace] {
        &self.spaces
    }

    /// Returns the exclusive cursor for the next page, if this page is full.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<SpaceGenesisCursor> {
        self.next_cursor
    }
}

/// Event payload bound to an MLS application or a locally authenticated Genesis.
///
/// External applications enter through [`bind_mls_application`], which proves
/// that `OpenMLS` processed the exact event ciphertext and binds the sender's
/// validated identity fingerprint. Local Genesis creation requires a
/// production-validated credential. Restore checks persisted credential
/// framing and key identity but does not recheck current path trust or expiry.
/// Neither path evaluates Space/channel authorization or application policy.
#[must_use]
#[derive(Debug)]
pub struct MlsBoundEvent {
    event: VerifiedSignatureOnlyEvent,
    plaintext: Vec<u8>,
}

impl MlsBoundEvent {
    /// Returns the signature-verified event bound to the MLS application.
    #[must_use]
    pub const fn event(&self) -> &VerifiedSignatureOnlyEvent {
        &self.event
    }

    /// Returns plaintext produced by processing that event's exact ciphertext.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Binds a signature-verified event to a successful MLS application result.
///
/// The binding rejects events whose author key or full identity fingerprint, protected body,
/// MLS epoch, or event-visible MLS group reference differs from the authenticated MLS result.
/// A successful value is not authorization and must not be treated as
/// permission to mutate a Space.
///
/// # Errors
///
/// Returns [`CoreError::MlsEventBindingFailed`] if the MLS member key or full
/// identity fingerprint, exact ciphertext, epoch, or group reference differs.
pub fn bind_mls_application(
    event: VerifiedSignatureOnlyEvent,
    application: MlsApplication,
) -> Result<MlsBoundEvent, CoreError> {
    let author_key = event.identity_bundle().ed25519_public_key();
    if application.member_signature_key() != Some(&author_key)
        || application.member_identity_fingerprint() != Some(event.author_fingerprint())
        || !application.matches_ciphertext(event.protected_body())
        || application.epoch() != event.mls_epoch()
        || application.group_reference() != event.mls_group_reference()
    {
        return Err(CoreError::MlsEventBindingFailed);
    }

    Ok(MlsBoundEvent {
        event,
        plaintext: application.into_plaintext(),
    })
}

/// Authorizes a bound application event and stores its exact outer bytes in the
/// caller's `SQLite` transaction.
///
/// The returned reducer is a staged copy. Install it only after the enclosing
/// transaction commits; on an authorization result other than `Authorized`, no
/// event row is written. Pending dependency bytes must be retained through the
/// bounded pending-event API rather than treated as accepted history.
///
/// # Errors
///
/// Returns [`CoreError::Storage`] for storage failures or
/// [`CoreError::ReceivedEventEquivocation`] if the authenticated author sequence
/// is already occupied by another event.
pub fn authorize_and_store_application_event(
    transaction: &Transaction<'_>,
    reducer: &space::SpaceReducer,
    event: &MlsBoundEvent,
) -> Result<(space::SpaceReducer, space::EventAuthorization), CoreError> {
    let mut staged_reducer = reducer.clone();
    let authorization = staged_reducer.authorize_application_event(event);
    if let space::EventAuthorization::Authorized { .. } = authorization {
        let verified = event.event();
        let event_id = *verified.event_id().as_bytes();
        let author_id = *verified.author_fingerprint();
        let parents = verified
            .parents()
            .iter()
            .map(|parent| *parent.as_bytes())
            .collect::<Vec<_>>();
        if let CommitOutcome::Equivocation { existing_event_id } =
            Store::commit_received_in_transaction(
                transaction,
                author_id,
                event_id,
                verified.author_sequence(),
                verified.encoded_bytes(),
                &parents,
            )?
        {
            return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
        }
    }
    Ok((staged_reducer, authorization))
}

fn store_received_event(
    transaction: &Transaction<'_>,
    event: &VerifiedSignatureOnlyEvent,
) -> Result<(), CoreError> {
    let parents = event
        .parents()
        .iter()
        .map(|parent| *parent.as_bytes())
        .collect::<Vec<_>>();
    if let CommitOutcome::Equivocation { existing_event_id } =
        Store::commit_received_in_transaction(
            transaction,
            *event.author_fingerprint(),
            *event.event_id().as_bytes(),
            event.author_sequence(),
            event.encoded_bytes(),
            &parents,
        )?
    {
        return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
    }
    Ok(())
}

fn commit_authored_event_to_outbox(
    transaction: &Transaction<'_>,
    event: &VerifiedSignatureOnlyEvent,
) -> Result<(), CoreError> {
    let parents = event
        .parents()
        .iter()
        .map(|parent| *parent.as_bytes())
        .collect::<Vec<_>>();
    if let CommitOutcome::Equivocation { existing_event_id } =
        Store::commit_authored_with_outbox_in_transaction(
            transaction,
            *event.author_fingerprint(),
            *event.event_id().as_bytes(),
            event.author_sequence(),
            event.encoded_bytes(),
            &parents,
            event.encoded_bytes(),
            0,
        )?
    {
        return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
    }
    Ok(())
}

/// Local core setup, protected MLS state, and durable-store failures.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Opening or writing the durable event/identity store failed.
    #[error(transparent)]
    Storage(#[from] StoreError),
    /// Creating or reopening the protected device identity failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// A fingerprint is already pinned to different public bundle bytes.
    #[error("identity fingerprint is already pinned to different bundle bytes")]
    PinnedIdentityConflict,
    /// A protected MLS storage key did not contain exactly 32 bytes.
    #[error("protected MLS storage key is invalid")]
    MlsStorageKeyInvalid,
    /// The OS random source could not provide an MLS storage key.
    #[error("OS randomness failed while initializing protected MLS storage")]
    MlsStorageKeyRandomness,
    /// `OpenMLS` database schema migration failed.
    #[error("protected MLS storage schema migration failed")]
    MlsStorageMigration,
    /// A protected MLS provider operation ran without a valid key scope.
    #[error(transparent)]
    MlsStorageCodec(#[from] ProtectedCodecError),
    /// An MLS operation failed and its enclosing transaction was rolled back.
    #[error(transparent)]
    Mls(#[from] lattice_mls::api::MlsError),
    /// A random identifier could not be generated for local Space creation.
    #[error("OS randomness failed while creating a Space identifier")]
    SpaceIdentifierRandomness,
    /// The local clock could not provide a valid signed wall-time hint.
    #[error("system wall clock is outside the supported Unix-millisecond range")]
    SpaceWallClockInvalid,
    /// Locally generated Space genesis did not satisfy its exact policy schema.
    #[error("candidate Space genesis rejected: {0:?}")]
    SpaceGenesisRejected(space::RejectReason),
    /// The production X.509 credential failed validation against the local identity.
    #[error("Space X.509 credential validation failed")]
    SpaceCredentialInvalid,
    /// The requested `KeyPackage` inventory exceeds the local bound.
    #[error("requested KeyPackage inventory exceeds the local maximum")]
    KeyPackageInventoryLimit,
    /// The local clock makes a newly generated `KeyPackage` immediately stale.
    #[error("system time is beyond the generated KeyPackage lifetime")]
    KeyPackageExpiredAtIssuance,
    /// Canonical Space genesis CBOR could not be encoded.
    #[error(transparent)]
    Protocol(#[from] lattice_protocol::Error),
    /// Signed event creation failed while constructing local Space genesis.
    #[error(transparent)]
    Event(#[from] lattice_events::EventError),
    /// An existing identity was required, but this data directory has none.
    #[error("no protected device identity is initialized")]
    MissingIdentity,
    /// A verified event did not match its authenticated MLS application result.
    #[error("event does not match the authenticated MLS application")]
    MlsEventBindingFailed,
    /// A membership control event did not bind to the staged MLS proof.
    #[error("Space membership control relation rejected: {0:?}")]
    SpaceControlRejected(space::RejectReason),
    /// A signed event could not join the local reducer graph.
    #[error("Space event graph rejected: {0:?}")]
    SpaceGraphEventRejected(space::RejectReason),
    /// The policy membership transition was not applied.
    #[error("Space membership policy transition not applied: {0:?}")]
    SpaceMembershipNotApplied(space::ApplyResult),
    /// A locally authenticated membership replay record failed validation.
    #[error("local Space membership transition snapshot is invalid")]
    SpaceMembershipSnapshotInvalid,
    /// A Welcome bootstrap package failed its signature or policy binding.
    #[error("Space Welcome bootstrap package is invalid")]
    SpaceWelcomeBootstrapInvalid,
    /// A signed offline invitation artifact could not be validated or encoded.
    #[error("Space invite artifact is invalid")]
    SpaceInviteInvalid,
    /// The inviter in a Welcome bootstrap package is not locally pinned.
    #[error("Space Welcome bootstrap inviter is not locally trusted")]
    SpaceWelcomeBootstrapUntrustedInviter,
    /// A conflict between valid sibling MLS Commits has been durably recorded.
    #[error("Space MLS membership generation is conflicted")]
    SpaceMembershipConflicted,
    /// A received author sequence is occupied by a different event ID.
    #[error("received author sequence conflicts with event {existing_event_id:02x?}")]
    ReceivedEventEquivocation { existing_event_id: [u8; 32] },
    /// An encrypted local message cache row failed event binding or validation.
    #[error("local Space message cache entry is invalid")]
    LocalSpaceMessageCacheInvalid,
    /// A protected local mention-preference record failed canonical validation.
    #[error("local mention preferences are invalid")]
    InvalidLocalMentionPreferences,
    /// A local history search query is empty or exceeds its byte bound.
    #[error("local text-message search query is invalid")]
    InvalidLocalTextMessageSearch,
    /// A locally authored message failed the Space policy gate.
    #[error("Space message rejected: {0:?}")]
    SpaceMessageRejected(space::EventAuthorization),
    /// One of the current policy-head events is missing from local storage.
    #[error("a Space policy parent event is missing")]
    SpaceParentEventMissing,
    /// The outbox references a signed event that is absent from durable storage.
    #[error("outbox event is missing its signed event record")]
    OutboxEventMissing,
    /// The Lamport counter cannot advance beyond the parent events.
    #[error("Space message Lamport counter is exhausted")]
    SpaceLamportExhausted,
    /// Attachment manifest validation failed or exceeded protocol limits.
    #[error(transparent)]
    Attachment(#[from] lattice_files::AttachmentError),
    /// A locally created Space Genesis or encrypted projection snapshot is absent.
    #[error("local Space Genesis snapshot was not found")]
    SpaceGenesisSnapshotNotFound,

    /// A direct-message packet is malformed or is not an authenticated application message.
    #[error("direct-message packet is invalid")]
    DirectMessagePacketInvalid,
    /// The requested direct-message conversation is absent or closed.
    #[error("direct-message conversation is unavailable")]
    DirectMessageConversationUnavailable,
    /// The authenticated transport peer does not match the pinned DM peer.
    #[error("direct-message authenticated peer mismatch")]
    DirectMessagePeerMismatch,
    /// A relay mailbox control payload or its protected local record is invalid.
    #[error("Space relay mailbox control is invalid")]
    SpaceRelayMailboxInvalid,
    /// The OS random source could not provide a generation mailbox token.
    #[error("OS randomness failed while creating a Space relay mailbox")]
    SpaceRelayMailboxRandomness,
    /// A generation attempted to replace its immutable relay mailbox token.
    #[error("Space generation relay mailbox token conflicts with the accepted token")]
    SpaceRelayMailboxConflict,
    /// Relay mailbox publication requires at least one admitted peer.
    #[error("relay mailbox control can be published only after a peer is admitted")]
    SpaceRelayMailboxRequiresAdmission,
}

fn prepare_space_genesis(
    creator: &[u8; 32],
    channels: Vec<InitialChannel>,
) -> Result<(space::SpaceId, Vec<u8>), CoreError> {
    if channels.is_empty() || channels.len() > space::MAX_INITIAL_CHANNELS {
        return Err(CoreError::SpaceGenesisRejected(
            space::RejectReason::LimitExceeded,
        ));
    }
    let mut space_id = [0_u8; 16];
    getrandom::fill(&mut space_id).map_err(|_| CoreError::SpaceIdentifierRandomness)?;
    let mut channel_ids = BTreeSet::new();
    let mut channel_values = Vec::with_capacity(channels.len());
    for channel in channels {
        let mut channel_id = [0_u8; 16];
        getrandom::fill(&mut channel_id).map_err(|_| CoreError::SpaceIdentifierRandomness)?;
        if !channel_ids.insert(channel_id) {
            return Err(CoreError::SpaceGenesisRejected(
                space::RejectReason::DuplicateEntity,
            ));
        }
        let channel_type = match channel.channel_type {
            space::ChannelType::Text => 0,
            space::ChannelType::Announcement => 1,
            space::ChannelType::Voice => 2,
        };
        let role_overrides = channel
            .role_overrides
            .into_iter()
            .map(|override_| {
                Value::Map(vec![
                    (0, Value::Bytes(override_.role_id.to_vec())),
                    (1, Value::Unsigned(override_.allow)),
                    (2, Value::Unsigned(override_.deny)),
                ])
            })
            .collect();
        channel_values.push(Value::Map(vec![
            (0, Value::Bytes(channel_id.to_vec())),
            (1, Value::Unsigned(channel_type)),
            (2, Value::Text(channel.name)),
            (3, Value::Bool(false)),
            (4, Value::Unsigned(channel.default_allow)),
            (5, Value::Unsigned(channel.default_deny)),
            (6, Value::Array(role_overrides)),
        ]));
    }
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Unsigned(0)),
        (2, Value::Bytes(creator.to_vec())),
        (3, Value::Array(channel_values)),
    ]))?;
    Ok((space_id, plaintext))
}

fn prepare_space_recovery_genesis(
    prior: &space::SpaceReducer,
    creator: &[u8; 32],
) -> Result<(space::SpaceId, Vec<u8>), CoreError> {
    let policy = prior.policy().ok_or(CoreError::SpaceGenesisRejected(
        space::RejectReason::MissingPolicy,
    ))?;
    if policy.channels.is_empty() || policy.channels.len() > space::MAX_INITIAL_CHANNELS {
        return Err(CoreError::SpaceGenesisRejected(
            space::RejectReason::LimitExceeded,
        ));
    }
    let mut recovery_id = [0_u8; 16];
    getrandom::fill(&mut recovery_id).map_err(|_| CoreError::SpaceIdentifierRandomness)?;
    let mut channel_ids = BTreeSet::new();
    let channel_values = policy
        .channels
        .iter()
        .map(|channel| {
            if !channel_ids.insert(channel.id) {
                return Err(CoreError::SpaceGenesisRejected(
                    space::RejectReason::DuplicateEntity,
                ));
            }
            let channel_type = match channel.channel_type {
                space::ChannelType::Text => 0,
                space::ChannelType::Announcement => 1,
                space::ChannelType::Voice => 2,
            };
            let role_overrides = channel
                .role_overrides
                .iter()
                .map(|override_| {
                    Value::Map(vec![
                        (0, Value::Bytes(override_.role_id.to_vec())),
                        (1, Value::Unsigned(override_.allow)),
                        (2, Value::Unsigned(override_.deny)),
                    ])
                })
                .collect();
            Ok(Value::Map(vec![
                (0, Value::Bytes(channel.id.to_vec())),
                (1, Value::Unsigned(channel_type)),
                (2, Value::Text(channel.name.clone())),
                (3, Value::Bool(channel.archived)),
                (4, Value::Unsigned(channel.default_allow)),
                (5, Value::Unsigned(channel.default_deny)),
                (6, Value::Array(role_overrides)),
            ]))
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Unsigned(1)),
        (2, Value::Bytes(creator.to_vec())),
        (3, Value::Bytes(policy.group_reference.to_vec())),
        (4, Value::Bytes(policy.root_event_id.to_vec())),
        (5, Value::Bytes(recovery_id.to_vec())),
        (6, Value::Array(channel_values)),
    ]))?;
    Ok((policy.space_id, plaintext))
}

fn recovery_parent_group_reference(plaintext: &[u8]) -> Result<Option<[u8; 32]>, CoreError> {
    let Value::Map(fields) = decode_canonical(plaintext)? else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    let Some((1, Value::Unsigned(operation))) = fields.get(1) else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    match operation {
        1 => {
            if fields.len() != 7 || fields[0].0 != 0 || fields[2].0 != 2 || fields[3].0 != 3 {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            let Value::Bytes(group_reference) = &fields[3].1 else {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            };
            let group_reference = group_reference
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::SpaceMembershipSnapshotInvalid)?;
            Ok(Some(group_reference))
        }
        _ => Ok(None),
    }
}

fn space_genesis_context(
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
    event_id: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(20 + 16 + 32 + 32);
    context.extend_from_slice(b"lattice-space-genesis-v1\0");
    context.extend_from_slice(space_id);
    context.extend_from_slice(group_reference);
    context.extend_from_slice(event_id);
    context
}

fn space_membership_context(
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
    parent_epoch: u64,
    control_event_id: &[u8; 32],
    transition_event_id: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(45 + 16 + 32 + 8 + 32 + 32);
    context.extend_from_slice(b"lattice-space-membership-transition-v1\0");
    context.extend_from_slice(space_id);
    context.extend_from_slice(group_reference);
    context.extend_from_slice(&parent_epoch.to_be_bytes());
    context.extend_from_slice(control_event_id);
    context.extend_from_slice(transition_event_id);
    context
}

struct SpaceMembershipReplayData {
    parent_epoch: u64,
    policy_revision: u64,
    action: lattice_mls::api::MlsMembershipAction,
    target: [u8; 32],
    key_package_hash: Option<[u8; 32]>,
    plaintext: Vec<u8>,
    policy_events: Vec<space::SpacePolicyReplayEvent>,
}

fn encode_space_membership_replay_data(
    parent_epoch: u64,
    policy_revision: u64,
    action: lattice_mls::api::MlsMembershipAction,
    target: [u8; 32],
    key_package_hash: Option<[u8; 32]>,
    plaintext: &[u8],
    policy_events: Vec<space::SpacePolicyReplayEvent>,
) -> Result<Vec<u8>, CoreError> {
    if plaintext.is_empty()
        || plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES
        || (action == lattice_mls::api::MlsMembershipAction::Add) != key_package_hash.is_some()
        || policy_events.len() > 64
    {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    }
    let action = match action {
        lattice_mls::api::MlsMembershipAction::Add => 0,
        lattice_mls::api::MlsMembershipAction::Remove => 1,
    };
    let policy_events = policy_events
        .into_iter()
        .map(|event| {
            Value::Map(vec![
                (0, Value::Bytes(event.event_bytes)),
                (1, Value::Bytes(event.plaintext)),
            ])
        })
        .collect();
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(2)),
        (1, Value::Unsigned(parent_epoch)),
        (2, Value::Unsigned(action)),
        (3, Value::Bytes(target.to_vec())),
        (
            4,
            key_package_hash.map_or(Value::Null, |hash| Value::Bytes(hash.to_vec())),
        ),
        (5, Value::Bytes(plaintext.to_vec())),
        (6, Value::Unsigned(policy_revision)),
        (7, Value::Array(policy_events)),
    ]))
    .map_err(CoreError::from)
}

fn decode_space_membership_replay_data(
    bytes: &[u8],
) -> Result<SpaceMembershipReplayData, CoreError> {
    let Value::Map(fields) =
        decode_canonical(bytes).map_err(|_| CoreError::SpaceMembershipSnapshotInvalid)?
    else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    let mut fields = fields.into_iter();
    if fields.next() != Some((0, Value::Unsigned(2))) {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    }
    let Some((1, Value::Unsigned(parent_epoch))) = fields.next() else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    let action = match fields.next() {
        Some((2, Value::Unsigned(0))) => lattice_mls::api::MlsMembershipAction::Add,
        Some((2, Value::Unsigned(1))) => lattice_mls::api::MlsMembershipAction::Remove,
        _ => return Err(CoreError::SpaceMembershipSnapshotInvalid),
    };
    let Some((3, Value::Bytes(target))) = fields.next() else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    let target = target
        .try_into()
        .map_err(|_| CoreError::SpaceMembershipSnapshotInvalid)?;
    let key_package_hash = match fields.next() {
        Some((4, Value::Null)) => None,
        Some((4, Value::Bytes(hash))) => Some(
            hash.try_into()
                .map_err(|_| CoreError::SpaceMembershipSnapshotInvalid)?,
        ),
        _ => return Err(CoreError::SpaceMembershipSnapshotInvalid),
    };
    let Some((5, Value::Bytes(plaintext))) = fields.next() else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    let Some((6, Value::Unsigned(policy_revision))) = fields.next() else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    let Some((7, Value::Array(policy_events))) = fields.next() else {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    };
    if fields.next().is_some()
        || plaintext.is_empty()
        || plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES
        || policy_events.len() > 64
        || (action == lattice_mls::api::MlsMembershipAction::Add) != key_package_hash.is_some()
    {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    }
    let policy_events = policy_events
        .into_iter()
        .map(|value| {
            let Value::Map(fields) = value else {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            };
            let mut fields = fields.into_iter();
            let Some((0, Value::Bytes(event_bytes))) = fields.next() else {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            };
            let Some((1, Value::Bytes(plaintext))) = fields.next() else {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            };
            if fields.next().is_some() || plaintext.is_empty() {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            Ok(space::SpacePolicyReplayEvent {
                event_bytes,
                plaintext,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SpaceMembershipReplayData {
        parent_epoch,
        policy_revision,
        action,
        target,
        key_package_hash,
        plaintext,
        policy_events,
    })
}

fn replay_space_membership_transitions(
    reducer: &mut space::SpaceReducer,
    transitions: Vec<(SpaceMembershipTransitionSnapshot, Vec<u8>, Vec<u8>)>,
) -> Result<(), CoreError> {
    let base_epoch = transitions
        .first()
        .map_or(0, |(snapshot, _, _)| snapshot.parent_epoch);
    for (offset, (snapshot, control_bytes, transition_bytes)) in transitions.into_iter().enumerate()
    {
        let expected_epoch = base_epoch
            .checked_add(
                u64::try_from(offset).map_err(|_| CoreError::SpaceMembershipSnapshotInvalid)?,
            )
            .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
        if snapshot.parent_epoch != expected_epoch {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
        let control_event = VerifiedSignatureOnlyEvent::decode_verify(&control_bytes)?;
        let transition_event = VerifiedSignatureOnlyEvent::decode_verify(&transition_bytes)?;
        if control_event.event_id().as_bytes() != &snapshot.control_event_id
            || transition_event.event_id().as_bytes() != &snapshot.transition_event_id
            || control_event.space_id() != &snapshot.space_id
            || transition_event.space_id() != &snapshot.space_id
            || control_event.mls_group_reference() != &snapshot.group_reference
            || transition_event.mls_group_reference() != &snapshot.group_reference
            || control_event.kind() != EventKind::MlsControl
            || transition_event.kind() != EventKind::Membership
            || control_event.channel_id().is_some()
            || transition_event.channel_id().is_some()
            || control_event.mls_epoch() != expected_epoch
            || transition_event.mls_epoch() != expected_epoch
        {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
        let context = space_membership_context(
            &snapshot.space_id,
            &snapshot.group_reference,
            snapshot.parent_epoch,
            &snapshot.control_event_id,
            &snapshot.transition_event_id,
        );
        let evidence = lattice_mls::unprotect_local_record(&context, &snapshot.encrypted_state)?;
        let replay = decode_space_membership_replay_data(&evidence)?;
        if replay.parent_epoch != snapshot.parent_epoch
            || replay.policy_revision != snapshot.policy_revision
        {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
        for policy_event in replay.policy_events {
            let event = VerifiedSignatureOnlyEvent::decode_verify(&policy_event.event_bytes)?;
            if event.kind() != EventKind::Membership
                || event.space_id() != &snapshot.space_id
                || event.mls_group_reference() != &snapshot.group_reference
            {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            let bound = MlsBoundEvent {
                event,
                plaintext: policy_event.plaintext,
            };
            if !matches!(
                reducer.apply(&bound, None),
                space::ApplyResult::Applied { .. }
            ) {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
        }
        reducer
            .observe_persisted_control_event(
                &control_event,
                replay.action,
                replay.target,
                replay.key_package_hash,
            )
            .map_err(CoreError::SpaceControlRejected)?;
        let policy_revision_before_transition = reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
            .revision;
        if policy_revision_before_transition >= snapshot.policy_revision {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
        let bound = MlsBoundEvent {
            event: transition_event,
            plaintext: replay.plaintext,
        };
        if !matches!(
            reducer.apply(&bound, None),
            space::ApplyResult::Applied { .. }
        ) || reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
            .revision
            != snapshot.policy_revision
        {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
    }
    Ok(())
}

fn validate_restored_membership_state(
    group: &GroupState,
    reducer: &space::SpaceReducer,
    expected_transition_count: u64,
) -> Result<(), CoreError> {
    let active_members = reducer
        .policy()
        .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
        .members
        .iter()
        .filter(|member| member.status == space::MemberStatus::Active)
        .count();
    if group.epoch() != expected_transition_count || group.member_count() != active_members {
        return Err(CoreError::SpaceMembershipSnapshotInvalid);
    }
    Ok(())
}

fn local_text_message_context(
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
    channel_id: &space::EntityId,
    event_id: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(34 + 16 + 32 + 16 + 32);
    context.extend_from_slice(b"lattice-space-message-cache-v1\0");
    context.extend_from_slice(space_id);
    context.extend_from_slice(group_reference);
    context.extend_from_slice(channel_id);
    context.extend_from_slice(event_id);
    context
}

fn relay_mailbox_context(
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(38 + 16 + 32);
    context.extend_from_slice(b"lattice-space-relay-mailbox-v1\0");
    context.extend_from_slice(space_id);
    context.extend_from_slice(group_reference);
    context
}

fn encode_relay_mailbox_control(mailbox: MailboxToken) -> Result<Vec<u8>, CoreError> {
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Bytes(mailbox.as_bytes().to_vec())),
    ]))
    .map_err(CoreError::from)
}

fn decode_relay_mailbox_control(plaintext: &[u8]) -> Result<MailboxToken, CoreError> {
    let Value::Map(fields) =
        decode_canonical(plaintext).map_err(|_| CoreError::SpaceRelayMailboxInvalid)?
    else {
        return Err(CoreError::SpaceRelayMailboxInvalid);
    };
    if fields.len() != 2 || fields[0].0 != 0 || fields[0].1 != Value::Unsigned(1) {
        return Err(CoreError::SpaceRelayMailboxInvalid);
    }
    let (key, value) = &fields[1];
    if *key != 1 {
        return Err(CoreError::SpaceRelayMailboxInvalid);
    }
    let Value::Bytes(bytes) = value else {
        return Err(CoreError::SpaceRelayMailboxInvalid);
    };
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::SpaceRelayMailboxInvalid)?;
    Ok(MailboxToken::from_bytes(bytes))
}

fn decode_protected_relay_mailbox(
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
    ciphertext: &[u8],
) -> Result<MailboxToken, CoreError> {
    let context = relay_mailbox_context(space_id, group_reference);
    let plaintext = lattice_mls::unprotect_local_record(&context, ciphertext)?;
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::SpaceRelayMailboxInvalid)?;
    Ok(MailboxToken::from_bytes(bytes))
}

fn decode_text_message(plaintext: &[u8]) -> Result<String, CoreError> {
    let Value::Map(fields) = decode_canonical(plaintext)? else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let mut fields = fields.into_iter();
    let Some((0, Value::Unsigned(version @ 1..=3))) = fields.next() else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let Some((1, Value::Text(content))) = fields.next() else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    match fields.next() {
        Some((2, Value::Null)) => {}
        Some((2, Value::Bytes(root))) if root.len() == 32 => {}
        _ => return Err(CoreError::LocalSpaceMessageCacheInvalid),
    }
    if fields.next() != Some((3, Value::Bool(false)))
        || fields.next() != Some((4, Value::Array(Vec::new())))
    {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    if version >= 2 && !matches!(fields.next(), Some((5, Value::Array(_)))) {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    let _rich_text = if version == 3 {
        let Some((6, spans)) = fields.next() else {
            return Err(CoreError::LocalSpaceMessageCacheInvalid);
        };
        space::rich_text::RichText::parse_with_spans(&content, &spans)
    } else {
        space::rich_text::RichText::parse(&content)
    }
    .map_err(|_| CoreError::LocalSpaceMessageCacheInvalid)?;
    if fields.next().is_some() {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    Ok(content)
}

fn mention_target_value(target: space::MentionTarget) -> Value {
    match target {
        space::MentionTarget::Identity(fingerprint) => {
            Value::Array(vec![Value::Unsigned(0), Value::Bytes(fingerprint.to_vec())])
        }
        space::MentionTarget::Role(role_id) => {
            Value::Array(vec![Value::Unsigned(1), Value::Bytes(role_id.to_vec())])
        }
    }
}

fn decode_mention_target(value: &Value) -> Result<space::MentionTarget, CoreError> {
    let Value::Array(fields) = value else {
        return Err(CoreError::InvalidLocalMentionPreferences);
    };
    if fields.len() != 2 {
        return Err(CoreError::InvalidLocalMentionPreferences);
    }
    match (&fields[0], &fields[1]) {
        (Value::Unsigned(0), Value::Bytes(bytes)) => Ok(space::MentionTarget::Identity(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::InvalidLocalMentionPreferences)?,
        )),
        (Value::Unsigned(1), Value::Bytes(bytes)) => Ok(space::MentionTarget::Role(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::InvalidLocalMentionPreferences)?,
        )),
        _ => Err(CoreError::InvalidLocalMentionPreferences),
    }
}

fn encode_local_mention_mutes(
    targets: &std::collections::BTreeSet<space::MentionTarget>,
) -> Result<Vec<u8>, CoreError> {
    if targets.len() > MAX_LOCAL_MUTED_MENTION_TARGETS {
        return Err(CoreError::InvalidLocalMentionPreferences);
    }
    let values = targets.iter().copied().map(mention_target_value).collect();
    Ok(encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Array(values)),
    ]))?)
}

fn decode_local_mention_mutes(
    plaintext: &[u8],
) -> Result<std::collections::BTreeSet<space::MentionTarget>, CoreError> {
    let Value::Map(fields) = decode_canonical(plaintext)? else {
        return Err(CoreError::InvalidLocalMentionPreferences);
    };
    if fields.len() != 2 || fields[0] != (0, Value::Unsigned(1)) {
        return Err(CoreError::InvalidLocalMentionPreferences);
    }
    let Value::Array(values) = &fields[1].1 else {
        return Err(CoreError::InvalidLocalMentionPreferences);
    };
    if fields[1].0 != 1 || values.len() > MAX_LOCAL_MUTED_MENTION_TARGETS {
        return Err(CoreError::InvalidLocalMentionPreferences);
    }
    let targets = values
        .iter()
        .map(decode_mention_target)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if targets.len() != values.len() {
        return Err(CoreError::InvalidLocalMentionPreferences);
    }
    Ok(targets)
}

fn decode_text_edit(plaintext: &[u8]) -> Result<([u8; 32], String), CoreError> {
    let Value::Map(fields) = decode_canonical(plaintext)? else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let mut fields = fields.into_iter();
    let Some((0, Value::Unsigned(version @ (1 | 2)))) = fields.next() else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let Some((1, Value::Bytes(target))) = fields.next() else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let target = target
        .try_into()
        .map_err(|_| CoreError::LocalSpaceMessageCacheInvalid)?;
    let Some((2, Value::Text(content))) = fields.next() else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let _rich_text = if version == 2 {
        let Some((3, spans)) = fields.next() else {
            return Err(CoreError::LocalSpaceMessageCacheInvalid);
        };
        space::rich_text::RichText::parse_with_spans(&content, &spans)
    } else {
        space::rich_text::RichText::parse(&content)
    }
    .map_err(|_| CoreError::LocalSpaceMessageCacheInvalid)?;
    if fields.next().is_some() {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    Ok((target, content))
}

fn decode_tombstone_target(plaintext: &[u8]) -> Result<[u8; 32], CoreError> {
    let Value::Map(fields) = decode_canonical(plaintext)? else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    if fields.len() != 4 || fields[0] != (0, Value::Unsigned(1)) {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    let Value::Bytes(target) = &fields[1].1 else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    target
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::LocalSpaceMessageCacheInvalid)
}

fn create_space_in_transaction(
    identity: &DeviceIdentity,
    provider: &ProtectedSqliteProvider<'_>,
    transaction: &Transaction<'_>,
    credential: &lattice_mls::api::DeviceCredentialInput,
    space_id: space::SpaceId,
    plaintext: Vec<u8>,
    prior_reducer: Option<&space::SpaceReducer>,
) -> Result<
    (
        VerifiedSignatureOnlyEvent,
        space::SpaceReducer,
        Vec<u8>,
        space::GroupReference,
    ),
    CoreError,
> {
    let mut group = lattice_mls::api::GroupState::create(provider, identity, credential)?;
    let group_id = group.group_id();
    let group_reference = group.group_reference();
    let fingerprint = identity.fingerprint();
    let protected = group.encrypt_application(provider, identity, credential, &plaintext)?;
    let author_sequence = Store::next_author_sequence_in_transaction(transaction, &fingerprint)?;
    let event = VerifiedSignatureOnlyEvent::create(
        identity,
        EventDraft {
            space_id,
            channel_id: None,
            author_sequence,
            lamport: 0,
            wall_time_hint: 0,
            parents: Vec::new(),
            kind: EventKind::Membership,
            protected_body: protected.as_bytes().to_vec(),
            mls_group_reference: group_reference,
            mls_epoch: 0,
        },
    )?;
    let event_id = *event.event_id().as_bytes();
    let context = space_genesis_context(&space_id, &group_reference, &event_id);
    let encrypted_state = lattice_mls::protect_local_record(&context, &plaintext)?;

    // This path owns both OpenMLS encryption and event creation, establishing
    // the exact plaintext/ciphertext relation without an external proof object.
    let bound = MlsBoundEvent {
        event: event.clone(),
        plaintext,
    };
    let mut reducer = space::SpaceReducer::new();
    let authorization = prior_reducer
        .map(|prior| prior.authorize_recovery_genesis(&bound))
        .transpose()
        .map_err(CoreError::SpaceGenesisRejected)?;
    match reducer.apply(&bound, authorization.as_ref()) {
        space::ApplyResult::Applied { revision: 0 } => {}
        space::ApplyResult::Rejected(reason) => {
            return Err(CoreError::SpaceGenesisRejected(reason));
        }
        _ => {
            return Err(CoreError::SpaceGenesisRejected(
                space::RejectReason::InvalidGenesisContext,
            ));
        }
    }

    let parents = event
        .parents()
        .iter()
        .map(|parent| *parent.as_bytes())
        .collect::<Vec<_>>();
    if let CommitOutcome::Equivocation { existing_event_id } =
        Store::commit_authored_in_transaction(
            transaction,
            fingerprint,
            *event.event_id().as_bytes(),
            author_sequence,
            event.encoded_bytes(),
            &parents,
        )?
    {
        return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
    }
    Store::save_space_genesis_snapshot_in_transaction(
        transaction,
        &SpaceGenesisSnapshot {
            space_id,
            group_reference,
            group_id: group_id.clone(),
            event_id,
            encrypted_state,
        },
    )?;
    Ok((event, reducer, group_id, group_reference))
}

/// Local device core with OS-protected identity and encrypted durable MLS state.
///
/// Private identity bytes and the MLS storage key never enter `SQLite` in
/// plaintext. Every MLS provider operation must run through
/// [`Client::with_mls_transaction`], which scopes the decrypted key and commits
/// provider and application writes in the same `SQLite` transaction.
pub struct Client {
    store: Store,
    identity: DeviceIdentity,
    mls_storage_key: Zeroizing<[u8; 32]>,
    credential_trust_policy: CredentialTrustPolicy,
}

impl Client {
    /// Opens a profile and initializes its device identity if it does not exist.
    ///
    /// Concurrent initializers are serialized by `SQLite`'s unique identity and
    /// MLS-key slots; a losing initializer reopens the committed ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the store cannot be opened, protected identity
    /// cannot be loaded or created, or protected MLS storage cannot be initialized.
    pub fn open_or_create<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
    ) -> Result<Self, CoreError> {
        Self::open_or_create_with_trust_policy(
            database_path,
            protector,
            CredentialTrustPolicy::native_system(),
        )
    }

    /// Opens or initializes a profile with an explicit immutable trust policy.
    ///
    /// Browser callers must load their confirmed issuer pin from profile-local
    /// storage and pass it here; absence of that pin is not native trust.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the store cannot be opened, protected identity
    /// cannot be loaded or created, or protected MLS storage cannot be initialized.
    pub fn open_or_create_with_trust_policy<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
        credential_trust_policy: CredentialTrustPolicy,
    ) -> Result<Self, CoreError> {
        let mut store = Store::open(database_path)?;
        let identity = if let Some(ciphertext) = store.load_protected_identity()? {
            DeviceIdentity::load_protected(protector, &ciphertext)?
        } else {
            let (generated, ciphertext) = DeviceIdentity::generate_protected(protector)?;
            if store.save_protected_identity(&ciphertext)? {
                generated
            } else {
                let persisted = store
                    .load_protected_identity()?
                    .ok_or(CoreError::MissingIdentity)?;
                DeviceIdentity::load_protected(protector, &persisted)?
            }
        };
        Self::finish_open(store, identity, protector, credential_trust_policy)
    }

    /// Opens an existing profile using the caller's immutable credential trust policy.
    ///
    /// This is the explicit entrypoint for profiles whose trust anchor is
    /// supplied out of band, such as a Web profile with a pinned root.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the store, protected identity, or protected MLS
    /// storage cannot be opened.
    pub fn open_existing_with_trust_policy<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
        credential_trust_policy: CredentialTrustPolicy,
    ) -> Result<Self, CoreError> {
        let store = Store::open(database_path)?;
        let ciphertext = store
            .load_protected_identity()?
            .ok_or(CoreError::MissingIdentity)?;
        let identity = DeviceIdentity::load_protected(protector, &ciphertext)?;
        Self::finish_open(store, identity, protector, credential_trust_policy)
    }

    /// Opens a profile using the native operating-system trust store.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the store, protected identity, or protected MLS
    /// storage cannot be opened.
    pub fn open_existing<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
    ) -> Result<Self, CoreError> {
        Self::open_existing_with_trust_policy(
            database_path,
            protector,
            CredentialTrustPolicy::native_system(),
        )
    }

    fn finish_open<P: PrivateKeyProtector>(
        mut store: Store,
        identity: DeviceIdentity,
        protector: &P,
        credential_trust_policy: CredentialTrustPolicy,
    ) -> Result<Self, CoreError> {
        store.with_connection_mut(|connection| {
            migrate_protected_sqlite(connection).map_err(|_| CoreError::MlsStorageMigration)
        })?;
        let mls_storage_key = load_or_create_mls_storage_key(&mut store, protector)?;
        Ok(Self {
            store,
            identity,
            mls_storage_key,
            credential_trust_policy,
        })
    }
    /// Returns this profile's immutable credential trust policy.
    pub fn credential_trust_policy(&self) -> &CredentialTrustPolicy {
        &self.credential_trust_policy
    }

    fn ensure_credential_trust_policy(
        &self,
        credential: &DeviceCredentialInput,
    ) -> Result<(), CoreError> {
        if credential
            .trust_policy()
            .same_policy(&self.credential_trust_policy)
        {
            Ok(())
        } else {
            Err(CoreError::SpaceCredentialInvalid)
        }
    }

    /// Runs protected `OpenMLS` and application writes in one `SQLite` transaction.
    ///
    /// The key is scoped only for this callback. Returning an error rolls back
    /// both MLS provider state and event/outbox writes made through `transaction`.
    /// The caller remains responsible for credential trust, authorization, and
    /// durable handling of process-local MLS conflict evidence.
    ///
    /// # Errors
    ///
    /// Returns the action's error or a converted [`StoreError`] or [`CoreError`].
    pub fn with_mls_transaction<T, E>(
        &mut self,
        action: impl FnOnce(
            &DeviceIdentity,
            &ProtectedSqliteProvider<'_>,
            &Transaction<'_>,
        ) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<StoreError> + From<CoreError>,
    {
        self.store.with_transaction(|transaction| {
            let provider = ProtectedSqliteProvider::new(transaction);
            with_mls_storage_key(&self.mls_storage_key[..], || {
                action(&self.identity, &provider, transaction)
            })
            .map_err(CoreError::from)
            .map_err(E::from)?
        })
    }

    /// Publishes fresh one-time `KeyPackage`s until the requested unexpired
    /// inventory target is met.
    ///
    /// `OpenMLS` private bundles and their app-visible lifecycle records are
    /// committed atomically. Existing packages are never re-published; each
    /// returned wire package is a distinct MLS object.
    ///
    /// `now` is Unix time in seconds and is explicit so callers can apply the
    /// same clock policy to their local inventory decisions.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::KeyPackageInventoryLimit`] for a target above the
    /// supported bound, or any credential, `OpenMLS`, or storage error.
    pub fn replenish_key_packages(
        &mut self,
        credential: &DeviceCredentialInput,
        target_available: usize,
        now: u64,
    ) -> Result<Vec<Vec<u8>>, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        if target_available > MAX_LOCAL_KEY_PACKAGE_INVENTORY {
            return Err(CoreError::KeyPackageInventoryLimit);
        }
        let available = self.store.available_key_package_count(now)?;
        let mut generated = Vec::with_capacity(target_available.saturating_sub(available));
        for _ in available..target_available {
            generated.push(self.publish_key_package(credential, now)?);
        }
        Ok(generated)
    }
    /// Publishes one fresh, tracked one-time X.509 `KeyPackage`.
    ///
    /// The package and its private bundle are committed atomically. Unlike
    /// [`Client::replenish_key_packages`], this always publishes a new package
    /// even when an existing local inventory is already full.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential is invalid, the package is already
    /// expired at issuance, or MLS/storage rejects publication.
    pub fn publish_key_package(
        &mut self,
        credential: &DeviceCredentialInput,
        now: u64,
    ) -> Result<Vec<u8>, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.with_mls_transaction(|identity, provider, transaction| {
            let message = GroupState::publish_key_package(provider, identity, credential)?;
            let wire = message.as_bytes().to_vec();
            let (reference, expires_at) =
                lattice_mls::api::key_package_lifecycle_metadata(provider, &wire)?;
            if expires_at <= now {
                return Err(CoreError::KeyPackageExpiredAtIssuance);
            }
            Store::record_key_package_in_transaction(transaction, &reference, expires_at)?;
            Ok::<_, CoreError>(wire)
        })
    }
    /// Discards a locally published package that can no longer be delivered.
    ///
    /// This removes its private bundle and marks the inventory record lost in
    /// one transaction. Subsequent replenishment can immediately issue a
    /// distinct package.
    ///
    /// # Errors
    ///
    /// Returns an error if the package is malformed, the MLS provider fails, or
    /// durable storage rejects the transition.
    pub fn discard_key_package(&mut self, package_wire: &[u8]) -> Result<bool, CoreError> {
        self.with_mls_transaction(|_, provider, transaction| {
            let (reference, _) =
                lattice_mls::api::key_package_lifecycle_metadata(provider, package_wire)?;
            if !Store::lose_key_package_in_transaction(transaction, &reference)? {
                return Ok(false);
            }
            let deleted_reference =
                lattice_mls::api::delete_key_package_bundle(provider, package_wire)?;
            if deleted_reference != reference {
                return Err(CoreError::Mls(lattice_mls::api::MlsError::OpenMlsFailure));
            }
            Ok(true)
        })
    }
    fn ensure_space_generation_mutable(
        &self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
    ) -> Result<(), CoreError> {
        if self
            .store
            .load_space_membership_conflict(space_id, group_reference)?
            .is_some()
        {
            return Err(CoreError::SpaceMembershipConflicted);
        }
        Ok(())
    }

    /// Creates a one-member MLS generation and signed Genesis event atomically.
    ///
    /// The group, exact signed event bytes, and AEAD-protected initial policy
    /// snapshot commit in one `SQLite` transaction. The returned reducer is a
    /// process-local view; [`Client::restore_space`] rebuilds the Genesis state.
    ///
    /// # Errors
    ///
    /// Returns an error for randomness, channel policy validation, event
    /// creation, `OpenMLS`, or storage failure. Failure rolls back all writes.
    pub fn create_space(
        &mut self,
        credential: &lattice_mls::api::DeviceCredentialInput,
        channels: Vec<InitialChannel>,
    ) -> Result<CreatedSpace, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        let creator = self.identity.fingerprint();
        let (space_id, plaintext) = prepare_space_genesis(&creator, channels)?;
        let (genesis_event, reducer, group_id, group_reference) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                create_space_in_transaction(
                    identity,
                    provider,
                    transaction,
                    credential,
                    space_id,
                    plaintext,
                    None,
                )
            })?;
        Ok(CreatedSpace {
            space_id,
            group_id,
            group_reference,
            genesis_event,
            reducer,
        })
    }

    /// Creates a fresh one-member MLS generation from an authorized prior policy.
    ///
    /// The new root keeps the Space ID, cites the prior group and root, preserves
    /// recovery-schema channel descriptors, drops custom roles, and resets
    /// membership to the recovery administrator.
    /// The new group, signed recovery Genesis, and protected local snapshot are
    /// committed atomically. Existing generations remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the prior reducer has no policy, the local
    /// identity lacks recovery permissions, credential validation fails, or
    /// event, MLS, randomness, or storage operations fail. Failure rolls back
    /// all new-generation writes.
    pub fn create_space_recovery_generation(
        &mut self,
        prior: &CreatedSpace,
        credential: &lattice_mls::api::DeviceCredentialInput,
    ) -> Result<CreatedSpace, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        let creator = self.identity.fingerprint();
        let (space_id, plaintext) = prepare_space_recovery_genesis(&prior.reducer, &creator)?;
        let prior_reducer = &prior.reducer;
        let (genesis_event, reducer, group_id, group_reference) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                create_space_in_transaction(
                    identity,
                    provider,
                    transaction,
                    credential,
                    space_id,
                    plaintext,
                    Some(prior_reducer),
                )
            })?;
        Ok(CreatedSpace {
            space_id,
            group_id,
            group_reference,
            genesis_event,
            reducer,
        })
    }

    /// Restores a local generation and creates an authorized one-member recovery root.
    ///
    /// The X.509 vector must match this device's signing identity and pass the
    /// production trust policy attached to this Client. Existing members do
    /// not automatically rejoin.
    ///
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for an invalid local credential; prior
    /// snapshot, authorization, MLS, randomness, and storage errors propagate.
    pub fn recover_space_generation_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
    ) -> Result<CreatedSpace, CoreError> {
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let prior = self.restore_space(space_id, group_reference)?;
        self.create_space_recovery_generation(&prior, &credential)
    }
    /// Creates a local candidate Space from an RFC 9420 credential vector under
    /// this Client's trust policy.
    ///
    /// The credential content is leaf-first TLS certificate-vector bytes. It is
    /// validated against this client's signing identity and configured trust
    /// policy before the atomic Space-creation transaction is entered.
    ///
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` when the vector is malformed, untrusted,
    /// or does not match this device's signing identity. Other failures from
    /// Genesis construction, `OpenMLS`, or the atomic storage transaction are
    /// propagated; failed creation rolls back all writes.
    pub fn create_space_from_x509_credential(
        &mut self,
        credential_content: Vec<u8>,
        channels: Vec<InitialChannel>,
    ) -> Result<CreatedSpace, CoreError> {
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        self.create_space(&credential, channels)
    }

    /// Mutes or unmutes one stable identity or role target on this device only.
    ///
    /// Preferences are encrypted with the local MLS storage key and never
    /// synced. At most [`MAX_LOCAL_MUTED_MENTION_TARGETS`] targets are retained.
    ///
    /// # Errors
    ///
    /// Returns an error if the protected settings record or `SQLite` write fails,
    /// or the local mute-target bound is exceeded.
    pub fn set_mention_muted(
        &mut self,
        target: space::MentionTarget,
        muted: bool,
    ) -> Result<(), CoreError> {
        let mut targets = self.load_local_mention_mutes()?;
        if muted && !targets.contains(&target) && targets.len() >= MAX_LOCAL_MUTED_MENTION_TARGETS {
            return Err(CoreError::InvalidLocalMentionPreferences);
        }
        if muted {
            targets.insert(target);
        } else {
            targets.remove(&target);
        }
        let plaintext = encode_local_mention_mutes(&targets)?;
        let encrypted = with_mls_storage_key(&self.mls_storage_key[..], || {
            lattice_mls::protect_local_record(b"lattice-local-mention-mutes-v1\0", &plaintext)
        })??;
        self.store.save_local_mention_preferences(&encrypted)?;
        Ok(())
    }

    /// Decides whether locally resolved mention targets may notify this device.
    ///
    /// The caller supplies only targets resolved to the local device under the
    /// event's chosen policy context. This returns false for no matching target
    /// or when every matching target is muted; it never creates a notification.
    ///
    /// # Errors
    ///
    /// Returns an error if the target list is oversized, or the encrypted
    /// local preference record is malformed or cannot be read/decrypted.
    pub fn should_notify_for_mentions(
        &self,
        locally_resolved_mentions: &[space::MentionTarget],
    ) -> Result<bool, CoreError> {
        if locally_resolved_mentions.len() > space::MAX_MESSAGE_MENTIONS {
            return Err(CoreError::SpaceMessageRejected(
                space::EventAuthorization::Rejected(space::RejectReason::LimitExceeded),
            ));
        }
        if locally_resolved_mentions.is_empty() {
            return Ok(false);
        }
        let muted = self.load_local_mention_mutes()?;
        Ok(locally_resolved_mentions
            .iter()
            .any(|target| !muted.contains(target)))
    }

    fn load_local_mention_mutes(
        &self,
    ) -> Result<std::collections::BTreeSet<space::MentionTarget>, CoreError> {
        let Some(encrypted) = self.store.load_local_mention_preferences()? else {
            return Ok(std::collections::BTreeSet::new());
        };
        let plaintext = with_mls_storage_key(&self.mls_storage_key[..], || {
            lattice_mls::unprotect_local_record(b"lattice-local-mention-mutes-v1\0", &encrypted)
        })??;
        decode_local_mention_mutes(&plaintext)
    }

    /// Encrypts, authorizes, and atomically queues one local text message.
    ///
    /// The exact signed event, outbox envelope, and MLS sender state are
    /// committed in one transaction. This performs no network I/O; the returned
    /// receipt means `queued`, not forwarded or delivered.
    ///
    /// `created` must be the current local candidate generation and is updated
    /// only after the transaction commits. `channel_id` must name an active
    /// text or announcement channel in that reducer.
    ///
    /// # Errors
    ///
    /// Returns `SpaceGenesisRejected` for an unavailable policy, `SpaceMessageRejected`
    /// when the active policy denies the message, `SpaceParentEventMissing` if
    /// an accepted policy head is absent from storage, or the underlying MLS,
    /// protocol, signing, storage, or outbox error. A failed operation leaves
    /// both the event and MLS sender state unchanged.
    pub fn queue_text_message(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        channel_id: space::EntityId,
        content: &str,
    ) -> Result<QueuedMessage, CoreError> {
        self.queue_text_message_with_mentions(created, credential, channel_id, content, &[])
    }

    /// Queues a text message with stable encrypted identity/role references.
    ///
    /// Mention targets must be sorted and unique. Role references must exist
    /// in the active policy; a role mention requires the existing broad-mention
    /// permission. Identity references are full device fingerprints.
    ///
    /// # Errors
    ///
    /// Returns the queue errors from [`Client::queue_text_message`], plus
    /// `SpaceMessageRejected` for invalid, excessive, or unknown mentions.
    pub fn queue_text_message_with_mentions(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        channel_id: space::EntityId,
        content: &str,
        mentions: &[space::MentionTarget],
    ) -> Result<QueuedMessage, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (parents, lamport) = resolve_policy_parents(&self.store, policy)?;
        let plaintext = encode_text_message_with_mentions(content, mentions)?;
        let message = LocalApplicationEvent {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
            cached_text: Some((None, content)),
            event_kind: EventKind::Message,
        };
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (event_id, staged_reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                queue_application_event_in_transaction(
                    identity,
                    provider,
                    transaction,
                    &credential_trust_policy,
                    message,
                )
            })?;
        created.reducer = staged_reducer;
        Ok(QueuedMessage { event_id })
    }
    /// Queues a reply whose immutable thread root is an earlier message.
    ///
    /// The root is included as a causal parent and Core revalidates its
    /// channel, Space generation, membership, and thread permission.
    /// # Errors
    ///
    /// Returns an error when the credential, thread root, channel, policy, MLS,
    /// signing, or storage operation is invalid or fails.
    pub fn queue_text_message_reply(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        channel_id: space::EntityId,
        thread_root: [u8; 32],
        content: &str,
    ) -> Result<QueuedMessage, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (mut parents, lamport) =
            resolve_edit_parents(&self.store, policy, channel_id, thread_root)?;
        parents.sort_unstable_by_key(|parent| *parent.as_bytes());
        parents.dedup_by_key(|parent| *parent.as_bytes());
        let plaintext = encode_text_reply(thread_root, content)?;
        let message = LocalApplicationEvent {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
            cached_text: Some((None, content)),
            event_kind: EventKind::Message,
        };
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (event_id, staged_reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                queue_application_event_in_transaction(
                    identity,
                    provider,
                    transaction,
                    &credential_trust_policy,
                    message,
                )
            })?;
        created.reducer = staged_reducer;
        Ok(QueuedMessage { event_id })
    }
    /// Queues an authorized text edit of an immutable message event.
    ///
    /// The edit is a separately signed and encrypted event referencing the
    /// original message. For a reopened local Space, its authenticated encrypted
    /// cache projection is restored before edit authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is not an authorized ancestor, the current
    /// MLS roster does not match the accepted policy, the payload is invalid,
    /// or storage/MLS encryption fails.
    pub fn queue_text_message_edit(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        channel_id: space::EntityId,
        target: [u8; 32],
        content: &str,
    ) -> Result<QueuedMessage, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        self.restore_cached_local_message_projection(created, channel_id, target)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (mut parents, lamport) = resolve_edit_parents(&self.store, policy, channel_id, target)?;
        parents.sort_unstable_by_key(|parent| *parent.as_bytes());
        parents.dedup_by_key(|parent| *parent.as_bytes());
        let plaintext = encode_text_edit(target, content)?;
        let message = LocalApplicationEvent {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
            cached_text: Some((Some(target), content)),
            event_kind: EventKind::Edit,
        };
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (event_id, staged_reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                queue_application_event_in_transaction(
                    identity,
                    provider,
                    transaction,
                    &credential_trust_policy,
                    message,
                )
            })?;
        created.reducer = staged_reducer;
        Ok(QueuedMessage { event_id })
    }
    /// Queues an authenticated tombstone for a locally authored text message.
    ///
    /// The immutable message event remains in the event log. Honoring history
    /// projections hide the content; this does not recall copies already read.
    /// # Errors
    ///
    /// Returns an error when the target is not a locally authored authorized
    /// message, cached history is invalid, or MLS/signing/storage fails.
    pub fn queue_text_message_tombstone(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        channel_id: space::EntityId,
        target: [u8; 32],
    ) -> Result<QueuedMessage, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        self.restore_cached_local_message_projection(created, channel_id, target)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (mut parents, lamport) = resolve_edit_parents(&self.store, policy, channel_id, target)?;
        parents.sort_unstable_by_key(|parent| *parent.as_bytes());
        parents.dedup_by_key(|parent| *parent.as_bytes());
        let plaintext = encode_text_tombstone(target)?;
        let message = LocalApplicationEvent {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
            cached_text: None,
            event_kind: EventKind::Tombstone,
        };
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (event_id, staged_reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                queue_application_event_in_transaction(
                    identity,
                    provider,
                    transaction,
                    &credential_trust_policy,
                    message,
                )
            })?;
        created.reducer = staged_reducer;
        Ok(QueuedMessage { event_id })
    }
    /// Queues one tagged reaction add or an observed-tag removal.
    ///
    /// For an add, `tag` must be `None`; its returned event ID is the immutable
    /// tag. For a removal, `tag` names one earlier reaction-add event authored
    /// by this device.
    /// # Errors
    ///
    /// Returns an error if the target, reaction token, causal tag, policy,
    /// current MLS membership, signing, or storage state is invalid.
    pub fn queue_text_message_reaction(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        reaction: &TextMessageReaction,
    ) -> Result<QueuedMessage, CoreError> {
        let plaintext =
            encode_text_reaction(reaction.target, &reaction.token, reaction.add, reaction.tag)?;
        self.queue_text_message_update(
            created,
            credential,
            TextMessageUpdate {
                channel_id: reaction.channel_id,
                target: reaction.target,
                causal_tag: reaction.tag,
                event_kind: EventKind::Reaction,
                plaintext,
            },
        )
    }

    /// Queues one pin add or an observed pin-tag removal.
    ///
    /// For an add, `tag` must be `None`; its returned event ID is the pin tag.
    /// A removal names the immutable ID of an earlier pin-add event.
    /// # Errors
    ///
    /// Returns an error if the target, causal tag, policy, current MLS
    /// membership, signing, or storage state is invalid.
    pub fn queue_text_message_pin(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        pin: TextMessagePin,
    ) -> Result<QueuedMessage, CoreError> {
        let plaintext = encode_text_pin(pin.target, pin.add, pin.tag)?;
        self.queue_text_message_update(
            created,
            credential,
            TextMessageUpdate {
                channel_id: pin.channel_id,
                target: pin.target,
                causal_tag: pin.tag,
                event_kind: EventKind::Pin,
                plaintext,
            },
        )
    }

    fn queue_text_message_update(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        update: TextMessageUpdate,
    ) -> Result<QueuedMessage, CoreError> {
        let TextMessageUpdate {
            channel_id,
            target,
            causal_tag,
            event_kind,
            plaintext,
        } = update;
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        self.restore_cached_local_message_projection(created, channel_id, target)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (mut parents, mut lamport) =
            resolve_edit_parents(&self.store, policy, channel_id, target)?;
        if let Some(tag) = causal_tag {
            let stored = self
                .store
                .load_event(&tag)?
                .ok_or(CoreError::SpaceParentEventMissing)?;
            let event = VerifiedSignatureOnlyEvent::decode_verify(&stored.canonical_bytes)?;
            if event.event_id().as_bytes() != &tag
                || event.space_id() != &policy.space_id
                || event.mls_group_reference() != &policy.group_reference
                || event.channel_id() != Some(&channel_id)
                || event.kind() != event_kind
            {
                return Err(CoreError::SpaceParentEventMissing);
            }
            parents.push(lattice_protocol::EventId::from_bytes(tag));
            lamport = lamport
                .max(event.lamport())
                .checked_add(1)
                .ok_or(CoreError::SpaceLamportExhausted)?;
        }
        parents.sort_unstable_by_key(|parent| *parent.as_bytes());
        parents.dedup_by_key(|parent| *parent.as_bytes());
        let message = LocalApplicationEvent {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
            cached_text: None,
            event_kind,
        };
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (event_id, staged_reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                queue_application_event_in_transaction(
                    identity,
                    provider,
                    transaction,
                    &credential_trust_policy,
                    message,
                )
            })?;
        created.reducer = staged_reducer;
        Ok(QueuedMessage { event_id })
    }

    /// Restores the local Genesis policy, validates an RFC 9420 X.509 credential,
    /// then encrypts and atomically queues a text message without network I/O.
    ///
    /// Restores the local Space and replays validated membership transitions
    /// before authorizing the message against the current local policy.
    ///
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for malformed, mismatched, or untrusted
    /// credential bytes, the same policy and transaction errors as
    /// [`Client::queue_text_message`], or a restore error if the Space has
    /// changed generation or lacks a valid local Genesis snapshot.
    pub fn queue_text_message_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        channel_id: space::EntityId,
        content: &str,
    ) -> Result<QueuedMessage, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message(&mut created, &credential, channel_id, content)
    }
    /// Restores the selected Space and queues an authenticated author tombstone
    /// using a validated RFC 9420 X.509 credential.
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for invalid credential bytes; restoration
    /// and tombstone queue errors are propagated.
    pub fn queue_text_message_tombstone_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        channel_id: space::EntityId,
        target: [u8; 32],
    ) -> Result<QueuedMessage, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message_tombstone(&mut created, &credential, channel_id, target)
    }
    /// X.509 credential wrapper for [`Client::queue_text_message_reply`].
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for invalid credential bytes; restoration
    /// and reply queue errors are propagated.
    pub fn queue_text_message_reply_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        channel_id: space::EntityId,
        thread_root: [u8; 32],
        content: &str,
    ) -> Result<QueuedMessage, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message_reply(&mut created, &credential, channel_id, thread_root, content)
    }

    /// X.509 credential wrapper for [`Client::queue_text_message_reaction`].
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for malformed, mismatched, or untrusted
    /// credential bytes, or propagates Space restoration and reaction queue errors.
    pub fn queue_text_message_reaction_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        reaction: &TextMessageReaction,
    ) -> Result<QueuedMessage, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message_reaction(&mut created, &credential, reaction)
    }

    /// X.509 credential wrapper for [`Client::queue_text_message_pin`].
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for malformed, mismatched, or untrusted
    /// credential bytes, or propagates Space restoration and pin queue errors.
    pub fn queue_text_message_pin_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        pin: TextMessagePin,
    ) -> Result<QueuedMessage, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message_pin(&mut created, &credential, pin)
    }

    /// Encrypts, policy-checks, and atomically queues one attachment manifest.
    ///
    /// Attachment bytes remain in caller-owned staging storage; this signed
    /// event contains only bounded metadata and integrity digests. The receipt
    /// means `queued`, not transferred or delivered.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest is invalid, the Space policy denies
    /// attachments, the selected channel is unavailable, or MLS/signing/storage
    /// operations fail. A rejected manifest leaves MLS sender state and outbox
    /// unchanged.
    pub fn queue_file_manifest(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        channel_id: space::EntityId,
        manifest: &AttachmentManifest,
    ) -> Result<QueuedFileManifest, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        manifest.validate()?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (parents, lamport) = resolve_policy_parents(&self.store, policy)?;
        let plaintext = encode_file_manifest(manifest)?;
        let message = LocalApplicationEvent {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
            cached_text: None,
            event_kind: EventKind::FileManifest,
        };
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (event_id, staged_reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                queue_application_event_in_transaction(
                    identity,
                    provider,
                    transaction,
                    &credential_trust_policy,
                    message,
                )
            })?;
        created.reducer = staged_reducer;
        Ok(QueuedFileManifest { event_id })
    }

    /// Restores a local Space and atomically queues an attachment manifest
    /// using this device's validated RFC 9420 X.509 credential.
    ///
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for malformed or untrusted credential
    /// bytes; otherwise returns the same manifest, policy, MLS, signing, and
    /// storage errors as [`Client::queue_file_manifest`], or a restore error
    /// when no valid local Genesis snapshot is available.
    pub fn queue_file_manifest_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        channel_id: space::EntityId,
        manifest: &AttachmentManifest,
    ) -> Result<QueuedFileManifest, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_file_manifest(&mut created, &credential, channel_id, manifest)
    }

    /// Restores a local Space, validates its X.509 device credential, and
    /// atomically queues an authorized edit of an authored message.
    ///
    /// The encrypted local history cache is updated with the edited body in
    /// the same transaction as the immutable Edit event and outbox entry.
    ///
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for malformed or untrusted credential
    /// bytes, the same policy and transaction errors as
    /// [`Client::queue_text_message_edit`], or a restore error if the local
    /// Space generation cannot be restored.
    pub fn queue_text_message_edit_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
        channel_id: space::EntityId,
        target: [u8; 32],
        content: &str,
    ) -> Result<QueuedMessage, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message_edit(&mut created, &credential, channel_id, target, content)
    }
    /// Accepts one signature-verified event for an already restored generation.
    ///
    /// Missing signed parents are retained in the bounded pending store without
    /// advancing MLS state. Accepted events update the MLS state, reducer, exact
    /// signed event row, and any message-text cache projection atomically. Signed
    /// ciphertext older than the local MLS epoch is retained only as graph ancestry
    /// and reported as `CheckpointExcluded`; its plaintext is never projected.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched generation, invalid signature or MLS
    /// binding, rejected Space policy, event equivocation, or MLS/storage failure.
    pub fn accept_synced_application_event(
        &mut self,
        created: &mut CreatedSpace,
        canonical_bytes: &[u8],
    ) -> Result<SyncedApplicationOutcome, CoreError> {
        let event = VerifiedSignatureOnlyEvent::decode_verify(canonical_bytes)?;
        self.accept_verified_synced_application_event(created, canonical_bytes, event)
    }

    /// Restores the local generation named by a verified event and ingests it.
    ///
    /// This is the transport-facing entry point for an opaque signed event.
    /// The event is signature-verified before its identifiers select a local
    /// generation; normal MLS binding, dependency, and authorization checks
    /// determine whether it is accepted. Ciphertext older than the local MLS epoch
    /// is retained only as graph ancestry and reported as `CheckpointExcluded`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or untrusted event bytes, an unavailable
    /// local generation, or failed MLS, authorization, or storage validation.
    pub fn accept_synced_application_event_for_local_generation(
        &mut self,
        canonical_bytes: &[u8],
    ) -> Result<SyncedApplicationOutcome, CoreError> {
        let event = VerifiedSignatureOnlyEvent::decode_verify(canonical_bytes)?;
        let space_id = *event.space_id();
        let group_reference = *event.mls_group_reference();
        let mut created = self.restore_space(&space_id, &group_reference)?;
        self.accept_verified_synced_application_event(&mut created, canonical_bytes, event)
    }

    fn missing_synced_event_dependencies(
        &self,
        created: &CreatedSpace,
        event: &VerifiedSignatureOnlyEvent,
    ) -> Result<Vec<[u8; 32]>, CoreError> {
        let mut missing = Vec::new();
        for parent in event.parents() {
            let parent_id = *parent.as_bytes();
            match self.store.load_event(&parent_id)? {
                None => missing.push(parent_id),
                Some(record) => {
                    let parent_event =
                        VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
                    if parent_event.event_id().as_bytes() != &parent_id
                        || parent_event.space_id() != &created.space_id
                        || parent_event.mls_group_reference() != &created.group_reference
                    {
                        return Err(CoreError::SpaceParentEventMissing);
                    }
                }
            }
        }
        Ok(missing)
    }

    fn accept_verified_synced_application_event(
        &mut self,
        created: &mut CreatedSpace,
        canonical_bytes: &[u8],
        event: VerifiedSignatureOnlyEvent,
    ) -> Result<SyncedApplicationOutcome, CoreError> {
        if event.space_id() != &created.space_id
            || event.mls_group_reference() != &created.group_reference
        {
            return Err(CoreError::MlsEventBindingFailed);
        }
        if event.kind() == EventKind::RelayMailboxControl {
            return self.accept_verified_relay_mailbox_control(created, canonical_bytes, event);
        }
        let event_id = *event.event_id().as_bytes();
        if let Some(existing) = self.store.load_event(&event_id)? {
            if existing.canonical_bytes != canonical_bytes {
                return Err(CoreError::Storage(StoreError::EventIdConflict));
            }
            self.store.resolve_pending(event_id)?;
            self.store.resolve_dependency(event_id)?;
            return Ok(SyncedApplicationOutcome::Duplicate { event_id });
        }
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let missing_dependencies = self.missing_synced_event_dependencies(created, &event)?;
        if !missing_dependencies.is_empty() {
            self.store
                .store_pending(event_id, canonical_bytes, &missing_dependencies)?;
            return Ok(SyncedApplicationOutcome::Pending {
                event_id,
                missing_dependencies,
            });
        }

        let group_id = created.group_id.clone();
        let space_id = created.space_id;
        let group_reference = created.group_reference;
        let reducer = created.reducer.clone();
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (staged_reducer, checkpoint_excluded) =
            self.with_mls_transaction(move |_identity, provider, transaction| {
                let mut group = GroupState::load_with_trust_policy(
                    provider,
                    &group_id,
                    &credential_trust_policy,
                )?;
                if group.group_reference() != group_reference {
                    return Err(CoreError::MlsEventBindingFailed);
                }
                if event.mls_epoch() < group.epoch() {
                    if !matches!(
                        event.kind(),
                        EventKind::Message
                            | EventKind::Edit
                            | EventKind::Tombstone
                            | EventKind::Reaction
                            | EventKind::Pin
                            | EventKind::FileManifest
                            | EventKind::VoiceSignal
                    ) {
                        return Err(CoreError::MlsEventBindingFailed);
                    }
                    let active_channel_author = event.channel_id().is_some_and(|channel_id| {
                        reducer
                            .effective_channel_permissions(event.author_fingerprint(), channel_id)
                            .is_some()
                    });
                    if !active_channel_author {
                        return Err(CoreError::SpaceMessageRejected(
                            space::EventAuthorization::Rejected(space::RejectReason::Unauthorized),
                        ));
                    }
                    let mut staged_reducer = reducer.clone();
                    staged_reducer
                        .observe_graph_event(&event)
                        .map_err(CoreError::SpaceGraphEventRejected)?;
                    store_received_event(transaction, &event)?;
                    Store::resolve_pending_in_transaction(transaction, event_id)?;
                    return Ok((staged_reducer, true));
                }
                let IncomingResult::Application(application) =
                    group.process_incoming(provider, event.protected_body())?
                else {
                    return Err(CoreError::MlsEventBindingFailed);
                };
                let bound = bind_mls_application(event, application)?;
                let (staged_reducer, authorization) =
                    authorize_and_store_application_event(transaction, &reducer, &bound)?;
                if !matches!(authorization, space::EventAuthorization::Authorized { .. }) {
                    return Err(CoreError::SpaceMessageRejected(authorization));
                }
                persist_received_text_projection(transaction, &bound, space_id, group_reference)?;
                Store::resolve_pending_in_transaction(transaction, event_id)?;
                Ok((staged_reducer, false))
            })?;
        created.reducer = staged_reducer;
        self.store.resolve_dependency(event_id)?;
        if checkpoint_excluded {
            return Ok(SyncedApplicationOutcome::CheckpointExcluded { event_id });
        }
        Ok(SyncedApplicationOutcome::Accepted { event_id })
    }

    fn accept_verified_relay_mailbox_control(
        &mut self,
        created: &mut CreatedSpace,
        canonical_bytes: &[u8],
        event: VerifiedSignatureOnlyEvent,
    ) -> Result<SyncedApplicationOutcome, CoreError> {
        if event.kind() != EventKind::RelayMailboxControl
            || event.channel_id().is_some()
            || event.space_id() != &created.space_id
            || event.mls_group_reference() != &created.group_reference
        {
            return Err(CoreError::MlsEventBindingFailed);
        }
        let event_id = *event.event_id().as_bytes();
        if let Some(existing) = self.store.load_event(&event_id)? {
            if existing.canonical_bytes != canonical_bytes {
                return Err(CoreError::Storage(StoreError::EventIdConflict));
            }
            self.store.resolve_pending(event_id)?;
            self.store.resolve_dependency(event_id)?;
            return Ok(SyncedApplicationOutcome::Duplicate { event_id });
        }
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let missing_dependencies = self.missing_synced_event_dependencies(created, &event)?;
        if !missing_dependencies.is_empty() {
            self.store
                .store_pending(event_id, canonical_bytes, &missing_dependencies)?;
            return Ok(SyncedApplicationOutcome::Pending {
                event_id,
                missing_dependencies,
            });
        }

        let group_id = created.group_id.clone();
        let space_id = created.space_id;
        let group_reference = created.group_reference;
        let reducer = created.reducer.clone();
        let credential_trust_policy = self.credential_trust_policy.clone();
        self.with_mls_transaction(move |_identity, provider, transaction| {
            let mut group =
                GroupState::load_with_trust_policy(provider, &group_id, &credential_trust_policy)?;
            if group.group_reference() != group_reference || event.mls_epoch() != group.epoch() {
                return Err(CoreError::MlsEventBindingFailed);
            }
            let IncomingResult::Application(application) =
                group.process_incoming(provider, event.protected_body())?
            else {
                return Err(CoreError::MlsEventBindingFailed);
            };
            let bound = bind_mls_application(event, application)?;
            let mailbox = decode_relay_mailbox_control(bound.plaintext())?;
            reducer
                .authorize_relay_mailbox_control(bound.event())
                .map_err(CoreError::SpaceControlRejected)?;

            let encrypted = Store::load_space_relay_mailbox_in_transaction(
                transaction,
                &space_id,
                &group_reference,
            )?;
            if let Some(encrypted) = encrypted {
                if decode_protected_relay_mailbox(&space_id, &group_reference, &encrypted)?
                    != mailbox
                {
                    return Err(CoreError::SpaceRelayMailboxConflict);
                }
            } else {
                let context = relay_mailbox_context(&space_id, &group_reference);
                let protected = lattice_mls::protect_local_record(&context, mailbox.as_bytes())?;
                if !Store::insert_space_relay_mailbox_in_transaction(
                    transaction,
                    &space_id,
                    &group_reference,
                    &protected,
                )? {
                    let persisted = Store::load_space_relay_mailbox_in_transaction(
                        transaction,
                        &space_id,
                        &group_reference,
                    )?
                    .ok_or(CoreError::SpaceRelayMailboxInvalid)?;
                    if decode_protected_relay_mailbox(&space_id, &group_reference, &persisted)?
                        != mailbox
                    {
                        return Err(CoreError::SpaceRelayMailboxConflict);
                    }
                }
            }
            store_received_event(transaction, bound.event())?;
            Store::resolve_pending_in_transaction(transaction, event_id)?;
            Ok(())
        })?;
        self.store.resolve_dependency(event_id)?;
        Ok(SyncedApplicationOutcome::Accepted { event_id })
    }

    /// Retries ready authenticated application events retained for this generation.
    ///
    /// Call after accepting a parent event. Returned outcomes include each
    /// pending event accepted or recognized as an exact duplicate; unresolved
    /// dependencies remain in the bounded pending store.
    ///
    /// # Errors
    ///
    /// Returns an error if a ready event fails signature, MLS, authorization, or
    /// storage validation.
    pub fn retry_ready_synced_application_events(
        &mut self,
        created: &mut CreatedSpace,
    ) -> Result<Vec<SyncedApplicationOutcome>, CoreError> {
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let mut outcomes = Vec::new();
        loop {
            let pending = self.store.list_pending()?;
            let mut made_progress = false;
            for item in pending {
                if !item.missing_dependencies.is_empty() {
                    continue;
                }
                let event = VerifiedSignatureOnlyEvent::decode_verify(&item.canonical_bytes)?;
                if event.space_id() != &created.space_id
                    || event.mls_group_reference() != &created.group_reference
                    || !matches!(
                        event.kind(),
                        EventKind::Message
                            | EventKind::Edit
                            | EventKind::Tombstone
                            | EventKind::Reaction
                            | EventKind::Pin
                            | EventKind::FileManifest
                            | EventKind::RelayMailboxControl
                    )
                {
                    continue;
                }
                let outcome =
                    self.accept_synced_application_event(created, &item.canonical_bytes)?;
                if matches!(
                    outcome,
                    SyncedApplicationOutcome::Accepted { .. }
                        | SyncedApplicationOutcome::Duplicate { .. }
                        | SyncedApplicationOutcome::CheckpointExcluded { .. }
                ) {
                    made_progress = true;
                }
                outcomes.push(outcome);
            }
            if !made_progress {
                break;
            }
        }
        Ok(outcomes)
    }

    /// Returns the newest bounded local text-message history for one channel.
    ///
    /// History combines locally authored and received messages from encrypted
    /// cache entries. Rows beyond the latest
    /// [`MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE`] are not included.
    ///
    /// # Errors
    ///
    /// Returns an error if the local Space generation cannot be restored,
    /// cached event metadata or authentication fails, or storage is unavailable.
    pub fn local_text_message_history(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        channel_id: &space::EntityId,
    ) -> Result<Vec<LocalTextMessageRecord>, CoreError> {
        self.restore_space(space_id, group_reference)?;
        let cached = self.store.list_cached_space_messages(
            space_id,
            group_reference,
            channel_id,
            MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE,
        )?;
        let mut event_bytes = Vec::with_capacity(cached.len());
        for message in &cached {
            let record = self
                .store
                .load_event(&message.event_id)?
                .ok_or(CoreError::LocalSpaceMessageCacheInvalid)?;
            event_bytes.push(record.canonical_bytes);
        }
        self.with_mls_transaction(move |_identity, _provider, _transaction| {
            let mut history = Vec::with_capacity(cached.len());
            for (message, event_bytes) in cached.into_iter().zip(event_bytes) {
                let event = VerifiedSignatureOnlyEvent::decode_verify(&event_bytes)?;
                if event.event_id().as_bytes() != &message.event_id
                    || event.space_id() != &message.space_id
                    || event.mls_group_reference() != &message.group_reference
                    || event.channel_id() != Some(&message.channel_id)
                    || event.kind() != EventKind::Message
                    || event.author_fingerprint() != &message.author_id
                    || event.author_sequence() != message.author_seq
                    || event.lamport() != message.lamport
                {
                    return Err(CoreError::LocalSpaceMessageCacheInvalid);
                }
                let cache_aad = local_text_message_context(
                    &message.space_id,
                    &message.group_reference,
                    &message.channel_id,
                    &message.event_id,
                );
                let plaintext =
                    lattice_mls::unprotect_local_record(&cache_aad, &message.encrypted_content)?;
                let source = decode_text_message(&plaintext)?;
                let content = space::rich_text::RichText::parse(&source)
                    .map_err(|_| CoreError::LocalSpaceMessageCacheInvalid)?
                    .render_plain_text()
                    .to_owned();
                history.push(LocalTextMessageRecord {
                    event_id: message.event_id,
                    channel_id: message.channel_id,
                    author_id: message.author_id,
                    author_sequence: message.author_seq,
                    lamport: message.lamport,
                    content,
                    outbox_state: message.outbox_state,
                });
            }
            Ok(history)
        })
    }

    /// Searches all locally retained authorized text messages for a channel.
    ///
    /// Matching is a Unicode lowercase substring search over locally decrypted
    /// cache contents. The store's row and encrypted-byte quotas bound scanning;
    /// at most [`MAX_LOCAL_TEXT_SEARCH_RESULTS`] newest matches are returned.
    /// Every returned row is rebound to its verified signed event. No network
    /// path is contacted.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized query, an unavailable local
    /// Space generation, corrupt cached metadata, failed content authentication,
    /// invalid event bytes, or storage failure.
    pub fn search_local_text_messages(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        channel_id: &space::EntityId,
        query: &str,
    ) -> Result<LocalTextMessageSearchResult, CoreError> {
        if query.is_empty() || query.len() > MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES {
            return Err(CoreError::InvalidLocalTextMessageSearch);
        }
        self.restore_space(space_id, group_reference)?;
        let cached =
            self.store
                .list_all_cached_space_messages(space_id, group_reference, channel_id)?;
        let scanned_messages = cached.len();
        let search = query.to_lowercase();
        let (matches, total_matches) =
            self.with_mls_transaction(move |_identity, _provider, _transaction| {
                let mut matches = VecDeque::with_capacity(MAX_LOCAL_TEXT_SEARCH_RESULTS);
                let mut total_matches = 0_usize;
                for message in cached {
                    if message.space_id != *space_id
                        || message.group_reference != *group_reference
                        || message.channel_id != *channel_id
                    {
                        return Err(CoreError::LocalSpaceMessageCacheInvalid);
                    }
                    let cache_aad = local_text_message_context(
                        &message.space_id,
                        &message.group_reference,
                        &message.channel_id,
                        &message.event_id,
                    );
                    let plaintext = lattice_mls::unprotect_local_record(
                        &cache_aad,
                        &message.encrypted_content,
                    )?;
                    let source = decode_text_message(&plaintext)?;
                    let content = space::rich_text::RichText::parse(&source)
                        .map_err(|_| CoreError::LocalSpaceMessageCacheInvalid)?
                        .render_plain_text()
                        .to_owned();
                    if !content.to_lowercase().contains(&search) {
                        continue;
                    }
                    total_matches = total_matches.saturating_add(1);
                    if matches.len() == MAX_LOCAL_TEXT_SEARCH_RESULTS {
                        matches.pop_front();
                    }
                    matches.push_back(LocalTextMessageRecord {
                        event_id: message.event_id,
                        channel_id: message.channel_id,
                        author_id: message.author_id,
                        author_sequence: message.author_seq,
                        lamport: message.lamport,
                        content,
                        outbox_state: message.outbox_state,
                    });
                }
                Ok((matches, total_matches))
            })?;
        let messages = matches.into_iter().collect::<Vec<_>>();
        for message in &messages {
            let record = self
                .store
                .load_event(&message.event_id)?
                .ok_or(CoreError::LocalSpaceMessageCacheInvalid)?;
            let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
            if event.event_id().as_bytes() != &message.event_id
                || event.space_id() != space_id
                || event.mls_group_reference() != group_reference
                || event.channel_id() != Some(channel_id)
                || event.kind() != EventKind::Message
                || event.author_fingerprint() != &message.author_id
                || event.author_sequence() != message.author_sequence
                || event.lamport() != message.lamport
            {
                return Err(CoreError::LocalSpaceMessageCacheInvalid);
            }
        }
        Ok(LocalTextMessageSearchResult {
            messages,
            total_matches,
            scanned_messages,
        })
    }

    fn restore_cached_local_message_projection(
        &mut self,
        created: &mut CreatedSpace,
        channel_id: space::EntityId,
        target: [u8; 32],
    ) -> Result<(), CoreError> {
        if created.reducer.has_projected_message(&target) {
            return Ok(());
        }
        let cached = self
            .store
            .list_cached_space_messages(
                &created.space_id,
                &created.group_reference,
                &channel_id,
                MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE,
            )?
            .into_iter()
            .find(|message| message.event_id == target)
            .ok_or(CoreError::SpaceParentEventMissing)?;
        let record = self
            .store
            .load_event(&target)?
            .ok_or(CoreError::LocalSpaceMessageCacheInvalid)?;
        let expected_author = self.identity.fingerprint();
        let expected_space_id = created.space_id;
        let expected_group_reference = created.group_reference;
        let (event, cached_plaintext) =
            self.with_mls_transaction(move |_identity, _provider, _transaction| {
                let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
                if event.event_id().as_bytes() != &target
                    || event.space_id() != &expected_space_id
                    || event.mls_group_reference() != &expected_group_reference
                    || event.channel_id() != Some(&channel_id)
                    || event.kind() != EventKind::Message
                    || event.author_fingerprint() != &expected_author
                    || cached.author_id != expected_author
                    || cached.space_id != expected_space_id
                    || cached.group_reference != expected_group_reference
                    || cached.channel_id != channel_id
                    || event.author_sequence() != cached.author_seq
                    || event.lamport() != cached.lamport
                {
                    return Err(CoreError::LocalSpaceMessageCacheInvalid);
                }
                let context = local_text_message_context(
                    &cached.space_id,
                    &cached.group_reference,
                    &cached.channel_id,
                    &cached.event_id,
                );
                let plaintext =
                    lattice_mls::unprotect_local_record(&context, &cached.encrypted_content)?;
                Ok((event, plaintext))
            })?;
        let content = decode_text_message(&cached_plaintext)?;
        let message_plaintext = encode_text_message(&content)?;
        let bound = MlsBoundEvent {
            event,
            plaintext: message_plaintext,
        };
        let mut staged_reducer = created.reducer.clone();
        let authorization = staged_reducer.authorize_application_event(&bound);
        if !matches!(authorization, space::EventAuthorization::Authorized { .. }) {
            return Err(CoreError::SpaceMessageRejected(authorization));
        }
        created.reducer = staged_reducer;
        Ok(())
    }

    /// Restores a locally created Space policy projection after process restart.
    ///
    /// The Genesis event, MLS group, and AEAD-protected initial policy payload are
    /// independently checked against the requested Space and MLS generation.
    /// Accepted local membership transitions are replayed from their exact
    /// signed events and AEAD-protected local proof records. Durable
    /// sibling-Commit conflicts are revalidated from their exact signed control
    /// events; Welcome-based checkpoints are revalidated and restored from their signed records.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot is missing, malformed, unauthenticated,
    /// or inconsistent with the protected MLS group and signed Genesis event.
    pub fn restore_space(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
    ) -> Result<CreatedSpace, CoreError> {
        self.restore_space_at_depth(space_id, group_reference, 0)
    }

    #[allow(clippy::too_many_lines)] // Restores one generation as a single validation flow.
    fn restore_space_at_depth(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        recovery_depth: usize,
    ) -> Result<CreatedSpace, CoreError> {
        if recovery_depth >= MAX_SPACE_RECOVERY_DEPTH {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
        let snapshot = self
            .store
            .load_space_genesis_snapshot(space_id, group_reference)?
            .ok_or(CoreError::SpaceGenesisSnapshotNotFound)?;
        let event_record = self
            .store
            .load_event(&snapshot.event_id)?
            .ok_or(CoreError::SpaceGenesisSnapshotNotFound)?;
        let event = VerifiedSignatureOnlyEvent::decode_verify(&event_record.canonical_bytes)?;
        if event.event_id().as_bytes() != &snapshot.event_id
            || event.space_id() != &snapshot.space_id
            || event.mls_group_reference() != &snapshot.group_reference
            || event.kind() != EventKind::Membership
            || event.channel_id().is_some()
            || !event.parents().is_empty()
            || event.mls_epoch() != 0
        {
            return Err(CoreError::SpaceGenesisRejected(
                space::RejectReason::InvalidGenesisContext,
            ));
        }
        if let Some(joined_snapshot) = self
            .store
            .load_space_welcome_bootstrap_snapshot(space_id, group_reference)?
        {
            return self.restore_joined_space(&snapshot, event, &joined_snapshot);
        }
        let recovery_context = space_genesis_context(
            &snapshot.space_id,
            &snapshot.group_reference,
            &snapshot.event_id,
        );
        let encrypted_recovery_state = snapshot.encrypted_state.clone();
        let recovery_context_for_auth = recovery_context.clone();
        let genesis_plaintext = self.with_mls_transaction(move |_, _, _| {
            let plaintext = lattice_mls::unprotect_local_record(
                &recovery_context_for_auth,
                &encrypted_recovery_state,
            )?;
            Ok::<_, CoreError>(plaintext)
        })?;
        let prior_group_reference = recovery_parent_group_reference(&genesis_plaintext)?;
        let prior_reducer = if let Some(prior_group_reference) = prior_group_reference {
            if prior_group_reference == snapshot.group_reference {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            Some(
                self.restore_space_at_depth(
                    &snapshot.space_id,
                    &prior_group_reference,
                    recovery_depth + 1,
                )?
                .reducer,
            )
        } else {
            None
        };
        let transition_snapshots = self
            .store
            .list_space_membership_transition_snapshots(space_id, group_reference)?;
        let mut transition_events = Vec::with_capacity(transition_snapshots.len());
        for transition_snapshot in transition_snapshots {
            if transition_snapshot.space_id != *space_id
                || transition_snapshot.group_reference != *group_reference
            {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            let control_event = self
                .store
                .load_event(&transition_snapshot.control_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            let transition_event = self
                .store
                .load_event(&transition_snapshot.transition_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            transition_events.push((
                transition_snapshot,
                control_event.canonical_bytes,
                transition_event.canonical_bytes,
            ));
        }
        let conflict_snapshot = self
            .store
            .load_space_membership_conflict(space_id, group_reference)?;
        let conflict_events = if let Some(conflict) = &conflict_snapshot {
            if conflict.space_id != *space_id || conflict.group_reference != *group_reference {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            let first = self
                .store
                .load_event(&conflict.first_control_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            let second = self
                .store
                .load_event(&conflict.second_control_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            Some((
                conflict.clone(),
                first.canonical_bytes,
                second.canonical_bytes,
            ))
        } else {
            None
        };
        let expected_transition_count = transition_events.len() as u64;
        let space_id = snapshot.space_id;
        let expected_group_reference = snapshot.group_reference;
        let group_id = snapshot.group_id;
        let group_id_for_load = group_id.clone();
        let encrypted_state = snapshot.encrypted_state;
        let context = recovery_context;
        let restored_event = event.clone();
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (group_reference, reducer) =
            self.with_mls_transaction(move |identity, provider, _transaction| {
                if event.author_fingerprint() != &identity.fingerprint() {
                    return Err(CoreError::SpaceGenesisRejected(
                        space::RejectReason::CreatorMismatch,
                    ));
                }
                let mut group = GroupState::load_with_trust_policy(
                    provider,
                    &group_id_for_load,
                    &credential_trust_policy,
                )?;
                let group_reference = group.group_reference();
                if group_reference != expected_group_reference {
                    return Err(CoreError::SpaceGenesisRejected(
                        space::RejectReason::WrongGeneration,
                    ));
                }
                let plaintext = lattice_mls::unprotect_local_record(&context, &encrypted_state)?;
                let bound = MlsBoundEvent { event, plaintext };
                let mut reducer = space::SpaceReducer::new();
                let recovery_authorization = prior_reducer
                    .as_ref()
                    .map(|prior| prior.authorize_recovery_genesis(&bound))
                    .transpose()
                    .map_err(CoreError::SpaceGenesisRejected)?;
                match reducer.apply(&bound, recovery_authorization.as_ref()) {
                    space::ApplyResult::Applied { revision: 0 } => {}
                    space::ApplyResult::Rejected(reason) => {
                        return Err(CoreError::SpaceGenesisRejected(reason));
                    }
                    _ => {
                        return Err(CoreError::SpaceGenesisRejected(
                            space::RejectReason::InvalidGenesisContext,
                        ));
                    }
                }
                replay_space_membership_transitions(&mut reducer, transition_events)?;
                validate_restored_membership_state(&group, &reducer, expected_transition_count)?;
                if let Some((conflict, first_bytes, second_bytes)) = conflict_events {
                    if group.epoch() != conflict.parent_epoch {
                        return Err(CoreError::SpaceMembershipSnapshotInvalid);
                    }
                    let first = VerifiedSignatureOnlyEvent::decode_verify(&first_bytes)?;
                    let second = VerifiedSignatureOnlyEvent::decode_verify(&second_bytes)?;
                    if first.event_id().as_bytes() != &conflict.first_control_event_id
                        || second.event_id().as_bytes() != &conflict.second_control_event_id
                        || [&first, &second].into_iter().any(|control| {
                            control.space_id() != &space_id
                                || control.mls_group_reference() != &expected_group_reference
                                || control.mls_epoch() != conflict.parent_epoch
                                || control.kind() != EventKind::MlsControl
                                || control.channel_id().is_some()
                        })
                    {
                        return Err(CoreError::SpaceMembershipSnapshotInvalid);
                    }
                    if !matches!(
                        group.process_incoming(provider, first.protected_body())?,
                        IncomingResult::StagedCommit { parent_epoch, .. }
                            if parent_epoch == conflict.parent_epoch
                    ) || !matches!(
                        group.process_incoming(provider, second.protected_body()),
                        Err(lattice_mls::api::MlsError::ConflictDetected { parent_epoch })
                            if parent_epoch == conflict.parent_epoch
                    ) {
                        return Err(CoreError::SpaceMembershipSnapshotInvalid);
                    }
                    let evidence = group
                        .conflict_evidence()
                        .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                    if evidence.parent_epoch() != conflict.parent_epoch
                        || evidence.first_commit() != first.protected_body()
                        || evidence.second_commit() != second.protected_body()
                    {
                        return Err(CoreError::SpaceMembershipSnapshotInvalid);
                    }
                    let first_proof = evidence
                        .first_membership_change()
                        .cloned()
                        .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                    let second_proof = evidence
                        .second_membership_change()
                        .cloned()
                        .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                    reducer
                        .observe_validated_control_event(&first, first_proof)
                        .map_err(CoreError::SpaceControlRejected)?;
                    reducer
                        .observe_validated_control_event(&second, second_proof)
                        .map_err(CoreError::SpaceControlRejected)?;
                    reducer.mark_membership_conflicted(&first, &second);
                }
                // Restored history is accepted only when every stored proof has
                // a corresponding committed MLS epoch.
                Ok((group_reference, reducer))
            })?;
        Ok(CreatedSpace {
            space_id,
            group_id,
            group_reference,
            genesis_event: restored_event,
            reducer,
        })
    }

    /// Restores a bounded page of locally created Space generations.
    ///
    /// Every result passes through [`Client::restore_space`], including its
    /// signature, MLS group, and authenticated snapshot checks. A full page
    /// returns an exclusive cursor; the final page can therefore require one
    /// additional empty query when the record count is an exact page multiple.
    ///
    /// # Errors
    ///
    /// Returns an error if the index query or any generation's integrity checks
    /// fail. No partial page is returned.
    pub fn restore_space_page(
        &mut self,
        after: Option<SpaceGenesisCursor>,
    ) -> Result<RestoredSpacePage, CoreError> {
        let cursors = self.store.list_space_genesis_page(after)?;
        let next_cursor = if cursors.len() == MAX_SPACE_GENESIS_PAGE_SIZE {
            cursors.last().copied()
        } else {
            None
        };
        let mut spaces = Vec::with_capacity(cursors.len());
        for cursor in cursors {
            spaces.push(self.restore_space(&cursor.space_id, &cursor.group_reference)?);
        }
        Ok(RestoredSpacePage {
            spaces,
            next_cursor,
        })
    }

    /// Creates a signed offline invitation and atomically commits its policy
    /// Invite, MLS Add Commit, and parent-epoch membership transition.
    ///
    /// `key_package_wire` must be a valid, unexpired X.509 `KeyPackage` for the
    /// invited device. Revision expiry is deterministic policy state;
    /// `expires_at_unix_seconds` is an additional signed local expiry hint.
    /// The returned bootstrap contains the MLS Welcome and accepted policy
    /// checkpoint needed by `space join`.
    ///
    /// # Errors
    ///
    /// Returns an error if local policy denies invitation, the target package
    /// is invalid, any signed event or policy transition fails, or the atomic
    /// MLS/store update cannot be committed.
    #[allow(clippy::too_many_lines)] // Invite, Add, transition, and replay evidence form one atomic boundary.
    pub fn create_space_invite(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        key_package_wire: &[u8],
        expires_at_revision: Option<u64>,
        expires_at_unix_seconds: u64,
        max_uses: Option<u16>,
    ) -> Result<CreatedSpaceInvite, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ))?;
        self.ensure_space_generation_mutable(&policy.space_id, &policy.group_reference)?;
        let (invite_parents, invite_lamport) = resolve_policy_parents(&self.store, policy)?;
        let existing_snapshots = self.store.list_space_membership_transition_snapshots(
            &created.space_id,
            &created.group_reference,
        )?;
        let replay_base_revision = match existing_snapshots.last() {
            Some(snapshot) => snapshot.policy_revision,
            None => created
                .reducer
                .policy_replay_base_revision()
                .map_err(|reason| {
                    CoreError::SpaceMembershipNotApplied(space::ApplyResult::Rejected(reason))
                })?,
        };

        let expected_space_id = created.space_id;
        let expected_group_reference = created.group_reference;
        let group_id = created.group_id.clone();
        let genesis_event_id = *created.genesis_event.event_id().as_bytes();
        let inviter_identity = self.identity.fingerprint();
        let credential = credential.clone();
        let key_package_wire = key_package_wire.to_vec();
        let reducer = created.reducer.clone();
        let root_event = created.genesis_event.clone();
        let root_snapshot = self
            .store
            .load_space_genesis_snapshot(&expected_space_id, &expected_group_reference)?
            .ok_or(CoreError::SpaceGenesisSnapshotNotFound)?;
        if root_snapshot.event_id != genesis_event_id {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let root_context = space_genesis_context(
            &root_snapshot.space_id,
            &root_snapshot.group_reference,
            &root_snapshot.event_id,
        );
        let encrypted_root_state = root_snapshot.encrypted_state.clone();
        let genesis_plaintext = self.with_mls_transaction(move |_, _, _| {
            lattice_mls::unprotect_local_record(&root_context, &encrypted_root_state)
                .map_err(CoreError::from)
        })?;
        let mut existing_head_events = Vec::with_capacity(policy.heads.len());
        for head in &policy.heads {
            let record = self
                .store
                .load_event(head)?
                .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
            let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
            if event.event_id().as_bytes() != head
                || event.space_id() != &expected_space_id
                || event.mls_group_reference() != &expected_group_reference
            {
                return Err(CoreError::SpaceWelcomeBootstrapInvalid);
            }
            existing_head_events.push(event);
        }
        let credential_trust_policy = self.credential_trust_policy.clone();
        let (invite_event, token, target_fingerprint, staged_reducer, welcome_bootstrap) = self
            .with_mls_transaction(move |identity, provider, transaction| {
                let mut staged_reducer = reducer;
                if identity.fingerprint() != inviter_identity {
                    return Err(CoreError::SpaceCredentialInvalid);
                }
                let mut group = GroupState::load_with_trust_policy(
                    provider,
                    &group_id,
                    &credential_trust_policy,
                )?;
                if group.group_reference() != expected_group_reference {
                    return Err(CoreError::SpaceMembershipNotApplied(
                        space::ApplyResult::Rejected(space::RejectReason::WrongGeneration),
                    ));
                }
                let prepared =
                    group.prepare_add(provider, identity, &credential, &key_package_wire)?;
                let target = *prepared.added_member_identity_fingerprint();
                let key_package_hash = *prepared.key_package_sha256();
                let parent_epoch = prepared.parent_epoch();

                let mut invite_id = [0u8; 16];
                let mut nonce = [0u8; 16];
                getrandom::fill(&mut invite_id)
                    .map_err(|_| CoreError::SpaceIdentifierRandomness)?;
                getrandom::fill(&mut nonce).map_err(|_| CoreError::SpaceIdentifierRandomness)?;

                let invite_plaintext = encode_canonical(&Value::Map(vec![
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(2)),
                    (2, Value::Bytes(invite_id.to_vec())),
                    (3, Value::Bytes(target.to_vec())),
                    (4, Value::Bytes(key_package_hash.to_vec())),
                    (5, expires_at_revision.map_or(Value::Null, Value::Unsigned)),
                    (
                        6,
                        max_uses.map_or(Value::Null, |uses| Value::Unsigned(u64::from(uses))),
                    ),
                ]))?;
                let (invite_ciphertext, invite_application) = group
                    .encrypt_application_for_pending_membership_with_evidence(
                        provider,
                        identity,
                        &credential,
                        &prepared,
                        &invite_plaintext,
                    )?;
                let invite_sequence =
                    Store::next_author_sequence_in_transaction(transaction, &inviter_identity)?;
                let invite_event = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id: expected_space_id,
                        channel_id: None,
                        author_sequence: invite_sequence,
                        lamport: invite_lamport,
                        wall_time_hint: 0,
                        parents: invite_parents,
                        kind: EventKind::Membership,
                        protected_body: invite_ciphertext.as_bytes().to_vec(),
                        mls_group_reference: expected_group_reference,
                        mls_epoch: parent_epoch,
                    },
                )?;
                let bound_invite = bind_mls_application(invite_event.clone(), invite_application)?;
                let invite_result = staged_reducer.apply(&bound_invite, None);
                if !matches!(invite_result, space::ApplyResult::Applied { .. }) {
                    return Err(CoreError::SpaceMembershipNotApplied(invite_result));
                }
                let policy_events = staged_reducer
                    .policy_replay_events_after(replay_base_revision)
                    .map_err(|reason| {
                        CoreError::SpaceMembershipNotApplied(space::ApplyResult::Rejected(reason))
                    })?;
                let invite_event_id = *invite_event.event_id().as_bytes();

                let control_event = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id: expected_space_id,
                        channel_id: None,
                        author_sequence: invite_sequence
                            .checked_add(1)
                            .ok_or(lattice_storage::StoreError::SequenceExhausted)?,
                        lamport: invite_lamport
                            .checked_add(1)
                            .ok_or(CoreError::SpaceLamportExhausted)?,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(invite_event_id)],
                        kind: EventKind::MlsControl,
                        protected_body: prepared.commit().as_bytes().to_vec(),
                        mls_group_reference: expected_group_reference,
                        mls_epoch: parent_epoch,
                    },
                )?;
                staged_reducer
                    .observe_persisted_control_event(
                        &control_event,
                        lattice_mls::api::MlsMembershipAction::Add,
                        target,
                        Some(key_package_hash),
                    )
                    .map_err(CoreError::SpaceControlRejected)?;
                let control_event_id = *control_event.event_id().as_bytes();
                let transition_plaintext = encode_canonical(&Value::Map(vec![
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(6)),
                    (2, Value::Unsigned(0)),
                    (3, Value::Bytes(target.to_vec())),
                    (4, Value::Bytes(invite_event_id.to_vec())),
                    (5, Value::Bytes(control_event_id.to_vec())),
                ]))?;
                let (transition_ciphertext, transition_application) = group
                    .encrypt_application_for_pending_membership_with_evidence(
                        provider,
                        identity,
                        &credential,
                        &prepared,
                        &transition_plaintext,
                    )?;
                let transition_event = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id: expected_space_id,
                        channel_id: None,
                        author_sequence: invite_sequence
                            .checked_add(2)
                            .ok_or(lattice_storage::StoreError::SequenceExhausted)?,
                        lamport: invite_lamport
                            .checked_add(2)
                            .ok_or(CoreError::SpaceLamportExhausted)?,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(control_event_id)],
                        kind: EventKind::Membership,
                        protected_body: transition_ciphertext.as_bytes().to_vec(),
                        mls_group_reference: expected_group_reference,
                        mls_epoch: parent_epoch,
                    },
                )?;
                let bound_transition =
                    bind_mls_application(transition_event, transition_application)?;
                let transition_result = staged_reducer.apply(&bound_transition, None);
                if !matches!(transition_result, space::ApplyResult::Applied { .. }) {
                    return Err(CoreError::SpaceMembershipNotApplied(transition_result));
                }
                commit_authored_event_to_outbox(transaction, &invite_event)?;
                commit_authored_event_to_outbox(transaction, &control_event)?;
                commit_authored_event_to_outbox(transaction, bound_transition.event())?;

                let welcome =
                    group.accept_prepared_add(provider, &prepared, prepared.commit().as_bytes())?;
                let revision = staged_reducer
                    .policy()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
                    .revision;
                let replay_data = encode_space_membership_replay_data(
                    parent_epoch,
                    revision,
                    lattice_mls::api::MlsMembershipAction::Add,
                    target,
                    Some(key_package_hash),
                    bound_transition.plaintext(),
                    policy_events,
                )?;
                let transition_event_id = *bound_transition.event().event_id().as_bytes();
                let context = space_membership_context(
                    &expected_space_id,
                    &expected_group_reference,
                    parent_epoch,
                    &control_event_id,
                    &transition_event_id,
                );
                let encrypted_state = lattice_mls::protect_local_record(&context, &replay_data)?;
                Store::save_space_membership_transition_snapshot_in_transaction(
                    transaction,
                    &SpaceMembershipTransitionSnapshot {
                        space_id: expected_space_id,
                        group_reference: expected_group_reference,
                        parent_epoch,
                        policy_revision: revision,
                        control_event_id,
                        transition_event_id,
                        encrypted_state,
                    },
                )?;
                let token = SpaceInviteV1::sign(
                    identity,
                    expected_space_id,
                    genesis_event_id,
                    invite_event_id,
                    invite_id,
                    target,
                    key_package_hash,
                    expires_at_unix_seconds,
                    max_uses,
                    nonce,
                    Vec::new(),
                )
                .map_err(|_| CoreError::SpaceInviteInvalid)?
                .to_bytes()
                .map_err(|_| CoreError::SpaceInviteInvalid)?;
                let staged_policy = staged_reducer
                    .policy()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                let mut head_events = Vec::with_capacity(staged_policy.heads.len());
                for head in &staged_policy.heads {
                    let event = std::iter::once(&invite_event)
                        .chain(std::iter::once(&control_event))
                        .chain(std::iter::once(bound_transition.event()))
                        .chain(existing_head_events.iter())
                        .find(|event| event.event_id().as_bytes() == head)
                        .cloned()
                        .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
                    head_events.push(event);
                }
                let staged_space = CreatedSpace {
                    space_id: expected_space_id,
                    group_id: group_id.clone(),
                    group_reference: expected_group_reference,
                    genesis_event: root_event,
                    reducer: staged_reducer.clone(),
                };
                let welcome_bootstrap = Client::build_space_welcome_bootstrap(
                    identity,
                    &staged_space,
                    &group,
                    &space_bootstrap::SpaceWelcomeEvidence {
                        welcome_wire: welcome.as_bytes(),
                        genesis_plaintext: &genesis_plaintext,
                        invite_event: &invite_event,
                        invite_plaintext: &invite_plaintext,
                        head_events: &head_events,
                        last_control_event: Some(&control_event),
                        target,
                        epoch: group.epoch(),
                    },
                )?;
                Ok((
                    invite_event,
                    token,
                    target,
                    staged_reducer,
                    welcome_bootstrap,
                ))
            })?;
        created.reducer = staged_reducer;
        Ok(CreatedSpaceInvite {
            invite_event_id: *invite_event.event_id().as_bytes(),
            target_fingerprint,
            token,
            welcome_bootstrap,
        })
    }

    /// Removes one active Space member with an authorized, persisted MLS
    /// Commit and matching policy transition.
    ///
    /// The MLS epoch, control event, policy transition, replay snapshot, and
    /// local reducer are committed in one storage transaction. A conflicted
    /// generation or unauthorized removal produces no outbox events.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential is invalid, the generation is
    /// blocked, the target is not removable, policy denies removal, event
    /// construction fails, or the atomic MLS/store update cannot be committed.
    #[allow(clippy::too_many_lines)] // Membership control, transition, rekey, and replay evidence are atomic.
    pub fn remove_space_member(
        &mut self,
        created: &mut CreatedSpace,
        credential: &DeviceCredentialInput,
        target_fingerprint: [u8; 32],
    ) -> Result<CreatedSpaceMemberRemoval, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ))?;
        self.ensure_space_generation_mutable(&policy.space_id, &policy.group_reference)?;
        let (control_parents, control_lamport) = resolve_policy_parents(&self.store, policy)?;
        let existing_snapshots = self.store.list_space_membership_transition_snapshots(
            &created.space_id,
            &created.group_reference,
        )?;
        let replay_base_revision = match existing_snapshots.last() {
            Some(snapshot) => snapshot.policy_revision,
            None => created
                .reducer
                .policy_replay_base_revision()
                .map_err(|reason| {
                    CoreError::SpaceMembershipNotApplied(space::ApplyResult::Rejected(reason))
                })?,
        };
        let expected_space_id = created.space_id;
        let expected_group_reference = created.group_reference;
        let group_id = created.group_id.clone();
        let identity_fingerprint = self.identity.fingerprint();
        let credential_trust_policy = credential.trust_policy().clone();
        let credential = credential.clone();
        let reducer = created.reducer.clone();
        let wall_time_hint = current_wall_time_hint()?;
        let (staged_reducer, control_event_id, transition_event_id, parent_epoch, new_epoch) = self
            .with_mls_transaction(move |identity, provider, transaction| {
                let mut staged_reducer = reducer;
                if identity.fingerprint() != identity_fingerprint {
                    return Err(CoreError::SpaceCredentialInvalid);
                }
                let mut group = GroupState::load_with_trust_policy(
                    provider,
                    &group_id,
                    &credential_trust_policy,
                )?;
                if group.group_reference() != expected_group_reference {
                    return Err(CoreError::SpaceMembershipNotApplied(
                        space::ApplyResult::Rejected(space::RejectReason::WrongGeneration),
                    ));
                }
                let prepared =
                    group.prepare_remove(provider, identity, &credential, &target_fingerprint)?;
                let parent_epoch = prepared.parent_epoch();
                let target = *prepared.removed_member_identity_fingerprint();
                let first_sequence =
                    Store::next_author_sequence_in_transaction(transaction, &identity_fingerprint)?;
                let control_event = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id: expected_space_id,
                        channel_id: None,
                        author_sequence: first_sequence,
                        lamport: control_lamport,
                        wall_time_hint,
                        parents: control_parents,
                        kind: EventKind::MlsControl,
                        protected_body: prepared.commit().as_bytes().to_vec(),
                        mls_group_reference: expected_group_reference,
                        mls_epoch: parent_epoch,
                    },
                )?;
                staged_reducer
                    .observe_persisted_control_event(
                        &control_event,
                        lattice_mls::api::MlsMembershipAction::Remove,
                        target,
                        None,
                    )
                    .map_err(CoreError::SpaceControlRejected)?;
                let policy_events = staged_reducer
                    .policy_replay_events_after(replay_base_revision)
                    .map_err(|reason| {
                        CoreError::SpaceMembershipNotApplied(space::ApplyResult::Rejected(reason))
                    })?;
                let control_event_id = *control_event.event_id().as_bytes();
                let transition_plaintext = encode_canonical(&Value::Map(vec![
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(6)),
                    (2, Value::Unsigned(1)),
                    (3, Value::Bytes(target.to_vec())),
                    (4, Value::Null),
                    (5, Value::Bytes(control_event_id.to_vec())),
                ]))?;
                let (transition_ciphertext, transition_application) = group
                    .encrypt_application_for_pending_removal_with_evidence(
                        provider,
                        identity,
                        &credential,
                        &prepared,
                        &transition_plaintext,
                    )?;
                let transition_event = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id: expected_space_id,
                        channel_id: None,
                        author_sequence: first_sequence
                            .checked_add(1)
                            .ok_or(lattice_storage::StoreError::SequenceExhausted)?,
                        lamport: control_lamport
                            .checked_add(1)
                            .ok_or(CoreError::SpaceLamportExhausted)?,
                        wall_time_hint,
                        parents: vec![lattice_protocol::EventId::from_bytes(control_event_id)],
                        kind: EventKind::Membership,
                        protected_body: transition_ciphertext.as_bytes().to_vec(),
                        mls_group_reference: expected_group_reference,
                        mls_epoch: parent_epoch,
                    },
                )?;
                let bound_transition =
                    bind_mls_application(transition_event, transition_application)?;
                let transition_result = staged_reducer.apply(&bound_transition, None);
                if !matches!(transition_result, space::ApplyResult::Applied { .. }) {
                    return Err(CoreError::SpaceMembershipNotApplied(transition_result));
                }
                commit_authored_event_to_outbox(transaction, &control_event)?;
                commit_authored_event_to_outbox(transaction, bound_transition.event())?;
                group.accept_prepared_remove(provider, &prepared, prepared.commit().as_bytes())?;
                let new_epoch = group.epoch();
                let revision = staged_reducer
                    .policy()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
                    .revision;
                let transition_event_id = *bound_transition.event().event_id().as_bytes();
                let replay_data = encode_space_membership_replay_data(
                    parent_epoch,
                    revision,
                    lattice_mls::api::MlsMembershipAction::Remove,
                    target,
                    None,
                    bound_transition.plaintext(),
                    policy_events,
                )?;
                let context = space_membership_context(
                    &expected_space_id,
                    &expected_group_reference,
                    parent_epoch,
                    &control_event_id,
                    &transition_event_id,
                );
                let encrypted_state = lattice_mls::protect_local_record(&context, &replay_data)?;
                Store::save_space_membership_transition_snapshot_in_transaction(
                    transaction,
                    &SpaceMembershipTransitionSnapshot {
                        space_id: expected_space_id,
                        group_reference: expected_group_reference,
                        parent_epoch,
                        policy_revision: revision,
                        control_event_id,
                        transition_event_id,
                        encrypted_state,
                    },
                )?;
                Ok((
                    staged_reducer,
                    control_event_id,
                    transition_event_id,
                    parent_epoch,
                    new_epoch,
                ))
            })?;
        created.reducer = staged_reducer;
        Ok(CreatedSpaceMemberRemoval {
            target_fingerprint,
            control_event_id,
            transition_event_id,
            parent_epoch,
            new_epoch,
        })
    }

    /// Removes a member after validating the supplied X.509 credential against
    /// this profile's pinned issuer and the client's configured trust policy.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::SpaceCredentialInvalid`] for malformed, untrusted,
    /// oversized, or mismatched credential bytes. Removal, policy, MLS, and
    /// storage failures are also returned.
    pub fn remove_space_member_from_x509_credential(
        &mut self,
        created: &mut CreatedSpace,
        credential_content: Vec<u8>,
        target_fingerprint: [u8; 32],
    ) -> Result<CreatedSpaceMemberRemoval, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        self.remove_space_member(created, &credential, target_fingerprint)
    }

    /// Publishes a one-time X.509 `KeyPackage` using this profile's pinned issuer.
    ///
    /// The certificate vector is validated against the local signing identity
    /// and trust policy before MLS creates or stores the package.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::SpaceCredentialInvalid`] if the credential is
    /// malformed, untrusted, or does not match the local identity. MLS or
    /// storage failures are also returned.
    pub fn publish_x509_key_package(
        &mut self,
        credential_content: Vec<u8>,
        now: u64,
    ) -> Result<Vec<u8>, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        self.publish_key_package(&credential, now)
    }

    /// Creates an offline invite using a device certificate validated locally.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::SpaceCredentialInvalid`] for malformed, untrusted,
    /// or mismatched credential bytes. Invalid key packages, denied invitation
    /// policy, event creation, MLS, and storage failures are also returned.
    pub fn create_space_invite_from_x509_credential(
        &mut self,
        created: &mut CreatedSpace,
        credential_content: Vec<u8>,
        key_package_wire: &[u8],
        expires_at_revision: Option<u64>,
        expires_at_unix_seconds: u64,
        max_uses: Option<u16>,
    ) -> Result<CreatedSpaceInvite, CoreError> {
        if credential_content.is_empty() || credential_content.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        self.create_space_invite(
            created,
            &credential,
            key_package_wire,
            expires_at_revision,
            expires_at_unix_seconds,
            max_uses,
        )
    }

    /// Atomically accepts one staged MLS Commit and its parent-epoch policy transition.
    ///
    /// `control_event` must carry the exact TLS Commit in its protected body.
    /// `transition_event` must carry MLS application data authenticated in the
    /// Commit's parent epoch and must pass the reducer's invite/transition
    /// policy. The Commit remains staged until that transition is accepted. The
    /// MLS group writes, both verified event records, and AEAD-protected
    /// reducer replay evidence share one `SQLite` transaction. The returned
    /// reducer is a candidate; callers install it only after this method
    /// Restore replays locally accepted transitions and revalidates durable
    /// sibling-Commit conflicts; joined generations replay from their signed
    /// Welcome checkpoints.
    ///
    /// # Errors
    ///
    /// Returns an error when the group does not match the reducer generation,
    /// either event does not match its authenticated MLS result, policy rejects
    /// the transition, an author sequence equivocates, or any MLS/storage
    /// operation fails. The transaction rolls back on every error.
    pub fn accept_space_membership_transition(
        &mut self,
        group_id: &[u8],
        reducer: &space::SpaceReducer,
        control_event: VerifiedSignatureOnlyEvent,
        transition_event: VerifiedSignatureOnlyEvent,
    ) -> Result<space::SpaceReducer, CoreError> {
        self.accept_space_membership_transition_with_policy_events(
            group_id,
            reducer,
            Vec::new(),
            control_event,
            transition_event,
        )
    }
    /// Accepts one synchronized MLS membership transition with its policy parent.
    ///
    /// The policy event, Commit, transition, reducer replay state, and MLS group
    /// update commit in one transaction. `Ok(false)` means the exact bundle was
    /// already accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if the events are not a bound membership transition,
    /// their author sequence equivocates, policy rejects the operation, or
    /// MLS/storage validation fails.
    pub fn accept_synced_space_membership_transition(
        &mut self,
        created: &mut CreatedSpace,
        policy_event_bytes: Option<&[u8]>,
        control_event_bytes: &[u8],
        transition_event_bytes: &[u8],
    ) -> Result<bool, CoreError> {
        let control_event = VerifiedSignatureOnlyEvent::decode_verify(control_event_bytes)?;
        let transition_event = VerifiedSignatureOnlyEvent::decode_verify(transition_event_bytes)?;
        let mut policy_event = policy_event_bytes
            .map(VerifiedSignatureOnlyEvent::decode_verify)
            .transpose()?;
        let control_event_id = *control_event.event_id().as_bytes();
        if control_event.kind() != EventKind::MlsControl
            || transition_event.kind() != EventKind::Membership
            || control_event.channel_id().is_some()
            || transition_event.channel_id().is_some()
            || control_event.space_id() != &created.space_id
            || transition_event.space_id() != &created.space_id
            || control_event.mls_group_reference() != &created.group_reference
            || transition_event.mls_group_reference() != &created.group_reference
            || control_event.mls_epoch() != transition_event.mls_epoch()
            || !transition_event
                .parents()
                .iter()
                .any(|parent| parent.as_bytes() == &control_event_id)
            || policy_event.as_ref().is_some_and(|event| {
                event.kind() != EventKind::Membership
                    || event.channel_id().is_some()
                    || event.space_id() != &created.space_id
                    || event.mls_group_reference() != &created.group_reference
                    || event.mls_epoch() != control_event.mls_epoch()
                    || !control_event
                        .parents()
                        .iter()
                        .any(|parent| parent.as_bytes() == event.event_id().as_bytes())
            })
        {
            return Err(CoreError::MlsEventBindingFailed);
        }

        if let Some(bytes) = policy_event_bytes {
            let event = policy_event
                .as_ref()
                .ok_or(CoreError::MlsEventBindingFailed)?;
            if let Some(record) = self.store.load_event(event.event_id().as_bytes())? {
                if record.canonical_bytes != bytes {
                    return Err(CoreError::Storage(StoreError::EventIdConflict));
                }
                policy_event = None;
            }
        }
        let control_record = self.store.load_event(control_event.event_id().as_bytes())?;
        let transition_record = self
            .store
            .load_event(transition_event.event_id().as_bytes())?;
        for (record, bytes) in [
            (control_record.as_ref(), control_event_bytes),
            (transition_record.as_ref(), transition_event_bytes),
        ] {
            if record.is_some_and(|record| record.canonical_bytes != bytes) {
                return Err(CoreError::Storage(StoreError::EventIdConflict));
            }
        }
        let control_exists = control_record.is_some();
        let transition_exists = transition_record.is_some();
        if control_exists != transition_exists {
            return Err(CoreError::SpaceMembershipSnapshotInvalid);
        }
        if control_exists {
            return Ok(false);
        }

        let reducer = self.accept_space_membership_transition_with_policy_events(
            &created.group_id,
            &created.reducer,
            policy_event.into_iter().collect(),
            control_event,
            transition_event,
        )?;
        created.reducer = reducer;
        Ok(true)
    }

    #[allow(clippy::too_many_lines)] // One membership transition is an atomic authenticated boundary.
    fn accept_space_membership_transition_with_policy_events(
        &mut self,
        group_id: &[u8],
        reducer: &space::SpaceReducer,
        incoming_policy_events: Vec<VerifiedSignatureOnlyEvent>,
        control_event: VerifiedSignatureOnlyEvent,
        transition_event: VerifiedSignatureOnlyEvent,
    ) -> Result<space::SpaceReducer, CoreError> {
        let policy = reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ))?;
        self.ensure_space_generation_mutable(&policy.space_id, &policy.group_reference)?;
        let expected_group_reference = policy.group_reference;
        let expected_space_id = policy.space_id;
        let group_id = group_id.to_vec();
        let existing_snapshots = self.store.list_space_membership_transition_snapshots(
            &expected_space_id,
            &expected_group_reference,
        )?;
        let replay_base_revision = match existing_snapshots.last() {
            Some(snapshot) => snapshot.policy_revision,
            None => reducer.policy_replay_base_revision().map_err(|reason| {
                CoreError::SpaceMembershipNotApplied(space::ApplyResult::Rejected(reason))
            })?,
        };
        let mut staged_reducer = reducer.clone();
        let credential_trust_policy = self.credential_trust_policy.clone();
        self.with_mls_transaction(move |_identity, provider, transaction| {
            let mut group =
                GroupState::load_with_trust_policy(provider, &group_id, &credential_trust_policy)?;
            if group.group_reference() != expected_group_reference {
                return Err(CoreError::SpaceMembershipNotApplied(
                    space::ApplyResult::Rejected(space::RejectReason::WrongGeneration),
                ));
            }
            let policy = staged_reducer
                .policy()
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            let active_member_count = policy
                .members
                .iter()
                .filter(|member| member.status == space::MemberStatus::Active)
                .count();
            let checkpoint_roster_matches = active_member_count == group.member_count()
                && policy
                    .members
                    .iter()
                    .filter(|member| member.status == space::MemberStatus::Active)
                    .all(|member| group.contains_member_identity(&member.fingerprint));
            if control_event.mls_epoch() < group.epoch() && checkpoint_roster_matches {
                let mut checkpointed_reducer = reducer.clone();
                if checkpointed_reducer
                    .register_checkpoint_covered_membership_history(
                        &incoming_policy_events,
                        &control_event,
                        &transition_event,
                    )
                    .is_ok()
                {
                    // The signed Welcome checkpoint already attests this
                    // earlier transition. Preserve its signed ancestry without
                    // replaying an MLS commit older than the joined epoch.
                    for event in &incoming_policy_events {
                        store_received_event(transaction, event)?;
                    }
                    store_received_event(transaction, &control_event)?;
                    store_received_event(transaction, &transition_event)?;
                    staged_reducer = checkpointed_reducer;
                    return Ok(staged_reducer);
                }
            }
            for event in incoming_policy_events {
                let IncomingResult::Application(application) =
                    group.process_incoming(provider, event.protected_body())?
                else {
                    return Err(CoreError::MlsEventBindingFailed);
                };
                let bound = bind_mls_application(event, application)?;
                if !matches!(
                    staged_reducer.apply(&bound, None),
                    space::ApplyResult::Applied { .. }
                ) {
                    return Err(CoreError::SpaceMembershipSnapshotInvalid);
                }
                store_received_event(transaction, bound.event())?;
            }

            let commit_wire = control_event.protected_body();
            if !matches!(
                group.process_incoming(provider, commit_wire)?,
                IncomingResult::StagedCommit { .. }
            ) {
                return Err(CoreError::MlsEventBindingFailed);
            }
            let proof = group
                .take_staged_membership_change()
                .ok_or(CoreError::MlsEventBindingFailed)?;
            let parent_epoch = proof.parent_epoch();
            let action = proof.action();
            let target = *proof.target();
            let key_package_hash = proof.key_package_hash().copied();
            staged_reducer
                .observe_validated_control_event(&control_event, proof)
                .map_err(CoreError::SpaceControlRejected)?;

            let policy_events = staged_reducer
                .policy_replay_events_after(replay_base_revision)
                .map_err(|reason| {
                    CoreError::SpaceMembershipNotApplied(space::ApplyResult::Rejected(reason))
                })?;
            let IncomingResult::Application(application) =
                group.process_incoming(provider, transition_event.protected_body())?
            else {
                return Err(CoreError::MlsEventBindingFailed);
            };
            let bound = bind_mls_application(transition_event, application)?;
            let result = staged_reducer.apply(&bound, None);
            if !matches!(result, space::ApplyResult::Applied { .. }) {
                return Err(CoreError::SpaceMembershipNotApplied(result));
            }
            let control_event_id = *control_event.event_id().as_bytes();
            let transition_event_id = *bound.event().event_id().as_bytes();
            let replay_data = encode_space_membership_replay_data(
                parent_epoch,
                staged_reducer
                    .policy()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
                    .revision,
                action,
                target,
                key_package_hash,
                bound.plaintext(),
                policy_events,
            )?;
            let context = space_membership_context(
                &expected_space_id,
                &expected_group_reference,
                parent_epoch,
                &control_event_id,
                &transition_event_id,
            );
            let encrypted_state = lattice_mls::protect_local_record(&context, &replay_data)?;
            store_received_event(transaction, &control_event)?;
            store_received_event(transaction, bound.event())?;
            Store::save_space_membership_transition_snapshot_in_transaction(
                transaction,
                &SpaceMembershipTransitionSnapshot {
                    space_id: expected_space_id,
                    group_reference: expected_group_reference,
                    parent_epoch,
                    policy_revision: staged_reducer
                        .policy()
                        .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?
                        .revision,
                    control_event_id,
                    transition_event_id,
                    encrypted_state,
                },
            )?;
            group.accept_incoming_commit(provider, commit_wire)?;
            Ok(staged_reducer)
        })
    }
    /// Creates a signed, encrypted MLS self-removal request and queues it locally.
    ///
    /// The request does not end membership: a current group member must commit
    /// the Remove proposal. The root author cannot leave without a prior
    /// ownership transfer.
    ///
    /// # Errors
    ///
    /// Returns an error if the generation is stale, the local identity is not
    /// an active member, the policy protects the root author, or MLS/signing/
    /// storage/outbox validation fails.
    pub fn request_space_leave(
        &mut self,
        created: &CreatedSpace,
        credential: &DeviceCredentialInput,
    ) -> Result<[u8; 32], CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ))?;
        let fingerprint = self.identity.fingerprint();
        if fingerprint == policy.root_author {
            return Err(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::OwnerProtected),
            ));
        }
        if !policy.members.iter().any(|member| {
            member.fingerprint == fingerprint && member.status == space::MemberStatus::Active
        }) {
            return Err(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::InvalidTransition),
            ));
        }
        let (parents, lamport) = resolve_policy_parents(&self.store, policy)?;
        let group_id = created.group_id.clone();
        let space_id = created.space_id;
        let group_reference = created.group_reference;
        let credential_trust_policy = self.credential_trust_policy.clone();
        self.with_mls_transaction(|identity, provider, transaction| {
            let mut group =
                GroupState::load_with_trust_policy(provider, &group_id, &credential_trust_policy)?;
            if group.group_reference() != group_reference
                || !group.contains_member_identity(&identity.fingerprint())
            {
                return Err(CoreError::MlsEventBindingFailed);
            }
            let proposal = group.prepare_leave(provider, identity, credential)?;
            let sequence =
                Store::next_author_sequence_in_transaction(transaction, &identity.fingerprint())?;
            let event = VerifiedSignatureOnlyEvent::create(
                identity,
                EventDraft {
                    space_id,
                    channel_id: None,
                    author_sequence: sequence,
                    lamport,
                    wall_time_hint: 0,
                    parents,
                    kind: EventKind::MlsControl,
                    protected_body: proposal.as_bytes().to_vec(),
                    mls_group_reference: group_reference,
                    mls_epoch: group.epoch(),
                },
            )?;
            let parent_ids = event
                .parents()
                .iter()
                .map(|parent| *parent.as_bytes())
                .collect::<Vec<_>>();
            if let CommitOutcome::Equivocation { existing_event_id } =
                Store::commit_authored_with_outbox_in_transaction(
                    transaction,
                    *event.author_fingerprint(),
                    *event.event_id().as_bytes(),
                    sequence,
                    event.encoded_bytes(),
                    &parent_ids,
                    event.encoded_bytes(),
                    0,
                )?
            {
                return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
            }
            Ok(*event.event_id().as_bytes())
        })
    }
    /// Restores a local Space, validates the supplied X.509 credential, and
    /// queues its signed self-removal request.
    ///
    /// The returned event identifier denotes a locally queued request, not a
    /// network delivery or a completed peer-side removal.
    ///
    /// # Errors
    ///
    /// Returns credential, restoration, membership, MLS, signing, or storage
    /// errors from the underlying operation.
    pub fn request_space_leave_from_x509_credential(
        &mut self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        credential_content: Vec<u8>,
    ) -> Result<[u8; 32], CoreError> {
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let created = self.restore_space(space_id, group_reference)?;
        self.request_space_leave(&created, &credential)
    }

    /// Authenticates and durably queues a peer's MLS self-removal request.
    ///
    /// The remote Remove proposal remains pending in the MLS group until a
    /// member commits it; this method does not alter the Space policy.
    ///
    /// # Errors
    ///
    /// Rejects stale epochs, unrelated or unauthorized events, non-self-removal
    /// proposals, missing policy parents, and duplicate author sequences.
    pub fn accept_space_leave_request(
        &mut self,
        created: &CreatedSpace,
        event: &VerifiedSignatureOnlyEvent,
    ) -> Result<(), CoreError> {
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ))?;
        if event.space_id() != &created.space_id
            || event.mls_group_reference() != &created.group_reference
            || event.kind() != EventKind::MlsControl
            || event.channel_id().is_some()
            || event.author_fingerprint() == &policy.root_author
            || !policy.members.iter().any(|member| {
                member.fingerprint == *event.author_fingerprint()
                    && member.status == space::MemberStatus::Active
            })
        {
            return Err(CoreError::MlsEventBindingFailed);
        }
        let (required_parents, _) = resolve_policy_parents(&self.store, policy)?;
        if required_parents
            .iter()
            .any(|parent| !event.parents().contains(parent))
        {
            return Err(CoreError::SpaceParentEventMissing);
        }
        let group_id = created.group_id.clone();
        let group_reference = created.group_reference;
        let credential_trust_policy = self.credential_trust_policy.clone();
        self.with_mls_transaction(move |_identity, provider, transaction| {
            let mut group =
                GroupState::load_with_trust_policy(provider, &group_id, &credential_trust_policy)?;
            if group.group_reference() != group_reference || event.mls_epoch() != group.epoch() {
                return Err(CoreError::MlsEventBindingFailed);
            }
            match group.process_incoming(provider, event.protected_body())? {
                IncomingResult::Proposal {
                    external: false,
                    member_identity_fingerprint: Some(author),
                    self_remove: true,
                    ..
                } if author == *event.author_fingerprint() => {
                    store_received_event(transaction, event)
                }
                _ => Err(CoreError::MlsEventBindingFailed),
            }
        })
    }
    /// Persists a same-parent conflict after authenticating both sibling MLS
    /// Commits. Neither branch is merged or applied to the common Space policy.
    ///
    /// Both outer control events and the durable conflict marker commit in the
    /// same `SQLite` transaction. Callers must treat the returned reducer as
    /// quarantined and require a new generation for further mutations.
    ///
    /// # Errors
    ///
    /// Returns an error unless both controls bind to distinct valid MLS
    /// membership Commits extending the group's current epoch.
    pub fn record_space_membership_conflict(
        &mut self,
        group_id: &[u8],
        reducer: &space::SpaceReducer,
        first_control_event: VerifiedSignatureOnlyEvent,
        second_control_event: VerifiedSignatureOnlyEvent,
    ) -> Result<space::SpaceReducer, CoreError> {
        let Some(policy) = reducer.policy() else {
            return Err(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ));
        };
        if matches!(reducer.status(), space::ReducerStatus::PolicyConflicted) {
            return Err(CoreError::SpaceMembershipConflicted);
        }
        let expected_space_id = policy.space_id;
        let expected_group_reference = policy.group_reference;
        if first_control_event.event_id() == second_control_event.event_id()
            || [&first_control_event, &second_control_event]
                .into_iter()
                .any(|event| {
                    event.space_id() != &expected_space_id
                        || event.mls_group_reference() != &expected_group_reference
                        || event.kind() != EventKind::MlsControl
                        || event.channel_id().is_some()
                })
        {
            return Err(CoreError::MlsEventBindingFailed);
        }
        if self
            .store
            .load_space_membership_conflict(&expected_space_id, &expected_group_reference)?
            .is_some()
        {
            return Err(CoreError::SpaceMembershipConflicted);
        }

        let group_id = group_id.to_vec();
        let first_event_id = *first_control_event.event_id().as_bytes();
        let second_event_id = *second_control_event.event_id().as_bytes();
        let mut staged_reducer = reducer.clone();
        let credential_trust_policy = self.credential_trust_policy.clone();
        self.with_mls_transaction(move |_identity, provider, transaction| {
            let mut group =
                GroupState::load_with_trust_policy(provider, &group_id, &credential_trust_policy)?;
            if group.group_reference() != expected_group_reference
                || first_control_event.mls_epoch() != group.epoch()
                || second_control_event.mls_epoch() != group.epoch()
            {
                return Err(CoreError::MlsEventBindingFailed);
            }
            let IncomingResult::StagedCommit {
                parent_epoch: first_parent,
                ..
            } = group.process_incoming(provider, first_control_event.protected_body())?
            else {
                return Err(CoreError::MlsEventBindingFailed);
            };

            match group.process_incoming(provider, second_control_event.protected_body()) {
                Err(lattice_mls::api::MlsError::ConflictDetected { parent_epoch })
                    if parent_epoch == first_parent => {}
                _ => return Err(CoreError::MlsEventBindingFailed),
            }
            let evidence = group
                .conflict_evidence()
                .ok_or(CoreError::MlsEventBindingFailed)?;
            if evidence.parent_epoch() != first_parent
                || evidence.first_commit() != first_control_event.protected_body()
                || evidence.second_commit() != second_control_event.protected_body()
            {
                return Err(CoreError::MlsEventBindingFailed);
            }
            let first_proof = evidence
                .first_membership_change()
                .cloned()
                .ok_or(CoreError::MlsEventBindingFailed)?;
            let second_proof = evidence
                .second_membership_change()
                .cloned()
                .ok_or(CoreError::MlsEventBindingFailed)?;
            staged_reducer
                .observe_validated_control_event(&first_control_event, first_proof)
                .map_err(CoreError::SpaceControlRejected)?;
            staged_reducer
                .observe_validated_control_event(&second_control_event, second_proof)
                .map_err(CoreError::SpaceControlRejected)?;
            staged_reducer.mark_membership_conflicted(&first_control_event, &second_control_event);
            store_received_event(transaction, &first_control_event)?;
            store_received_event(transaction, &second_control_event)?;
            Store::save_space_membership_conflict_in_transaction(
                transaction,
                &SpaceMembershipConflictSnapshot {
                    space_id: expected_space_id,
                    group_reference: expected_group_reference,
                    parent_epoch: first_parent,
                    first_control_event_id: first_event_id,
                    second_control_event_id: second_event_id,
                },
            )?;
            Ok(staged_reducer)
        })
    }

    /// Creates a DER PKCS#10 certificate signing request for this device.
    ///
    /// The request contains the public Ed25519 key and the full-fingerprint
    /// URI SAN; private key material never leaves this process.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Identity`] if bounded DER encoding fails.
    pub fn certificate_signing_request(&self) -> Result<Vec<u8>, CoreError> {
        self.identity
            .certificate_signing_request()
            .map_err(CoreError::from)
    }

    /// Returns the non-secret public identity bundle and fingerprint.
    #[must_use]
    pub fn identity_info(&self) -> DeviceIdentityInfo {
        let bundle: IdentityPublicBundle = self.identity.public_bundle();
        DeviceIdentityInfo {
            public_bundle: bundle.to_bytes(),
            fingerprint: bundle.fingerprint(),
        }
    }

    /// Signs a role-bound, transcript-specific exp0 identity proof or confirmation.
    ///
    /// The identity key remains inside Core. The typed context limits signing
    /// to the protocol domains and peer-bundle positions defined by exp0.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when a supplied peer bundle is malformed.
    pub fn sign_ble_exp0_identity_signature(
        &self,
        signature: &BleExp0IdentitySignature,
    ) -> Result<[u8; 64], IdentityError> {
        self.identity.sign_ble_exp0_signature(signature)
    }

    /// Returns the next local author sequence reserved by the durable store.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the durable sequence reservation fails.
    pub fn next_author_sequence(&self) -> Result<u64, CoreError> {
        Ok(self
            .store
            .next_author_sequence(&self.identity.fingerprint())?)
    }
    /// Returns a bounded event-ID-ordered page of durable opaque outbox envelopes.
    ///
    /// The envelope bytes are unchanged from their durable representation.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] for an invalid page limit, malformed stored data,
    /// or storage failures.
    pub fn outbox_page(
        &self,
        after_event_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<OutboxEntry>, CoreError> {
        Ok(self.store.list_outbox_page(after_event_id, limit)?)
    }

    /// Returns verified signed application events from one Space generation's outbox.
    ///
    /// Each page is bounded by [`MAX_OUTBOX_PAGE_SIZE`]. The cursor advances
    /// over every outbox entry, including entries from other generations, so
    /// callers can iterate without rescanning prior rows.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the page limit, stored envelope linkage,
    /// signed event bytes, or storage state is invalid.
    pub fn outbox_application_event_page(
        &self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
        after_event_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<OutboxApplicationEventPage, CoreError> {
        let entries = self.store.list_outbox_page(after_event_id, limit)?;
        let next_cursor = if entries.len() == limit {
            entries.last().map(|entry| entry.event_id)
        } else {
            None
        };
        let mut events = Vec::new();
        for entry in entries {
            let record = self
                .store
                .load_event(&entry.event_id)?
                .ok_or(CoreError::OutboxEventMissing)?;
            let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
            if record.event_id != entry.event_id || event.event_id().as_bytes() != &entry.event_id {
                return Err(CoreError::MlsEventBindingFailed);
            }
            if event.space_id() == space_id
                && event.mls_group_reference() == group_reference
                && matches!(
                    event.kind(),
                    EventKind::Message | EventKind::RelayMailboxControl
                )
            {
                events.push(record.canonical_bytes);
            }
        }
        Ok(OutboxApplicationEventPage {
            events,
            next_cursor,
        })
    }
    /// Records one persisted forwarding attempt for a durable outbox row.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the timestamp or outbox state transition is invalid.
    pub fn mark_outbox_attempt(
        &mut self,
        event_id: [u8; 32],
        next_attempt_ms: i64,
    ) -> Result<(), CoreError> {
        self.store
            .mark_forwarding_attempt(event_id, next_attempt_ms)?;
        Ok(())
    }

    /// Records authenticated peer ingress acceptance, never destination delivery.
    /// # Errors
    ///
    /// Returns an error if the event identifier is unknown or the durable
    /// ingress-acceptance update fails.
    pub fn record_peer_ingress_accepted(&mut self, event_id: [u8; 32]) -> Result<(), CoreError> {
        self.store.record_peer_ingress_accepted(event_id)?;
        Ok(())
    }

    /// Returns the protected mailbox token retained for one exact Space generation.
    /// # Errors
    ///
    /// Returns an error if the protected mailbox record is malformed or cannot
    /// be read or decrypted.
    pub fn space_relay_mailbox(
        &self,
        space_id: &space::SpaceId,
        group_reference: &space::GroupReference,
    ) -> Result<Option<MailboxToken>, CoreError> {
        let Some(ciphertext) = self
            .store
            .load_space_relay_mailbox(space_id, group_reference)?
        else {
            return Ok(None);
        };
        let context = relay_mailbox_context(space_id, group_reference);
        let plaintext = with_mls_storage_key(&self.mls_storage_key[..], || {
            lattice_mls::unprotect_local_record(&context, &ciphertext)
        })??;
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::SpaceRelayMailboxInvalid)?;
        Ok(Some(MailboxToken::from_bytes(bytes)))
    }

    /// Queues an MLS-protected relay-mailbox control after a member has been admitted.
    ///
    /// Each invocation publishes the generation's stable token to the current MLS
    /// membership. The caller must invoke this only after the Add Commit is committed.
    /// The local token and authored control event are committed atomically.
    /// # Errors
    ///
    /// Returns an error for an untrusted credential, stale or unauthorized
    /// generation, missing peer admission, invalid mailbox state, or failed
    /// MLS, signing, or storage operation.
    pub fn publish_space_relay_mailbox_control(
        &mut self,
        created: &CreatedSpace,
        credential: &DeviceCredentialInput,
        now_unix_millis: u64,
    ) -> Result<PublishedSpaceRelayMailbox, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        self.ensure_space_generation_mutable(&created.space_id, &created.group_reference)?;
        if now_unix_millis / 1_000 == 0 {
            return Err(CoreError::SpaceRelayMailboxInvalid);
        }
        let local_fingerprint = self.identity.fingerprint();
        if !created.reducer.can_manage_space(&local_fingerprint) {
            return Err(CoreError::SpaceControlRejected(
                space::RejectReason::Unauthorized,
            ));
        }
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (parents, lamport) = resolve_policy_parents(&self.store, policy)?;
        let parent_ids = parents
            .iter()
            .map(|parent| *parent.as_bytes())
            .collect::<Vec<_>>();
        let group_id = created.group_id.clone();
        let space_id = created.space_id;
        let group_reference = created.group_reference;
        let reducer = created.reducer.clone();
        let credential_trust_policy = self.credential_trust_policy.clone();
        let credential = credential.clone();
        let (event_id, mailbox) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                let mut group = GroupState::load_with_trust_policy(
                    provider,
                    &group_id,
                    &credential_trust_policy,
                )?;
                let active_members = reducer
                    .policy()
                    .ok_or(CoreError::SpaceRelayMailboxInvalid)?
                    .members
                    .iter()
                    .filter(|member| member.status == space::MemberStatus::Active)
                    .collect::<Vec<_>>();
                if group.group_reference() != group_reference
                    || group.epoch() == 0
                    || active_members.len() < 2
                    || group.member_count() != active_members.len()
                    || active_members
                        .iter()
                        .any(|member| !group.contains_member_identity(&member.fingerprint))
                    || !reducer.can_manage_space(&identity.fingerprint())
                {
                    return Err(CoreError::SpaceRelayMailboxRequiresAdmission);
                }

                let mailbox = load_or_create_relay_mailbox_in_transaction(
                    transaction,
                    &space_id,
                    &group_reference,
                )?;
                let plaintext = encode_relay_mailbox_control(mailbox)?;
                let protected =
                    group.encrypt_application(provider, identity, &credential, &plaintext)?;
                let sequence = Store::next_author_sequence_in_transaction(
                    transaction,
                    &identity.fingerprint(),
                )?;
                let event = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id,
                        channel_id: None,
                        author_sequence: sequence,
                        lamport,
                        wall_time_hint: now_unix_millis,
                        parents: parents.clone(),
                        kind: EventKind::RelayMailboxControl,
                        protected_body: protected.as_bytes().to_vec(),
                        mls_group_reference: group_reference,
                        mls_epoch: group.epoch(),
                    },
                )?;
                reducer
                    .authorize_relay_mailbox_control(&event)
                    .map_err(CoreError::SpaceControlRejected)?;
                if let CommitOutcome::Equivocation { existing_event_id } =
                    Store::commit_authored_with_outbox_in_transaction(
                        transaction,
                        *event.author_fingerprint(),
                        *event.event_id().as_bytes(),
                        sequence,
                        event.encoded_bytes(),
                        &parent_ids,
                        event.encoded_bytes(),
                        0,
                    )?
                {
                    return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
                }
                Ok((*event.event_id().as_bytes(), mailbox))
            })?;
        Ok(PublishedSpaceRelayMailbox { event_id, mailbox })
    }
}

fn load_or_create_relay_mailbox_in_transaction(
    transaction: &Transaction<'_>,
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
) -> Result<MailboxToken, CoreError> {
    if let Some(ciphertext) =
        Store::load_space_relay_mailbox_in_transaction(transaction, space_id, group_reference)?
    {
        return decode_protected_relay_mailbox(space_id, group_reference, &ciphertext);
    }

    let mut random = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut random[..]).map_err(|_| CoreError::SpaceRelayMailboxRandomness)?;
    let candidate = MailboxToken::from_bytes(*random);
    let context = relay_mailbox_context(space_id, group_reference);
    let encrypted = lattice_mls::protect_local_record(&context, candidate.as_bytes())?;
    if Store::insert_space_relay_mailbox_in_transaction(
        transaction,
        space_id,
        group_reference,
        &encrypted,
    )? {
        Ok(candidate)
    } else {
        let persisted =
            Store::load_space_relay_mailbox_in_transaction(transaction, space_id, group_reference)?
                .ok_or(CoreError::SpaceRelayMailboxInvalid)?;
        decode_protected_relay_mailbox(space_id, group_reference, &persisted)
    }
}

struct LocalApplicationEvent<'a> {
    group_id: Vec<u8>,
    credential: &'a DeviceCredentialInput,
    reducer: &'a space::SpaceReducer,
    space_id: space::SpaceId,
    group_reference: space::GroupReference,
    channel_id: space::EntityId,
    parents: Vec<lattice_protocol::EventId>,
    lamport: u64,
    plaintext: Vec<u8>,
    cached_text: Option<(Option<[u8; 32]>, &'a str)>,
    event_kind: EventKind,
}

struct CachedTextProjection<'a> {
    event_kind: EventKind,
    target: Option<[u8; 32]>,
    content: &'a str,
    source_event_id: [u8; 32],
    space_id: space::SpaceId,
    group_reference: space::GroupReference,
    channel_id: space::EntityId,
    author_id: [u8; 32],
    author_sequence: u64,
    lamport: u64,
}

fn resolve_policy_parents(
    store: &Store,
    policy: &space::SpacePolicy,
) -> Result<(Vec<lattice_protocol::EventId>, u64), CoreError> {
    let mut parent_ids = policy.heads.clone();
    parent_ids.sort_unstable();
    let mut maximum_lamport = 0;
    for parent_id in &parent_ids {
        let record = store
            .load_event(parent_id)?
            .ok_or(CoreError::SpaceParentEventMissing)?;
        let parent = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
        if parent.event_id().as_bytes() != parent_id
            || parent.space_id() != &policy.space_id
            || parent.mls_group_reference() != &policy.group_reference
        {
            return Err(CoreError::SpaceParentEventMissing);
        }
        maximum_lamport = maximum_lamport.max(parent.lamport());
    }
    let lamport = maximum_lamport
        .checked_add(1)
        .ok_or(CoreError::SpaceLamportExhausted)?;
    Ok((
        parent_ids
            .into_iter()
            .map(lattice_protocol::EventId::from_bytes)
            .collect(),
        lamport,
    ))
}
fn resolve_edit_parents(
    store: &Store,
    policy: &space::SpacePolicy,
    channel_id: space::EntityId,
    target: [u8; 32],
) -> Result<(Vec<lattice_protocol::EventId>, u64), CoreError> {
    let (mut parents, base_lamport) = resolve_policy_parents(store, policy)?;
    let record = store
        .load_event(&target)?
        .ok_or(CoreError::SpaceParentEventMissing)?;
    let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
    if event.event_id().as_bytes() != &target
        || event.space_id() != &policy.space_id
        || event.mls_group_reference() != &policy.group_reference
        || event.channel_id() != Some(&channel_id)
        || event.kind() != EventKind::Message
    {
        return Err(CoreError::SpaceParentEventMissing);
    }
    parents.push(lattice_protocol::EventId::from_bytes(target));
    let lamport = base_lamport
        .saturating_sub(1)
        .max(event.lamport())
        .checked_add(1)
        .ok_or(CoreError::SpaceLamportExhausted)?;
    Ok((parents, lamport))
}
fn encode_text_reply(thread_root: [u8; 32], content: &str) -> Result<Vec<u8>, CoreError> {
    if content.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    let rich_text = space::rich_text::RichText::parse(content).map_err(rich_text_send_error)?;
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(3)),
        (1, Value::Text(content.to_owned())),
        (2, Value::Bytes(thread_root.to_vec())),
        (3, Value::Bool(false)),
        (4, Value::Array(Vec::new())),
        (5, Value::Array(Vec::new())),
        (6, rich_text.spans_value()),
    ]))?;
    if plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    Ok(plaintext)
}
fn encode_text_message(content: &str) -> Result<Vec<u8>, CoreError> {
    encode_text_message_with_mentions(content, &[])
}

fn encode_text_message_with_mentions(
    content: &str,
    mentions: &[space::MentionTarget],
) -> Result<Vec<u8>, CoreError> {
    if content.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    if mentions.len() > space::MAX_MESSAGE_MENTIONS {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::LimitExceeded),
        ));
    }
    if mentions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::InvalidValue),
        ));
    }
    let mention_values = mentions
        .iter()
        .map(|mention| match mention {
            space::MentionTarget::Identity(fingerprint) => {
                Value::Array(vec![Value::Unsigned(0), Value::Bytes(fingerprint.to_vec())])
            }
            space::MentionTarget::Role(role_id) => {
                Value::Array(vec![Value::Unsigned(1), Value::Bytes(role_id.to_vec())])
            }
        })
        .collect();
    let rich_text = space::rich_text::RichText::parse(content).map_err(rich_text_send_error)?;
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(3)),
        (1, Value::Text(content.to_owned())),
        (2, Value::Null),
        (3, Value::Bool(false)),
        (4, Value::Array(Vec::new())),
        (5, Value::Array(mention_values)),
        (6, rich_text.spans_value()),
    ]))?;
    if plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    Ok(plaintext)
}
fn encode_text_tombstone(target: [u8; 32]) -> Result<Vec<u8>, CoreError> {
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Bytes(target.to_vec())),
        (2, Value::Unsigned(0)),
        (3, Value::Null),
    ]))
    .map_err(Into::into)
}
fn encode_text_reaction(
    target: [u8; 32],
    token: &str,
    add: bool,
    tag: Option<[u8; 32]>,
) -> Result<Vec<u8>, CoreError> {
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Bytes(target.to_vec())),
        (2, Value::Text(token.to_owned())),
        (3, Value::Unsigned(u64::from(!add))),
        (
            4,
            tag.map_or(Value::Null, |value| Value::Bytes(value.to_vec())),
        ),
    ]))
    .map_err(Into::into)
}

fn encode_text_pin(
    target: [u8; 32],
    add: bool,
    tag: Option<[u8; 32]>,
) -> Result<Vec<u8>, CoreError> {
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Bytes(target.to_vec())),
        (2, Value::Bool(add)),
        (
            3,
            tag.map_or(Value::Null, |value| Value::Bytes(value.to_vec())),
        ),
    ]))
    .map_err(Into::into)
}
fn encode_text_edit(target: [u8; 32], content: &str) -> Result<Vec<u8>, CoreError> {
    if content.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    let rich_text = space::rich_text::RichText::parse(content).map_err(rich_text_send_error)?;
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(2)),
        (1, Value::Bytes(target.to_vec())),
        (2, Value::Text(content.to_owned())),
        (3, rich_text.spans_value()),
    ]))?;
    if plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    Ok(plaintext)
}
fn rich_text_send_error(error: space::rich_text::RichTextError) -> CoreError {
    let reason = match error {
        space::rich_text::RichTextError::InputTooLarge => space::RejectReason::PayloadTooLarge,
        space::rich_text::RichTextError::TooManySpans => space::RejectReason::LimitExceeded,
        space::rich_text::RichTextError::InvalidWireSpans => space::RejectReason::InvalidValue,
    };
    CoreError::SpaceMessageRejected(space::EventAuthorization::Rejected(reason))
}

fn encode_file_manifest(manifest: &AttachmentManifest) -> Result<Vec<u8>, CoreError> {
    let chunk_hashes = manifest
        .chunk_hashes
        .iter()
        .map(|hash| Value::Bytes(hash.to_vec()))
        .collect();
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Text(manifest.filename.clone())),
        (
            2,
            manifest
                .mime_type
                .as_ref()
                .map_or(Value::Null, |mime| Value::Text(mime.clone())),
        ),
        (3, Value::Unsigned(manifest.file_size)),
        (4, Value::Bytes(manifest.file_hash.to_vec())),
        (5, Value::Array(chunk_hashes)),
    ]))?;
    if plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    Ok(plaintext)
}

fn current_wall_time_hint() -> Result<u64, CoreError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::SpaceWallClockInvalid)?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| CoreError::SpaceWallClockInvalid)
}
fn queue_application_event_in_transaction(
    identity: &DeviceIdentity,
    provider: &ProtectedSqliteProvider<'_>,
    transaction: &Transaction<'_>,
    credential_trust_policy: &CredentialTrustPolicy,
    message: LocalApplicationEvent<'_>,
) -> Result<([u8; 32], space::SpaceReducer), CoreError> {
    let mut group =
        GroupState::load_with_trust_policy(provider, &message.group_id, credential_trust_policy)?;

    let policy = message
        .reducer
        .policy()
        .ok_or(CoreError::SpaceGenesisRejected(
            space::RejectReason::MissingPolicy,
        ))?;
    let mut active_members = policy
        .members
        .iter()
        .filter(|member| member.status == space::MemberStatus::Active);
    if group.group_reference() != message.group_reference
        || group.member_count() != active_members.clone().count()
        || active_members.any(|member| !group.contains_member_identity(&member.fingerprint))
    {
        return Err(CoreError::SpaceGenesisRejected(
            space::RejectReason::WrongGeneration,
        ));
    }
    let protected =
        group.encrypt_application(provider, identity, message.credential, &message.plaintext)?;
    let sequence =
        Store::next_author_sequence_in_transaction(transaction, &identity.fingerprint())?;
    let event = VerifiedSignatureOnlyEvent::create(
        identity,
        EventDraft {
            space_id: message.space_id,
            channel_id: Some(message.channel_id),
            author_sequence: sequence,
            lamport: message.lamport,
            wall_time_hint: current_wall_time_hint()?,
            parents: message.parents,
            kind: message.event_kind,
            protected_body: protected.as_bytes().to_vec(),
            mls_group_reference: message.group_reference,
            mls_epoch: group.epoch(),
        },
    )?;
    let bound = MlsBoundEvent {
        event: event.clone(),
        plaintext: message.plaintext,
    };
    let mut staged_reducer = message.reducer.clone();
    let authorization = staged_reducer.authorize_application_event(&bound);
    if !matches!(authorization, space::EventAuthorization::Authorized { .. }) {
        return Err(CoreError::SpaceMessageRejected(authorization));
    }
    let parent_ids = event
        .parents()
        .iter()
        .map(|parent| *parent.as_bytes())
        .collect::<Vec<_>>();
    if let CommitOutcome::Equivocation { existing_event_id } =
        Store::commit_authored_with_outbox_in_transaction(
            transaction,
            *event.author_fingerprint(),
            *event.event_id().as_bytes(),
            sequence,
            event.encoded_bytes(),
            &parent_ids,
            event.encoded_bytes(),
            0,
        )?
    {
        return Err(CoreError::ReceivedEventEquivocation { existing_event_id });
    }
    if let Some((target, content)) = message.cached_text {
        persist_cached_text_projection(
            transaction,
            &CachedTextProjection {
                event_kind: message.event_kind,
                target,
                content,
                source_event_id: *event.event_id().as_bytes(),
                space_id: message.space_id,
                group_reference: message.group_reference,
                channel_id: message.channel_id,
                author_id: *event.author_fingerprint(),
                author_sequence: sequence,
                lamport: event.lamport(),
            },
        )?;
    }
    if message.event_kind == EventKind::Tombstone {
        let target = decode_tombstone_target(bound.plaintext())?;
        Store::delete_cached_space_message_in_transaction(
            transaction,
            &target,
            &message.space_id,
            &message.group_reference,
            &message.channel_id,
        )?;
    }
    Ok((*event.event_id().as_bytes(), staged_reducer))
}

fn persist_cached_text_projection(
    transaction: &Transaction<'_>,
    projection: &CachedTextProjection<'_>,
) -> Result<(), CoreError> {
    let (event_id, is_update) = match (projection.event_kind, projection.target) {
        (EventKind::Message, None) => (projection.source_event_id, false),
        (EventKind::Edit, Some(target)) => (target, true),
        _ => return Err(CoreError::LocalSpaceMessageCacheInvalid),
    };
    let plaintext = encode_text_message(projection.content)?;
    let context = local_text_message_context(
        &projection.space_id,
        &projection.group_reference,
        &projection.channel_id,
        &event_id,
    );
    let encrypted_content = lattice_mls::protect_local_record(&context, &plaintext)?;
    if is_update {
        Store::replace_cached_space_message_content_in_transaction(
            transaction,
            &event_id,
            &projection.space_id,
            &projection.group_reference,
            &projection.channel_id,
            &encrypted_content,
        )?;
    } else {
        Store::save_cached_space_message_in_transaction(
            transaction,
            &CachedSpaceMessage {
                event_id,
                space_id: projection.space_id,
                group_reference: projection.group_reference,
                channel_id: projection.channel_id,
                author_id: projection.author_id,
                author_seq: projection.author_sequence,
                lamport: projection.lamport,
                encrypted_content,
                outbox_state: None,
            },
        )?;
    }
    Ok(())
}

fn persist_received_text_projection(
    transaction: &Transaction<'_>,
    bound: &MlsBoundEvent,
    space_id: space::SpaceId,
    group_reference: space::GroupReference,
) -> Result<(), CoreError> {
    let event = bound.event();
    let Some(channel_id) = event.channel_id().copied() else {
        return if matches!(
            event.kind(),
            EventKind::Message | EventKind::Edit | EventKind::Tombstone
        ) {
            Err(CoreError::LocalSpaceMessageCacheInvalid)
        } else {
            Ok(())
        };
    };
    if event.kind() == EventKind::Tombstone {
        let target = decode_tombstone_target(bound.plaintext())?;
        Store::delete_cached_space_message_in_transaction(
            transaction,
            &target,
            &space_id,
            &group_reference,
            &channel_id,
        )?;
        return Ok(());
    }
    let (event_kind, target, content) = match event.kind() {
        EventKind::Message => (
            EventKind::Message,
            None,
            decode_text_message(bound.plaintext())?,
        ),
        EventKind::Edit => {
            let (target, content) = decode_text_edit(bound.plaintext())?;
            if !Store::has_cached_space_message_in_transaction(
                transaction,
                &target,
                &space_id,
                &group_reference,
                &channel_id,
            )? {
                return Ok(());
            }
            (EventKind::Edit, Some(target), content)
        }
        _ => return Ok(()),
    };
    persist_cached_text_projection(
        transaction,
        &CachedTextProjection {
            event_kind,
            target,
            content: &content,
            source_event_id: *event.event_id().as_bytes(),
            space_id,
            group_reference,
            channel_id,
            author_id: *event.author_fingerprint(),
            author_sequence: event.author_sequence(),
            lamport: event.lamport(),
        },
    )
}

fn load_or_create_mls_storage_key<P: PrivateKeyProtector>(
    store: &mut Store,
    protector: &P,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if let Some(ciphertext) = store.load_protected_mls_storage_key()? {
        return unwrap_mls_storage_key(protector, &ciphertext);
    }

    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut key[..]).map_err(|_| CoreError::MlsStorageKeyRandomness)?;
    let ciphertext = protector.wrap(&key[..]).map_err(IdentityError::from)?;
    if store.save_protected_mls_storage_key(&ciphertext)? {
        return Ok(key);
    }

    let persisted = store
        .load_protected_mls_storage_key()?
        .ok_or(CoreError::MlsStorageKeyInvalid)?;
    unwrap_mls_storage_key(protector, &persisted)
}

fn unwrap_mls_storage_key<P: PrivateKeyProtector>(
    protector: &P,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let plaintext = Zeroizing::new(protector.unwrap(ciphertext).map_err(IdentityError::from)?);
    let mut key = Zeroizing::new([0_u8; 32]);
    if plaintext.len() != key.len() {
        return Err(CoreError::MlsStorageKeyInvalid);
    }
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use super::space::ephemeral::{
        EphemeralApplyResult, EphemeralKind, EphemeralStateTable, EphemeralUpdate,
    };
    use super::{
        Client, CoreError, CreatedSpace, DirectMessageIngressOutcome, InitialChannel,
        MlsBoundEvent, QueuedMessage, bind_mls_application,
    };
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::{
        DeviceIdentity, IdentityError, IdentityPublicBundle, PinnedIdentity,
        PrivateKeyProtectionError, PrivateKeyProtector,
    };
    use lattice_mls::api::{DeviceCredentialInput, GroupState, IncomingResult};
    use lattice_storage::OutboxState;
    use openmls::credentials::Credential;
    use openmls::prelude::CredentialType;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestDatabase(std::path::PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            let sequence = NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lattice-core-{}-{sequence}.sqlite",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    /// Test-only passthrough; it is not suitable for real identity persistence.
    struct TestProtector;

    impl PrivateKeyProtector for TestProtector {
        fn wrap(&self, private_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(private_material.to_vec())
        }

        fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(ciphertext.to_vec())
        }
    }

    fn test_credential(identity: &DeviceIdentity) -> DeviceCredentialInput {
        let credential = Credential::new(
            CredentialType::X509,
            b"test-only untrusted X.509 placeholder".to_vec(),
        );
        DeviceCredentialInput::from_untrusted_x509_credential_for_tests(identity, &credential)
            .expect("device signer matches test credential")
    }

    fn event(
        identity: &DeviceIdentity,
        body: Vec<u8>,
        epoch: u64,
        group_reference: [u8; 32],
    ) -> VerifiedSignatureOnlyEvent {
        VerifiedSignatureOnlyEvent::create(
            identity,
            EventDraft {
                space_id: [1; 16],
                channel_id: None,
                author_sequence: 1,
                lamport: 1,
                wall_time_hint: 0,
                parents: Vec::new(),
                kind: EventKind::Message,
                protected_body: body,
                mls_group_reference: group_reference,
                mls_epoch: epoch,
            },
        )
        .expect("event signature created")
    }

    fn encrypted_application_event(
        client: &mut Client,
        group_id: &[u8],
        credential: &DeviceCredentialInput,
        mut draft: EventDraft,
        plaintext: &[u8],
    ) -> VerifiedSignatureOnlyEvent {
        draft.protected_body = client
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, group_id)?;
                let ciphertext =
                    group.encrypt_application(provider, identity, credential, plaintext)?;
                Ok::<_, CoreError>(ciphertext.as_bytes().to_vec())
            })
            .expect("encrypt remote application event");
        VerifiedSignatureOnlyEvent::create(&client.identity, draft)
            .expect("sign remote application event")
    }

    fn deliver_remote_application(
        sender: &mut Client,
        receiver: &mut Client,
        receiver_space: &mut super::CreatedSpace,
        group_id: &[u8],
        credential: &DeviceCredentialInput,
        draft: EventDraft,
        plaintext: &[u8],
    ) -> [u8; 32] {
        let event = encrypted_application_event(sender, group_id, credential, draft, plaintext);
        let event_id = *event.event_id().as_bytes();
        assert_eq!(
            receiver
                .accept_synced_application_event(receiver_space, event.encoded_bytes())
                .expect("accept remote application event"),
            super::SyncedApplicationOutcome::Accepted { event_id }
        );
        event_id
    }

    #[test]
    fn message_and_edit_wire_spans_round_trip_and_reject_mismatches() {
        use lattice_protocol::Value;

        let source = "**safe**";
        let message = super::encode_text_message(source).expect("encode message v3");
        assert_eq!(super::decode_text_message(&message).unwrap(), source);
        let Value::Map(message_fields) =
            super::decode_canonical(&message).expect("decode canonical message")
        else {
            panic!("encoded message is a map");
        };
        assert_eq!(message_fields[0], (0, Value::Unsigned(3)));
        assert_eq!(
            message_fields[6].1,
            Value::Array(vec![Value::Array(vec![
                Value::Unsigned(0),
                Value::Unsigned(0),
                Value::Unsigned(4),
            ])])
        );

        let edit = super::encode_text_edit([7; 32], "edit *it*").expect("encode edit v2");
        let (target, content) = super::decode_text_edit(&edit).expect("decode edit");
        assert_eq!(target, [7; 32]);
        assert_eq!(content, "edit *it*");
        let Value::Map(mut edit_fields) =
            super::decode_canonical(&edit).expect("decode canonical edit")
        else {
            panic!("encoded edit is a map");
        };
        assert_eq!(edit_fields[0], (0, Value::Unsigned(2)));
        edit_fields[3].1 = Value::Array(Vec::new());
        let mismatched = super::encode_canonical(&Value::Map(edit_fields))
            .expect("encode mismatched span value");
        assert!(matches!(
            super::decode_text_edit(&mismatched),
            Err(CoreError::LocalSpaceMessageCacheInvalid)
        ));
    }

    #[test]
    fn peer_pin_requires_full_fingerprint_and_survives_restart() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let peer = DeviceIdentity::generate().expect("peer identity");
        let bundle = peer.public_bundle();
        let fingerprint = bundle.fingerprint();
        {
            let mut client =
                Client::open_or_create(&database.0, &protector).expect("initialize client");
            let pinned = client
                .pin_identity(&bundle.to_bytes(), fingerprint)
                .expect("pin exact bundle");
            assert_eq!(pinned.bundle(), bundle);
            assert_eq!(
                client.pinned_identity(&fingerprint).expect("load pin"),
                Some(pinned)
            );

            let mut wrong_fingerprint = fingerprint;
            wrong_fingerprint[0] ^= 1;
            assert!(matches!(
                client.pin_identity(&bundle.to_bytes(), wrong_fingerprint),
                Err(CoreError::Identity(IdentityError::FingerprintMismatch))
            ));

            let mut changed_bundle_bytes = bundle.to_bytes();
            changed_bundle_bytes[33] ^= 1;
            let changed_x25519 = IdentityPublicBundle::from_bytes(&changed_bundle_bytes)
                .expect("changed public bundle");
            assert!(matches!(
                client.pin_identity(&changed_x25519.to_bytes(), fingerprint),
                Err(CoreError::Identity(IdentityError::FingerprintMismatch))
            ));
            assert_eq!(
                client
                    .pinned_identity(&fingerprint)
                    .expect("original pin remains"),
                Some(pinned)
            );
        }
        let client = Client::open_existing(&database.0, &protector).expect("reopen client");
        assert_eq!(
            client
                .pinned_identity(&fingerprint)
                .expect("pin survives restart"),
            Some(
                PinnedIdentity::from_verified_fingerprint(bundle, fingerprint)
                    .expect("matching fingerprint")
            )
        );
    }

    #[test]
    fn unpin_revokes_local_trust_and_survives_restart() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let peer = DeviceIdentity::generate().expect("peer identity");
        let bundle = peer.public_bundle();
        let fingerprint = bundle.fingerprint();
        {
            let mut client =
                Client::open_or_create(&database.0, &protector).expect("initialize client");
            client
                .pin_identity(&bundle.to_bytes(), fingerprint)
                .expect("pin verified peer");
            assert!(
                client
                    .unpin_identity(&fingerprint)
                    .expect("remove local trust")
            );
            assert_eq!(
                client
                    .pinned_identity(&fingerprint)
                    .expect("revoked pin lookup"),
                None
            );
            assert!(
                !client
                    .unpin_identity(&fingerprint)
                    .expect("repeat removal is idempotent")
            );
        }

        let client = Client::open_existing(&database.0, &protector).expect("reopen client");
        assert_eq!(
            client
                .pinned_identity(&fingerprint)
                .expect("revoked pin remains absent"),
            None
        );
    }

    #[test]
    fn modified_pinned_bundle_is_rejected_on_lookup() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let peer = DeviceIdentity::generate().expect("peer identity");
        let bundle = peer.public_bundle();
        let fingerprint = bundle.fingerprint();
        {
            let mut client =
                Client::open_or_create(&database.0, &protector).expect("initialize client");
            client
                .pin_identity(&bundle.to_bytes(), fingerprint)
                .expect("pin exact bundle");
        }

        let mut changed_bundle = bundle.to_bytes();
        changed_bundle[33] ^= 1;
        let connection =
            rusqlite::Connection::open(&database.0).expect("open pin database directly");
        connection
            .execute(
                "UPDATE trusted_identities SET public_bundle = ?1 WHERE fingerprint = ?2",
                rusqlite::params![&changed_bundle[..], &fingerprint[..]],
            )
            .expect("alter stored bundle");
        drop(connection);

        let client = Client::open_existing(&database.0, &protector).expect("reopen client");
        assert!(matches!(
            client.pinned_identity(&fingerprint),
            Err(CoreError::Identity(IdentityError::FingerprintMismatch))
        ));
    }

    #[test]
    fn mls_binding_rejects_wrong_author_and_ciphertext_before_releasing_plaintext() {
        let provider_alice = OpenMlsRustCrypto::default();
        let provider_bob = OpenMlsRustCrypto::default();
        let alice_identity = DeviceIdentity::generate().expect("Alice identity");
        let bob_identity = DeviceIdentity::generate().expect("Bob identity");
        let alice_credential = test_credential(&alice_identity);
        let bob_credential = test_credential(&bob_identity);
        let mut alice = GroupState::create(&provider_alice, &alice_identity, &alice_credential)
            .expect("create group");
        let bob_key_package =
            GroupState::publish_key_package(&provider_bob, &bob_identity, &bob_credential)
                .expect("publish Bob key package");
        let prepared = alice
            .prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                bob_key_package.as_bytes(),
            )
            .expect("prepare Bob add");
        let commit = prepared.commit().as_bytes().to_vec();
        let welcome = alice
            .accept_prepared_add(&provider_alice, &prepared, &commit)
            .expect("merge accepted add");
        let mut bob = GroupState::from_welcome(
            &provider_bob,
            &alice.group_id(),
            &alice_credential,
            welcome.as_bytes(),
        )
        .expect("join group");
        let wire = alice
            .encrypt_application(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                b"authenticated event plaintext",
            )
            .expect("encrypt event payload")
            .as_bytes()
            .to_vec();
        let proof = match bob
            .process_incoming(&provider_bob, &wire)
            .expect("process MLS application")
        {
            IncomingResult::Application(proof) => proof,
            other => panic!("expected application result, got {other:?}"),
        };

        let group_reference = alice.group_reference();
        let mut altered_wire = wire.clone();
        altered_wire[0] ^= 1;
        assert!(matches!(
            bind_mls_application(
                event(&alice_identity, altered_wire, 1, group_reference),
                proof.clone()
            ),
            Err(CoreError::MlsEventBindingFailed)
        ));
        assert!(matches!(
            bind_mls_application(
                event(&bob_identity, wire.clone(), 1, group_reference),
                proof.clone()
            ),
            Err(CoreError::MlsEventBindingFailed)
        ));
        assert!(matches!(
            bind_mls_application(
                event(&alice_identity, wire.clone(), 2, group_reference),
                proof.clone()
            ),
            Err(CoreError::MlsEventBindingFailed)
        ));
        assert!(matches!(
            bind_mls_application(
                event(&alice_identity, wire.clone(), 1, [9; 32]),
                proof.clone()
            ),
            Err(CoreError::MlsEventBindingFailed)
        ));

        let fingerprint_mismatch_proof =
            proof.clone().with_test_member_identity_fingerprint([9; 32]);
        assert!(matches!(
            bind_mls_application(
                event(&alice_identity, wire.clone(), 1, group_reference),
                fingerprint_mismatch_proof
            ),
            Err(CoreError::MlsEventBindingFailed)
        ));

        let bound = bind_mls_application(event(&alice_identity, wire, 1, group_reference), proof)
            .expect("matching event and MLS proof bind");
        assert_eq!(bound.plaintext(), b"authenticated event plaintext");
        assert_eq!(
            bound.event().identity_bundle().ed25519_public_key(),
            alice_identity.public_key()
        );
    }

    #[test]
    fn local_file_manifest_is_authorized_encrypted_and_queued() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;
        let content = b"attachment bytes";
        let mut reader = std::io::Cursor::new(content);
        let manifest = lattice_files::AttachmentManifest::from_reader(
            &mut reader,
            "shared.txt",
            Some("text/plain"),
        )
        .expect("build attachment manifest");
        let mut invalid_manifest = manifest.clone();
        invalid_manifest.filename = "../unsafe.txt".to_owned();
        assert!(matches!(
            client.queue_file_manifest(&mut created, &credential, channel_id, &invalid_manifest),
            Err(CoreError::Attachment(
                lattice_files::AttachmentError::InvalidFilenameHint
            ))
        ));
        assert!(
            client
                .store
                .list_outbox_page(None, 10)
                .expect("read outbox after invalid manifest")
                .is_empty()
        );

        let receipt = client
            .queue_file_manifest(&mut created, &credential, channel_id, &manifest)
            .expect("queue authorized attachment manifest");
        let event_id = *receipt.event_id();
        let stored = client
            .store
            .load_event(&event_id)
            .expect("load signed manifest event")
            .expect("manifest event stored");
        let event = VerifiedSignatureOnlyEvent::decode_verify(&stored.canonical_bytes)
            .expect("verify signed event");
        assert_eq!(event.kind(), EventKind::FileManifest);
        let authorized = created
            .reducer()
            .authorized_attachment_manifest(&event_id)
            .expect("manifest authorized by the local Space policy");
        assert_eq!(authorized.manifest(), &manifest);
        let outbox = client
            .store
            .list_outbox_page(None, 10)
            .expect("read queued attachment event");
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].event_id, event_id);
        assert_eq!(outbox[0].envelope_bytes, stored.canonical_bytes);
        assert_ne!(outbox[0].envelope_bytes.as_slice(), content);
    }
    #[test]
    fn local_text_message_is_policy_checked_and_queued_atomically() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;

        assert!(matches!(
            client.queue_text_message(&mut created, &credential, [0xEE; 16], "rejected"),
            Err(CoreError::SpaceMessageRejected(
                super::space::EventAuthorization::Rejected(
                    super::space::RejectReason::UnknownEntity
                )
            ))
        ));
        assert!(
            client
                .store
                .list_outbox_page(None, 10)
                .expect("read outbox after rejection")
                .is_empty()
        );
        assert!(
            client
                .local_text_message_history(
                    created.space_id(),
                    created.group_reference(),
                    &channel_id
                )
                .expect("empty message history after denied send")
                .is_empty()
        );

        let receipt = client
            .queue_text_message(&mut created, &credential, channel_id, "**queued offline**")
            .expect("queue authorized local message");
        let event_id = *receipt.event_id();
        let event = client
            .store
            .load_event(&event_id)
            .expect("load committed message event")
            .expect("event persisted");
        let verified_event = VerifiedSignatureOnlyEvent::decode_verify(&event.canonical_bytes)
            .expect("verify stored event signature");
        assert_eq!(verified_event.kind(), EventKind::Message);
        let message_history = created.reducer().message_history(&channel_id);
        let current_version = message_history.messages()[0].current_version();
        assert_eq!(current_version.content.as_ref(), "queued offline");
        assert_eq!(
            current_version.rich_text.spans(),
            &[super::space::rich_text::RichTextSpan {
                start: 0,
                end: 14,
                style: super::space::rich_text::RichTextStyle::Strong,
            }]
        );
        let history = client
            .local_text_message_history(created.space_id(), created.group_reference(), &channel_id)
            .expect("read authorized local history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_id, event_id);
        assert_eq!(history[0].content, "queued offline");
        assert_eq!(history[0].outbox_state, Some(OutboxState::Queued));
        let queued = client
            .store
            .list_outbox_page(None, 10)
            .expect("read committed outbox");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].event_id, event_id);
        assert_eq!(queued[0].state, OutboxState::Queued);
        assert_eq!(queued[0].envelope_bytes, event.canonical_bytes);
        assert_eq!(
            client.outbox_page(None, 10).expect("read Core outbox page"),
            queued
        );

        drop(client);
        let mut reopened = Client::open_existing(&database.0, &protector).expect("reopen profile");
        let outbox = reopened
            .store
            .list_outbox_page(None, 10)
            .expect("restore queued status after restart");
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].event_id, event_id);
        assert_eq!(outbox[0].state, OutboxState::Queued);
        let history = reopened
            .local_text_message_history(created.space_id(), created.group_reference(), &channel_id)
            .expect("restore local history after restart");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "queued offline");
        assert_eq!(history[0].event_id, event_id);
    }

    #[test]
    fn stable_mentions_resolve_and_local_mutes_survive_restart() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;
        let target = super::space::MentionTarget::Identity(client.identity.fingerprint());

        assert!(matches!(
            client.queue_text_message_with_mentions(
                &mut created,
                &credential,
                channel_id,
                "unknown role",
                &[super::space::MentionTarget::Role([0xE1; 16])],
            ),
            Err(CoreError::SpaceMessageRejected(
                super::space::EventAuthorization::Rejected(
                    super::space::RejectReason::UnknownEntity
                )
            ))
        ));

        assert!(matches!(
            client.queue_text_message_with_mentions(
                &mut created,
                &credential,
                channel_id,
                "unsorted mentions",
                &[
                    super::space::MentionTarget::Identity([0xFF; 32]),
                    super::space::MentionTarget::Identity([0x00; 32]),
                ],
            ),
            Err(CoreError::SpaceMessageRejected(
                super::space::EventAuthorization::Rejected(
                    super::space::RejectReason::InvalidValue
                )
            ))
        ));
        client
            .queue_text_message_with_mentions(
                &mut created,
                &credential,
                channel_id,
                "stable target",
                &[target],
            )
            .expect("queue stable identity mention");
        assert_eq!(
            created.reducer().message_history(&channel_id).messages()[0].mentions,
            vec![target]
        );
        assert!(client.should_notify_for_mentions(&[target]).unwrap());

        client
            .set_mention_muted(target, true)
            .expect("persist local mute");
        let encrypted = client
            .store
            .load_local_mention_preferences()
            .expect("read encrypted preferences")
            .expect("preference row exists");
        assert!(
            !encrypted
                .windows(32)
                .any(|window| window == client.identity.fingerprint())
        );
        assert!(!client.should_notify_for_mentions(&[target]).unwrap());

        drop(client);
        let mut reopened = Client::open_existing(&database.0, &protector).expect("reopen profile");
        assert!(!reopened.should_notify_for_mentions(&[target]).unwrap());
        reopened
            .set_mention_muted(target, false)
            .expect("remove local mute");
        assert!(reopened.should_notify_for_mentions(&[target]).unwrap());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Keep the expiry/replay lifecycle assertions together.
    fn ephemeral_state_is_bounded_replay_safe_and_expires() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let reducer = created.reducer();
        let now = Instant::now();
        let make_event = |sequence, update: EphemeralUpdate| {
            let event = VerifiedSignatureOnlyEvent::create(
                &client.identity,
                EventDraft {
                    space_id: *created.space_id(),
                    channel_id: None,
                    author_sequence: sequence,
                    lamport: sequence,
                    wall_time_hint: 0,
                    parents: Vec::new(),
                    kind: EventKind::Ephemeral,
                    protected_body: vec![1],
                    mls_group_reference: *created.group_reference(),
                    mls_epoch: 0,
                },
            )
            .expect("sign ephemeral hint");
            MlsBoundEvent {
                event,
                plaintext: update.encode().expect("encode ephemeral payload"),
            }
        };
        let active = EphemeralUpdate {
            kind: EphemeralKind::Presence,
            active: true,
            ttl: Duration::from_secs(5),
        };
        let first = make_event(1, active);
        let mut table = EphemeralStateTable::new();
        assert_eq!(
            table.apply(reducer, &first, now).unwrap(),
            EphemeralApplyResult::Applied
        );
        assert_eq!(
            table.apply(reducer, &first, now).unwrap(),
            EphemeralApplyResult::Duplicate
        );
        assert!(table.is_present(
            reducer,
            client.identity.fingerprint(),
            now + Duration::from_secs(4)
        ));
        let typing = make_event(
            1,
            EphemeralUpdate {
                kind: EphemeralKind::Typing,
                active: true,
                ttl: Duration::from_secs(5),
            },
        );
        assert_eq!(
            table.apply(reducer, &typing, now).unwrap(),
            EphemeralApplyResult::Applied
        );
        assert!(table.is_typing(
            reducer,
            client.identity.fingerprint(),
            now + Duration::from_secs(4),
        ));
        assert!(!table.is_typing(
            reducer,
            client.identity.fingerprint(),
            now + Duration::from_secs(5),
        ));
        assert!(!table.is_present(
            reducer,
            client.identity.fingerprint(),
            now + Duration::from_secs(5)
        ));

        let clear = make_event(
            2,
            EphemeralUpdate {
                kind: EphemeralKind::Presence,
                active: false,
                ttl: Duration::ZERO,
            },
        );
        assert_eq!(
            table
                .apply(reducer, &clear, now + Duration::from_secs(6))
                .unwrap(),
            EphemeralApplyResult::Applied
        );
        assert_eq!(
            table
                .apply(reducer, &first, now + Duration::from_secs(7))
                .unwrap(),
            EphemeralApplyResult::IgnoredStale
        );
        assert!(!table.is_present(
            reducer,
            client.identity.fingerprint(),
            now + Duration::from_secs(7)
        ));
    }

    #[test]
    fn local_text_search_scans_retained_history_and_bounds_matches() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;
        client
            .queue_text_message(
                &mut created,
                &credential,
                channel_id,
                "Needle and shared in the oldest retained message",
            )
            .expect("queue oldest searchable message");
        for index in 0..100 {
            client
                .queue_text_message(
                    &mut created,
                    &credential,
                    channel_id,
                    &format!("Shared record {index}"),
                )
                .expect("queue bounded-cache search record");
        }

        assert!(matches!(
            client.search_local_text_messages(
                created.space_id(),
                created.group_reference(),
                &channel_id,
                "",
            ),
            Err(CoreError::InvalidLocalTextMessageSearch)
        ));
        assert!(matches!(
            client.search_local_text_messages(
                created.space_id(),
                created.group_reference(),
                &channel_id,
                &"x".repeat(super::MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES + 1),
            ),
            Err(CoreError::InvalidLocalTextMessageSearch)
        ));

        let oldest = client
            .search_local_text_messages(
                created.space_id(),
                created.group_reference(),
                &channel_id,
                "NEEDLE",
            )
            .expect("search beyond the newest history page");
        assert_eq!(oldest.scanned_messages, 101);
        assert_eq!(oldest.total_matches, 1);
        assert_eq!(oldest.messages.len(), 1);
        assert_eq!(
            oldest.messages[0].content,
            "Needle and shared in the oldest retained message"
        );

        let shared = client
            .search_local_text_messages(
                created.space_id(),
                created.group_reference(),
                &channel_id,
                "SHARED",
            )
            .expect("search all locally retained messages");
        assert_eq!(shared.scanned_messages, 101);
        assert_eq!(shared.total_matches, 101);
        assert_eq!(shared.messages.len(), super::MAX_LOCAL_TEXT_SEARCH_RESULTS);
        assert_eq!(shared.messages[0].content, "Shared record 0");
        assert_eq!(shared.messages[99].content, "Shared record 99");
    }

    #[test]
    fn local_text_edit_is_authorized_and_survives_profile_restart() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;
        let original = client
            .queue_text_message(&mut created, &credential, channel_id, "original")
            .expect("queue original message");
        let edit = client
            .queue_text_message_edit(
                &mut created,
                &credential,
                channel_id,
                *original.event_id(),
                "edited",
            )
            .expect("queue authorized edit");

        assert_local_edit_projection_and_outbox(&client, &created, &original, &edit, channel_id);

        drop(created);
        drop(credential);
        drop(client);
        let mut reopened = Client::open_existing(&database.0, &protector)
            .expect("reopen local profile after edit");
        let cached_history = reopened
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .expect("read cache after profile reopen");
        assert_eq!(cached_history.len(), 1);
        assert_eq!(cached_history[0].event_id, *original.event_id());
        assert_eq!(cached_history[0].content, "edited");
        let credential = test_credential(&reopened.identity);
        let mut restored = reopened
            .restore_space(&space_id, &group_reference)
            .expect("restore local Space policy");
        let second_edit = reopened
            .queue_text_message_edit(
                &mut restored,
                &credential,
                channel_id,
                *original.event_id(),
                "edited after restart",
            )
            .expect("authorize edit against the authenticated local history cache");
        assert_ne!(second_edit.event_id(), original.event_id());
        assert_ne!(second_edit.event_id(), edit.event_id());
        let history = reopened
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .expect("read updated history after restart edit");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_id, *original.event_id());
        assert_eq!(history[0].content, "edited after restart");
        let deletion = reopened
            .queue_text_message_tombstone(
                &mut restored,
                &credential,
                channel_id,
                *original.event_id(),
            )
            .expect("queue authorized tombstone against authenticated local history");
        assert_ne!(deletion.event_id(), original.event_id());
        assert!(
            reopened
                .local_text_message_history(&space_id, &group_reference, &channel_id)
                .expect("read local history after tombstone")
                .is_empty()
        );
        let message_history = restored.reducer().message_history(&channel_id);
        let projected = message_history
            .messages()
            .iter()
            .find(|message| message.event_id == *original.event_id())
            .expect("retain the immutable message projection");
        assert!(projected.is_deleted());
        let outbox = reopened
            .store
            .list_outbox_page(None, 10)
            .expect("read outbox after restart edit");
        assert_eq!(outbox.len(), 4);
    }

    fn assert_local_edit_projection_and_outbox(
        client: &Client,
        created: &CreatedSpace,
        original: &QueuedMessage,
        edit: &QueuedMessage,
        channel_id: super::space::EntityId,
    ) {
        assert_ne!(original.event_id(), edit.event_id());
        let history = created.reducer().message_history(&channel_id);
        let projected = &history.messages()[0];
        assert_eq!(projected.event_id, *original.event_id());
        assert_eq!(projected.versions().len(), 2);
        assert_eq!(projected.current_version().content.as_ref(), "edited");

        let stored = client
            .store
            .load_event(edit.event_id())
            .expect("read committed edit")
            .expect("edit event persisted");
        let event = VerifiedSignatureOnlyEvent::decode_verify(&stored.canonical_bytes)
            .expect("verify signed edit");
        assert_eq!(event.kind(), EventKind::Edit);
        assert!(
            event
                .parents()
                .iter()
                .any(|parent| parent.as_bytes() == original.event_id())
        );
        let outbox = client
            .store
            .list_outbox_page(None, 10)
            .expect("read local outbox");
        assert_eq!(outbox.len(), 2);
        assert!(
            outbox
                .iter()
                .any(|entry| entry.event_id == *edit.event_id())
        );
    }
    #[test]
    fn tampered_local_message_history_fails_authentication() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;
        let event_id = *client
            .queue_text_message(&mut created, &credential, channel_id, "protected history")
            .expect("queue local message")
            .event_id();
        let connection =
            rusqlite::Connection::open(&database.0).expect("open cache for tamper simulation");
        connection
            .execute(
                "UPDATE cached_space_messages
                 SET encrypted_content = zeroblob(length(encrypted_content))
                 WHERE event_id = ?1",
                rusqlite::params![&event_id[..]],
            )
            .expect("alter authenticated cache ciphertext");
        drop(connection);
        let mut tampered = Client::open_existing(&database.0, &protector)
            .expect("reopen profile with tampered cache row");
        assert!(matches!(
            tampered.local_text_message_history(
                created.space_id(),
                created.group_reference(),
                &channel_id
            ),
            Err(CoreError::MlsStorageCodec(_))
        ));
    }
    #[test]
    fn local_message_queue_rejects_a_stale_genesis_policy_after_mls_advance() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let mut created = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let channel_id = created.reducer().policy().expect("Genesis policy").channels[0].id;
        let group_id = created.group_id().to_vec();

        let bob_identity = DeviceIdentity::generate().expect("generate Bob identity");
        let bob_credential = test_credential(&bob_identity);
        let bob_key_package = GroupState::publish_key_package(
            &OpenMlsRustCrypto::default(),
            &bob_identity,
            &bob_credential,
        )
        .expect("publish Bob KeyPackage")
        .as_bytes()
        .to_vec();
        let (epoch, member_count) = client
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared =
                    group.prepare_add(provider, identity, &credential, &bob_key_package)?;
                let commit = prepared.commit().as_bytes().to_vec();
                group.accept_prepared_add(provider, &prepared, &commit)?;
                Ok::<_, CoreError>((group.epoch(), group.member_count()))
            })
            .expect("advance local MLS generation");
        assert_eq!(epoch, 1);
        assert_eq!(member_count, 2);

        assert!(matches!(
            client.queue_text_message(&mut created, &credential, channel_id, "stale policy"),
            Err(CoreError::SpaceGenesisRejected(
                super::space::RejectReason::WrongGeneration
            ))
        ));
        assert!(
            client
                .store
                .list_outbox_page(None, 10)
                .expect("read outbox after stale-policy rejection")
                .is_empty()
        );
    }

    #[test]
    fn recovery_generation_preserves_space_channels_and_restores_after_restart() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let owner = client.identity.fingerprint();
        let original = client
            .create_space(
                &credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create original generation");
        let original_policy = original.reducer().policy().expect("original policy");
        let original_space_id = *original.space_id();
        let original_group_reference = *original.group_reference();
        let original_channels = original_policy.channels.clone();

        let recovered = client
            .create_space_recovery_generation(&original, &credential)
            .expect("create authorized recovery generation");
        assert_eq!(recovered.space_id(), &original_space_id);
        assert_ne!(recovered.group_reference(), &original_group_reference);
        let recovery_policy = recovered.reducer().policy().expect("recovery policy");
        assert_eq!(recovery_policy.channels, original_channels);
        assert_eq!(recovery_policy.root_author, owner);
        assert_eq!(recovery_policy.revision, 0);
        assert_eq!(original.reducer().policy(), Some(original_policy));
        let recovered_group_reference = *recovered.group_reference();

        drop(recovered);
        drop(original);
        drop(client);
        let mut reopened =
            Client::open_existing(&database.0, &protector).expect("reopen protected profile");
        let restored_recovery = reopened
            .restore_space(&original_space_id, &recovered_group_reference)
            .expect("restore recovery root with prior-policy proof");
        let restored_policy = restored_recovery
            .reducer()
            .policy()
            .expect("restored policy");
        assert_eq!(restored_policy.root_author, owner);
        assert_eq!(restored_policy.channels, original_channels);
        assert_eq!(restored_policy.revision, 0);
        let restored_original = reopened
            .restore_space(&original_space_id, &original_group_reference)
            .expect("restore unchanged original generation");
        assert_eq!(
            restored_original
                .reducer()
                .policy()
                .expect("original restored policy")
                .channels,
            original_channels
        );
    }

    #[test]
    fn openmls_group_and_event_share_a_durable_transaction() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize client");
        let credential = test_credential(&client.identity);
        let mut rolled_back_group_id = None;
        let rolled_back_event_id = [0x41; 32];

        let aborted: Result<(), CoreError> =
            client.with_mls_transaction(|identity, provider, transaction| {
                let group = GroupState::create(provider, identity, &credential)?;
                rolled_back_group_id = Some(group.group_id());
                lattice_storage::Store::commit_authored_in_transaction(
                    transaction,
                    identity.fingerprint(),
                    rolled_back_event_id,
                    1,
                    &[0x01],
                    &[],
                )?;
                Err(CoreError::Mls(lattice_mls::api::MlsError::OpenMlsFailure))
            });
        assert!(matches!(aborted, Err(CoreError::Mls(_))));
        let rolled_back_group_id = rolled_back_group_id.expect("created group before abort");
        let missing_group: Result<(), CoreError> = client.with_mls_transaction(|_, provider, _| {
            GroupState::load(provider, &rolled_back_group_id)
                .map(|_| ())
                .map_err(CoreError::Mls)
        });
        assert!(matches!(
            missing_group,
            Err(CoreError::Mls(lattice_mls::api::MlsError::GroupNotFound))
        ));

        let event_id = [0x42; 32];
        let group_id = client
            .with_mls_transaction(|identity, provider, transaction| {
                let group = GroupState::create(provider, identity, &credential)?;
                let group_id = group.group_id();
                let stored_rows: i64 = transaction
                    .query_row("SELECT COUNT(*) FROM openmls_group_data", [], |row| {
                        row.get(0)
                    })
                    .map_err(lattice_storage::StoreError::from)?;
                assert!(stored_rows > 0);
                let unencrypted_records: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM openmls_group_data
                         WHERE substr(group_data, 1, 1) != X'01'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(lattice_storage::StoreError::from)?;
                assert_eq!(unencrypted_records, 0);
                lattice_storage::Store::commit_authored_in_transaction(
                    transaction,
                    identity.fingerprint(),
                    event_id,
                    1,
                    &[0x02],
                    &[],
                )?;
                Ok::<Vec<u8>, CoreError>(group_id)
            })
            .expect("commit MLS group and event together");
        drop(client);

        let mut store = lattice_storage::Store::open(&database.0).expect("open MLS database");
        let persisted_rows = store
            .with_connection_mut(|connection| {
                connection
                    .query_row("SELECT COUNT(*) FROM openmls_group_data", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(lattice_storage::StoreError::from)
            })
            .expect("query persisted MLS rows");
        assert!(persisted_rows > 0);
        let mut reopened =
            Client::open_existing(&database.0, &protector).expect("reopen protected MLS state");
        let epoch: Result<u64, CoreError> = reopened.with_mls_transaction(|_, provider, _| {
            GroupState::load(provider, &group_id)
                .map(|group| group.epoch())
                .map_err(CoreError::Mls)
        });
        assert_eq!(epoch.expect("load persisted group"), 0);
        let store = lattice_storage::Store::open(&database.0).expect("open event store");
        assert!(
            store
                .load_event(&event_id)
                .expect("load event committed with group")
                .is_some()
        );
        assert!(
            store
                .load_event(&rolled_back_event_id)
                .expect("load rolled-back event")
                .is_none()
        );
    }

    #[test]
    fn identity_initialization_persists_ciphertext_and_reopens_same_public_identity() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let first_info = {
            let client =
                Client::open_or_create(&database.0, &protector).expect("initialize identity");
            assert_eq!(client.next_author_sequence().expect("first sequence"), 1);
            client.identity_info()
        };

        let reopened = Client::open_existing(&database.0, &protector).expect("reopen identity");
        assert_eq!(reopened.identity_info(), first_info);
        assert_eq!(reopened.next_author_sequence().expect("sequence"), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // End-to-end creation, restore, and tamper regression.
    fn local_space_genesis_persists_event_and_mls_group_atomically() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize identity");
        let credential = test_credential(&client.identity);
        let invalid = super::InitialChannel {
            channel_type: super::space::ChannelType::Text,
            name: "general".to_owned(),
            default_allow: u64::MAX,
            default_deny: 0,
            role_overrides: Vec::new(),
        };
        assert!(matches!(
            client.create_space(&credential, vec![invalid]),
            Err(CoreError::SpaceGenesisRejected(
                super::space::RejectReason::InvalidValue
            ))
        ));
        let rolled_back_rows = client
            .store
            .with_connection_mut(|connection| {
                connection
                    .query_row("SELECT COUNT(*) FROM openmls_group_data", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(lattice_storage::StoreError::from)
            })
            .expect("query rolled-back MLS state");
        assert_eq!(rolled_back_rows, 0);
        assert_eq!(
            client
                .next_author_sequence()
                .expect("sequence after rollback"),
            1
        );

        let created = client
            .create_space(
                &credential,
                vec![super::InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let fingerprint = client.identity_info().fingerprint;
        let event_id = *created.genesis_event().event_id().as_bytes();
        assert_eq!(created.genesis_event().space_id(), created.space_id());
        assert_eq!(created.genesis_event().channel_id(), None);
        assert_eq!(created.genesis_event().author_fingerprint(), &fingerprint);
        assert_eq!(created.genesis_event().author_sequence(), 1);
        assert_eq!(created.genesis_event().lamport(), 0);
        assert_eq!(created.genesis_event().parents().len(), 0);
        assert_eq!(created.genesis_event().kind(), EventKind::Membership);
        assert_eq!(created.genesis_event().mls_epoch(), 0);
        assert_eq!(
            created.genesis_event().mls_group_reference(),
            created.group_reference()
        );
        assert_eq!(
            created
                .reducer()
                .policy()
                .expect("active Genesis policy")
                .members[0]
                .fingerprint,
            fingerprint
        );
        assert_eq!(
            created
                .reducer()
                .policy()
                .expect("active Genesis policy")
                .members[0]
                .status,
            super::space::MemberStatus::Active
        );
        assert_eq!(client.next_author_sequence().expect("next sequence"), 2);
        drop(client);
        let mut reopened =
            Client::open_existing(&database.0, &protector).expect("reopen protected profile");

        let restored_page = reopened
            .restore_space_page(None)
            .expect("discover and restore local Space policy");
        assert_eq!(restored_page.spaces().len(), 1);
        assert_eq!(restored_page.next_cursor(), None);
        let restored = &restored_page.spaces()[0];
        assert_eq!(restored.group_id(), created.group_id());
        assert_eq!(
            restored
                .reducer()
                .policy()
                .expect("restored Genesis policy")
                .channels[0]
                .name,
            "general"
        );
        assert_eq!(
            restored
                .reducer()
                .policy()
                .expect("restored Genesis policy")
                .members[0]
                .status,
            super::space::MemberStatus::Active
        );
        let mut snapshot_store =
            lattice_storage::Store::open(&database.0).expect("reopen snapshot store");
        let encrypted_snapshot = snapshot_store
            .with_connection_mut(|connection| {
                connection
                    .query_row(
                        "SELECT encrypted_state FROM space_genesis_snapshots
                         WHERE space_id = ?1 AND group_reference = ?2",
                        rusqlite::params![&created.space_id()[..], &created.group_reference()[..]],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(lattice_storage::StoreError::from)
            })
            .expect("read encrypted snapshot");
        assert!(
            !encrypted_snapshot
                .windows(b"general".len())
                .any(|window| window == b"general")
        );
        let store = lattice_storage::Store::open(&database.0).expect("reopen event store");
        let stored_event = store
            .load_event(&event_id)
            .expect("load persisted Genesis")
            .expect("Genesis stored");
        assert_eq!(
            stored_event.canonical_bytes,
            created.genesis_event().encoded_bytes()
        );
        let updated = snapshot_store
            .with_connection_mut(|connection| {
                connection
                    .execute(
                        "UPDATE space_genesis_snapshots
                         SET encrypted_state = zeroblob(length(encrypted_state))
                         WHERE space_id = ?1 AND group_reference = ?2",
                        rusqlite::params![&created.space_id()[..], &created.group_reference()[..]],
                    )
                    .map_err(lattice_storage::StoreError::from)
            })
            .expect("tamper with encrypted snapshot");
        assert_eq!(updated, 1);
        let Err(restore_error) =
            reopened.restore_space(created.space_id(), created.group_reference())
        else {
            panic!("tampered snapshot must fail closed");
        };
        assert!(
            matches!(
                restore_error,
                CoreError::MlsStorageCodec(super::ProtectedCodecError::UnsupportedVersion)
            ),
            "unexpected restore error: {restore_error:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exercises one end-to-end membership transaction.
    fn membership_commit_policy_and_events_commit_atomically() {
        use lattice_protocol::{Value, encode_canonical};

        fn signed_event(
            identity: &DeviceIdentity,
            draft: EventDraft,
        ) -> VerifiedSignatureOnlyEvent {
            VerifiedSignatureOnlyEvent::create(identity, draft).expect("valid test event")
        }

        let alice_database = TestDatabase::new();
        let bob_database = TestDatabase::new();
        let protector = TestProtector;
        let mut alice = Client::open_or_create(&alice_database.0, &protector)
            .expect("initialize Alice profile");
        let mut bob =
            Client::open_or_create(&bob_database.0, &protector).expect("initialize Bob profile");
        let alice_credential = test_credential(&alice.identity);
        let bob_credential = test_credential(&bob.identity);
        let charlie_database = TestDatabase::new();
        let mut charlie = Client::open_or_create(&charlie_database.0, &protector)
            .expect("initialize Charlie profile");
        let charlie_fingerprint = charlie.identity.fingerprint();
        let charlie_credential = test_credential(&charlie.identity);
        let created = alice
            .create_space(
                &alice_credential,
                vec![super::InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create Genesis group");
        assert!(matches!(
            alice.request_space_leave(&created, &alice_credential),
            Err(CoreError::SpaceMembershipNotApplied(
                super::space::ApplyResult::Rejected(super::space::RejectReason::OwnerProtected)
            ))
        ));
        let group_id = created.group_id().to_vec();
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        let reducer = created.reducer().clone();
        let genesis_reducer = reducer.clone();
        let genesis_id = *created.genesis_event().event_id().as_bytes();

        let bob_key_package = bob
            .with_mls_transaction(|identity, provider, _transaction| {
                let key_package =
                    GroupState::publish_key_package(provider, identity, &bob_credential)?;
                Ok::<_, CoreError>(key_package.as_bytes().to_vec())
            })
            .expect("publish Bob KeyPackage");
        let welcome = alice
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared =
                    group.prepare_add(provider, identity, &alice_credential, &bob_key_package)?;
                let welcome =
                    group.accept_prepared_add(provider, &prepared, prepared.commit().as_bytes())?;
                Ok::<_, CoreError>(welcome.as_bytes().to_vec())
            })
            .expect("commit Bob membership");
        bob.with_mls_transaction(|_, provider, _transaction| {
            GroupState::from_welcome(provider, &group_id, &bob_credential, &welcome)?;
            Ok::<_, CoreError>(())
        })
        .expect("persist Bob's joined group");

        let charlie_key_package = charlie
            .with_mls_transaction(|identity, provider, _transaction| {
                let key_package =
                    GroupState::publish_key_package(provider, identity, &charlie_credential)?;
                Ok::<_, CoreError>(key_package.as_bytes().to_vec())
            })
            .expect("publish Charlie KeyPackage");
        let charlie_key_package_hash =
            lattice_mls::api::key_package_wire_sha256(&charlie_key_package)
                .expect("hash bounded Charlie KeyPackage");
        let invite_id = [0x71; 16];
        let invite_payload = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(2)),
            (2, Value::Bytes(invite_id.to_vec())),
            (3, Value::Bytes(charlie_fingerprint.to_vec())),
            (4, Value::Bytes(charlie_key_package_hash.to_vec())),
            (5, Value::Null),
            (6, Value::Null),
        ]))
        .expect("encode invite policy");
        let invite_ciphertext = alice
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let ciphertext = group.encrypt_application(
                    provider,
                    identity,
                    &alice_credential,
                    &invite_payload,
                )?;
                Ok::<_, CoreError>(ciphertext.as_bytes().to_vec())
            })
            .expect("encrypt invite at parent epoch");
        let invite = signed_event(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: 2,
                lamport: 2,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(genesis_id)],
                kind: EventKind::Membership,
                protected_body: invite_ciphertext,
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        );
        let invite_event_id = *invite.event_id().as_bytes();

        let (control_event, transition_event, charlie_welcome) = alice
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared = group.prepare_add(
                    provider,
                    identity,
                    &alice_credential,
                    &charlie_key_package,
                )?;
                assert_eq!(prepared.key_package_sha256(), &charlie_key_package_hash);
                let commit_wire = prepared.commit().as_bytes().to_vec();
                let control = signed_event(
                    identity,
                    EventDraft {
                        space_id,
                        channel_id: None,
                        author_sequence: 3,
                        lamport: 3,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(invite_event_id)],
                        kind: EventKind::MlsControl,
                        protected_body: commit_wire.clone(),
                        mls_group_reference: group_reference,
                        mls_epoch: 1,
                    },
                );
                let control_id = *control.event_id().as_bytes();
                let transition_payload = encode_canonical(&Value::Map(vec![
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(6)),
                    (2, Value::Unsigned(0)),
                    (3, Value::Bytes(charlie_fingerprint.to_vec())),
                    (4, Value::Bytes(invite_event_id.to_vec())),
                    (5, Value::Bytes(control_id.to_vec())),
                ]))
                .expect("encode admission policy");
                let ciphertext = group.encrypt_application_for_pending_membership(
                    provider,
                    identity,
                    &alice_credential,
                    &prepared,
                    &transition_payload,
                )?;
                let transition = signed_event(
                    identity,
                    EventDraft {
                        space_id,
                        channel_id: None,
                        author_sequence: 4,
                        lamport: 4,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(control_id)],
                        kind: EventKind::Membership,
                        protected_body: ciphertext.as_bytes().to_vec(),
                        mls_group_reference: group_reference,
                        mls_epoch: 1,
                    },
                );
                let charlie_welcome =
                    group.accept_prepared_add(provider, &prepared, &commit_wire)?;
                Ok::<_, CoreError>((control, transition, charlie_welcome.as_bytes().to_vec()))
            })
            .expect("prepare and commit Charlie add");
        charlie
            .with_mls_transaction(|_, provider, _transaction| {
                GroupState::from_welcome(
                    provider,
                    &group_id,
                    &charlie_credential,
                    &charlie_welcome,
                )?;
                Ok::<_, CoreError>(())
            })
            .expect("persist Charlie's joined group");

        let invalid_control = signed_event(
            &bob.identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: 1,
                lamport: 1,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(invite_event_id)],
                kind: EventKind::MlsControl,
                protected_body: control_event.protected_body().to_vec(),
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        );
        let invalid_control_id = *invalid_control.event_id().as_bytes();
        assert!(matches!(
            bob.accept_space_membership_transition(
                &group_id,
                &reducer,
                invalid_control,
                transition_event.clone(),
            ),
            Err(CoreError::SpaceControlRejected(
                super::space::RejectReason::InvalidControlRelation
            ))
        ));
        let epoch_after_rollback = bob
            .with_mls_transaction(|_, provider, _transaction| {
                Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
            })
            .expect("inspect group after rejected transaction");
        assert_eq!(epoch_after_rollback, 1);
        assert!(
            bob.store
                .load_event(&invalid_control_id)
                .expect("query rejected event")
                .is_none()
        );

        let control_event_id = *control_event.event_id().as_bytes();
        let channel_id = reducer.policy().expect("Genesis policy").channels[0].id;
        let post_commit_plaintext =
            super::encode_text_message("received after the missing MLS Commit")
                .expect("encode post-Commit message");
        let post_commit_ciphertext = alice
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                assert_eq!(group.epoch(), 2);
                let ciphertext = group.encrypt_application(
                    provider,
                    identity,
                    &alice_credential,
                    &post_commit_plaintext,
                )?;
                Ok::<_, CoreError>(ciphertext.as_bytes().to_vec())
            })
            .expect("encrypt message at committed MLS epoch");
        let mut post_commit_parents = vec![
            lattice_protocol::EventId::from_bytes(control_event_id),
            lattice_protocol::EventId::from_bytes(*transition_event.event_id().as_bytes()),
        ];
        post_commit_parents.sort_unstable_by_key(|parent| *parent.as_bytes());
        let post_commit_message = signed_event(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: Some(channel_id),
                author_sequence: 5,
                lamport: 5,
                wall_time_hint: 0,
                parents: post_commit_parents,
                kind: EventKind::Message,
                protected_body: post_commit_ciphertext,
                mls_group_reference: group_reference,
                mls_epoch: 2,
            },
        );
        let alice_peer = lattice_testkit::PeerId::new(0);
        let bob_peer = lattice_testkit::PeerId::new(1);
        let contact_plan = lattice_testkit::ContactPlan::new(
            3,
            vec![
                lattice_testkit::ContactWindow {
                    from: alice_peer,
                    to: bob_peer,
                    starts_at: 10,
                    ends_at: 11,
                },
                lattice_testkit::ContactWindow {
                    from: alice_peer,
                    to: bob_peer,
                    starts_at: 12,
                    ends_at: 13,
                },
            ],
        )
        .expect("build explicit membership delivery windows");
        let mut membership_link =
            lattice_testkit::DirectedLink::new(0x4d45_4d42, lattice_testkit::LinkConfig::default())
                .expect("build deterministic membership path");
        assert!(!contact_plan.is_active(alice_peer, bob_peer, 9));
        assert!(contact_plan.is_active(alice_peer, bob_peer, 10));
        membership_link
            .send(10, post_commit_message.encoded_bytes().to_vec())
            .expect("queue post-Commit event during first contact");
        let received_post_commit_bytes = membership_link
            .deliver(10, 1)
            .pop()
            .expect("deliver post-Commit event");
        let received_post_commit =
            VerifiedSignatureOnlyEvent::decode_verify(&received_post_commit_bytes)
                .expect("verify relayed post-Commit event");
        assert!(!contact_plan.is_active(alice_peer, bob_peer, 11));
        assert!(contact_plan.is_active(alice_peer, bob_peer, 12));
        membership_link
            .send(12, control_event.encoded_bytes().to_vec())
            .expect("queue MLS Commit during reunion");
        membership_link
            .send(12, transition_event.encoded_bytes().to_vec())
            .expect("queue member admission during reunion");
        let mut received_membership_events = membership_link.deliver(12, 2);
        assert_eq!(received_membership_events.len(), 2);
        let received_control =
            VerifiedSignatureOnlyEvent::decode_verify(&received_membership_events.remove(0))
                .expect("verify relayed MLS Commit");
        let received_transition =
            VerifiedSignatureOnlyEvent::decode_verify(&received_membership_events.remove(0))
                .expect("verify relayed member transition");
        let mut bob_joined = super::CreatedSpace {
            space_id,
            group_id: group_id.clone(),
            group_reference,
            genesis_event: created.genesis_event().clone(),
            reducer: reducer.clone(),
        };
        assert!(matches!(
            bob.accept_synced_application_event(
                &mut bob_joined,
                received_post_commit.encoded_bytes(),
            )
            .expect("hold post-Commit ciphertext behind missing control parent"),
            super::SyncedApplicationOutcome::Pending {
                missing_dependencies,
                ..
            } if missing_dependencies.len() == 2
                && missing_dependencies.contains(&control_event_id)
        ));
        assert!(
            bob.accept_synced_space_membership_transition(
                &mut bob_joined,
                Some(invite.encoded_bytes()),
                received_control.encoded_bytes(),
                received_transition.encoded_bytes(),
            )
            .expect("atomically accept synchronized invite, Commit, and transition")
        );
        assert!(
            !bob.accept_synced_space_membership_transition(
                &mut bob_joined,
                Some(invite.encoded_bytes()),
                received_control.encoded_bytes(),
                received_transition.encoded_bytes(),
            )
            .expect("recognize duplicate synchronized membership bundle")
        );
        let updated = bob_joined.reducer.clone();
        assert_eq!(
            bob.accept_synced_application_event(
                &mut bob_joined,
                received_post_commit.encoded_bytes(),
            )
            .expect("retry dependent ciphertext after MLS Commit"),
            super::SyncedApplicationOutcome::Accepted {
                event_id: *post_commit_message.event_id().as_bytes(),
            }
        );
        let policy = updated.policy().expect("active updated policy");
        assert_eq!(
            policy
                .members
                .iter()
                .find(|member| { member.fingerprint == charlie_fingerprint })
                .map(|member| member.status),
            Some(super::space::MemberStatus::Active)
        );
        assert_eq!(policy.invites[0].uses, 1);
        let bob_prior = super::CreatedSpace {
            space_id,
            group_id: group_id.clone(),
            group_reference,
            genesis_event: created.genesis_event().clone(),
            reducer: updated.clone(),
        };
        assert!(matches!(
            bob.create_space_recovery_generation(&bob_prior, &bob_credential),
            Err(CoreError::SpaceGenesisRejected(
                super::space::RejectReason::InvalidRecoveryAuthorization
            ))
        ));
        assert!(
            bob.store
                .list_space_genesis_page(None)
                .expect("read Bob recovery snapshots after denial")
                .is_empty()
        );
        let committed_epoch = bob
            .with_mls_transaction(|_, provider, _transaction| {
                Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
            })
            .expect("reload committed Bob group");
        assert_eq!(committed_epoch, 2);
        let dave_identity = DeviceIdentity::generate().expect("Dave identity");
        let dave_credential = test_credential(&dave_identity);
        let dave_provider = OpenMlsRustCrypto::default();
        let dave_key_package =
            GroupState::publish_key_package(&dave_provider, &dave_identity, &dave_credential)
                .expect("publish Dave KeyPackage")
                .as_bytes()
                .to_vec();
        let eve_identity = DeviceIdentity::generate().expect("Eve identity");
        let eve_credential = test_credential(&eve_identity);
        let eve_provider = OpenMlsRustCrypto::default();
        let eve_key_package =
            GroupState::publish_key_package(&eve_provider, &eve_identity, &eve_credential)
                .expect("publish Eve KeyPackage")
                .as_bytes()
                .to_vec();
        let alice_branch_commit = alice
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let branch =
                    group.prepare_add(provider, identity, &alice_credential, &dave_key_package)?;
                Ok::<_, CoreError>(branch.commit().as_bytes().to_vec())
            })
            .expect("create Alice sibling Commit");
        let charlie_branch_commit = charlie
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let branch =
                    group.prepare_add(provider, identity, &charlie_credential, &eve_key_package)?;
                Ok::<_, CoreError>(branch.commit().as_bytes().to_vec())
            })
            .expect("create Charlie sibling Commit");
        let policy_parent =
            lattice_protocol::EventId::from_bytes(*transition_event.event_id().as_bytes());
        let alice_control = signed_event(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: 6,
                lamport: 5,
                wall_time_hint: 0,
                parents: vec![policy_parent],
                kind: EventKind::MlsControl,
                protected_body: alice_branch_commit,
                mls_group_reference: group_reference,
                mls_epoch: 2,
            },
        );
        let charlie_control = signed_event(
            &charlie.identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: charlie.next_author_sequence().expect("Charlie sequence"),
                lamport: 5,
                wall_time_hint: 0,
                parents: vec![policy_parent],
                kind: EventKind::MlsControl,
                protected_body: charlie_branch_commit,
                mls_group_reference: group_reference,
                mls_epoch: 2,
            },
        );
        let quarantined = bob
            .record_space_membership_conflict(
                &group_id,
                &updated,
                alice_control.clone(),
                charlie_control.clone(),
            )
            .expect("persist distinct-author sibling conflict");
        assert!(matches!(
            quarantined.status(),
            super::space::ReducerStatus::PolicyConflicted
        ));
        assert_eq!(quarantined.quarantined_event_ids().len(), 2);
        assert_eq!(
            bob.store
                .load_space_membership_conflict(&space_id, &group_reference)
                .expect("load durable conflict marker")
                .expect("conflict marker persisted")
                .parent_epoch,
            2
        );
        assert!(matches!(
            bob.accept_space_membership_transition(
                &group_id,
                &updated,
                control_event.clone(),
                transition_event.clone(),
            ),
            Err(CoreError::SpaceMembershipConflicted)
        ));
        assert!(matches!(
            bob.record_space_membership_conflict(
                &group_id,
                &quarantined,
                alice_control,
                charlie_control,
            ),
            Err(CoreError::SpaceMembershipConflicted)
        ));
        for event in [&control_event, &transition_event] {
            let stored = bob
                .store
                .load_event(event.event_id().as_bytes())
                .expect("query stored membership event")
                .expect("membership event committed with MLS merge");
            assert_eq!(stored.canonical_bytes, event.encoded_bytes());
        }
        assert!(
            bob.store
                .load_event(&control_event_id)
                .expect("query committed control event")
                .is_some()
        );

        let snapshot = bob
            .store
            .list_space_membership_transition_snapshots(&space_id, &group_reference)
            .expect("load persisted transition evidence")
            .into_iter()
            .next()
            .expect("one accepted transition");
        let control_record = bob
            .store
            .load_event(&snapshot.control_event_id)
            .expect("load persisted control event")
            .expect("control event exists");
        let transition_record = bob
            .store
            .load_event(&snapshot.transition_event_id)
            .expect("load persisted transition event")
            .expect("transition event exists");
        let replayed = bob
            .with_mls_transaction(|_, _, _| {
                let mut reducer = genesis_reducer;
                super::replay_space_membership_transitions(
                    &mut reducer,
                    vec![(
                        snapshot,
                        control_record.canonical_bytes,
                        transition_record.canonical_bytes,
                    )],
                )?;
                Ok::<_, CoreError>(reducer)
            })
            .expect("replay authenticated policy history after storage round trip");
        let replayed_policy = replayed.policy().expect("replayed active policy");
        assert_eq!(replayed_policy.revision, policy.revision);
        assert_eq!(replayed_policy.invites[0].uses, policy.invites[0].uses);
        assert_eq!(
            replayed_policy
                .members
                .iter()
                .find(|member| member.fingerprint == charlie_fingerprint)
                .map(|member| member.status),
            Some(super::space::MemberStatus::Active)
        );

        drop(bob);
        let reopened_bob = Client::open_existing(&bob_database.0, &protector)
            .expect("reopen Bob after durable sibling-Commit conflict");
        assert!(matches!(
            reopened_bob.ensure_space_generation_mutable(&space_id, &group_reference),
            Err(CoreError::SpaceMembershipConflicted)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exercises stale branch rejection and transaction rollback.
    fn self_authored_sibling_commits_are_not_accepted_as_remote_conflicts() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let mut client =
            Client::open_or_create(&database.0, &protector).expect("initialize local profile");
        let credential = test_credential(&client.identity);
        let created = client
            .create_space(
                &credential,
                vec![super::InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create local Space");
        let group_id = created.group_id().to_vec();
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        let genesis_id = *created.genesis_event().event_id().as_bytes();
        let reducer = created.reducer().clone();
        let charlie_identity = DeviceIdentity::generate().expect("generate invited identity");
        let charlie_credential = test_credential(&charlie_identity);
        let charlie_provider = OpenMlsRustCrypto::default();
        let key_package = GroupState::publish_key_package(
            &charlie_provider,
            &charlie_identity,
            &charlie_credential,
        )
        .expect("publish invited KeyPackage")
        .as_bytes()
        .to_vec();
        drop(credential);
        drop(created);
        drop(client);

        let first_branch = TestDatabase::new();
        let second_branch = TestDatabase::new();
        std::fs::copy(&database.0, &first_branch.0).expect("copy first branch profile");
        std::fs::copy(&database.0, &second_branch.0).expect("copy second branch profile");
        let mut first_client =
            Client::open_existing(&first_branch.0, &protector).expect("open first branch");
        let mut second_client =
            Client::open_existing(&second_branch.0, &protector).expect("open second branch");
        let first_control = {
            let credential = test_credential(&first_client.identity);
            first_client
                .with_mls_transaction(|identity, provider, _transaction| {
                    let mut group = GroupState::load(provider, &group_id)?;
                    let prepared =
                        group.prepare_add(provider, identity, &credential, &key_package)?;
                    let wire = prepared.commit().as_bytes().to_vec();
                    Ok::<_, CoreError>(VerifiedSignatureOnlyEvent::create(
                        identity,
                        EventDraft {
                            space_id,
                            channel_id: None,
                            author_sequence: 2,
                            lamport: 2,
                            wall_time_hint: 0,
                            parents: vec![lattice_protocol::EventId::from_bytes(genesis_id)],
                            kind: EventKind::MlsControl,
                            protected_body: wire,
                            mls_group_reference: group_reference,
                            mls_epoch: 0,
                        },
                    )?)
                })
                .expect("create first valid sibling Commit")
        };
        let second_control = {
            let credential = test_credential(&second_client.identity);
            second_client
                .with_mls_transaction(|identity, provider, _transaction| {
                    let mut group = GroupState::load(provider, &group_id)?;
                    let prepared =
                        group.prepare_add(provider, identity, &credential, &key_package)?;
                    let wire = prepared.commit().as_bytes().to_vec();
                    Ok::<_, CoreError>(VerifiedSignatureOnlyEvent::create(
                        identity,
                        EventDraft {
                            space_id,
                            channel_id: None,
                            author_sequence: 3,
                            lamport: 3,
                            wall_time_hint: 0,
                            parents: vec![lattice_protocol::EventId::from_bytes(genesis_id)],
                            kind: EventKind::MlsControl,
                            protected_body: wire,
                            mls_group_reference: group_reference,
                            mls_epoch: 0,
                        },
                    )?)
                })
                .expect("create second valid sibling Commit")
        };
        drop(first_client);
        drop(second_client);

        let mut reopened =
            Client::open_existing(&database.0, &protector).expect("reopen parent generation");
        assert!(
            reopened
                .record_space_membership_conflict(
                    &group_id,
                    &reducer,
                    first_control.clone(),
                    second_control.clone(),
                )
                .is_err()
        );
        assert!(
            reopened
                .store
                .load_space_membership_conflict(&space_id, &group_reference)
                .expect("query unaccepted conflict")
                .is_none()
        );
        for event in [&first_control, &second_control] {
            assert!(
                reopened
                    .store
                    .load_event(event.event_id().as_bytes())
                    .expect("query unaccepted control")
                    .is_none()
            );
        }
        let epoch = reopened
            .with_mls_transaction(|_, provider, _transaction| {
                Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
            })
            .expect("inspect epoch after unaccepted controls");
        assert_eq!(epoch, 0);
        drop(reopened);

        let mut restored =
            Client::open_existing(&database.0, &protector).expect("reopen unchanged profile");
        let restored_space = restored
            .restore_space(&space_id, &group_reference)
            .expect("restore unchanged local generation");
        assert_eq!(
            restored_space.reducer().status(),
            super::space::ReducerStatus::Active { revision: 0 }
        );
    }

    #[test]
    fn existing_profile_open_fails_closed_when_identity_is_missing() {
        let database = TestDatabase::new();
        assert!(matches!(
            Client::open_existing(&database.0, &TestProtector),
            Err(CoreError::MissingIdentity)
        ));
    }
    #[allow(clippy::too_many_lines)] // Covers atomic authoring, rollback, restore, and recipient import.
    #[test]
    fn create_space_invite_commits_transition_and_importable_welcome() {
        let alice_database = TestDatabase::new();
        let bob_database = TestDatabase::new();
        let protector = TestProtector;
        let mut alice =
            Client::open_or_create(&alice_database.0, &protector).expect("initialize inviter");
        let mut bob =
            Client::open_or_create(&bob_database.0, &protector).expect("initialize invitee");
        let alice_credential = test_credential(&alice.identity);
        let bob_credential = test_credential(&bob.identity);
        let alice_fingerprint = alice.identity.fingerprint();
        let bob_fingerprint = bob.identity.fingerprint();
        let mut created = alice
            .create_space(
                &alice_credential,
                vec![super::InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create inviter Space");
        let key_package = bob
            .publish_key_package(&bob_credential, 100)
            .expect("publish tracked invitee KeyPackage");
        assert!(matches!(
            alice.create_space_invite(
                &mut created,
                &alice_credential,
                &key_package,
                None,
                0,
                Some(1),
            ),
            Err(CoreError::SpaceInviteInvalid)
        ));
        assert!(
            alice
                .create_space_invite(&mut created, &alice_credential, &[0], None, 2_000, Some(1),)
                .is_err()
        );
        assert_eq!(
            alice
                .next_author_sequence()
                .expect("failed invite rolled back"),
            2
        );
        assert!(
            alice
                .store
                .list_outbox_page(None, 16)
                .expect("inspect failed invite outbox")
                .is_empty()
        );
        let invitation = alice
            .create_space_invite(
                &mut created,
                &alice_credential,
                &key_package,
                None,
                2_000,
                Some(1),
            )
            .expect("commit signed invitation and Add transition");
        let token =
            super::SpaceInviteV1::from_bytes(invitation.token()).expect("decode signed token");
        assert_eq!(token.target(), &bob_fingerprint);
        assert_eq!(token.inviter_fingerprint(), Ok(alice_fingerprint));
        let policy = created.reducer().policy().expect("committed policy");
        assert_eq!(policy.revision, 2);
        assert!(policy.members.iter().any(|member| {
            member.fingerprint == bob_fingerprint
                && member.status == super::space::MemberStatus::Active
        }));
        assert_eq!(policy.invites.len(), 1);
        assert_eq!(policy.invites[0].uses, 1);
        assert_eq!(policy.invites[0].max_uses, Some(1));
        let outbox = alice
            .store
            .list_outbox_page(None, 16)
            .expect("read queued invitation events");
        assert_eq!(outbox.len(), 3);
        assert!(
            outbox
                .iter()
                .any(|event| event.event_id == *invitation.invite_event_id())
        );
        assert!(
            outbox
                .iter()
                .all(|event| { event.state == lattice_storage::OutboxState::Queued })
        );

        let restored = alice
            .restore_space(created.space_id(), created.group_reference())
            .expect("replay committed invitation transition");
        assert_eq!(
            restored
                .reducer()
                .policy()
                .expect("restored policy")
                .revision,
            2
        );
        let channel_id = created
            .reducer()
            .policy()
            .expect("committed membership policy")
            .channels[0]
            .id;
        let queued = alice
            .queue_text_message(
                &mut created,
                &alice_credential,
                channel_id,
                "message after verified membership transition",
            )
            .expect("queue on the accepted two-member MLS roster");
        let stored = alice
            .store
            .load_event(queued.event_id())
            .expect("load queued post-membership event")
            .expect("post-membership event is durable");
        let event = VerifiedSignatureOnlyEvent::decode_verify(&stored.canonical_bytes)
            .expect("verify post-membership event");
        assert_eq!(event.mls_epoch(), 1);
        bob.pin_identity(
            &alice.identity.public_bundle().to_bytes(),
            alice_fingerprint,
        )
        .expect("pin inviter identity");
        let joined = bob
            .join_space_from_welcome_bootstrap(
                invitation.welcome_bootstrap(),
                alice_fingerprint,
                &bob_credential,
            )
            .expect("import signed Welcome bootstrap");
        assert_eq!(joined.space_id(), created.space_id());
        assert!(joined.reducer().policy().is_some_and(|policy| {
            policy.members.iter().any(|member| {
                member.fingerprint == bob_fingerprint
                    && member.status == super::space::MemberStatus::Active
            })
        }));
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        drop(created);
        drop(alice);
        let mut alice = Client::open_existing(&alice_database.0, &protector)
            .expect("reopen inviter profile between member additions");
        let mut created = alice
            .restore_space(&space_id, &group_reference)
            .expect("restore inviter Space before second invitation");
        let charlie_database = TestDatabase::new();
        let mut charlie = Client::open_or_create(&charlie_database.0, &protector)
            .expect("initialize second invitee");
        let charlie_credential = test_credential(&charlie.identity);
        let charlie_fingerprint = charlie.identity.fingerprint();
        let charlie_key_package = charlie
            .publish_key_package(&charlie_credential, 101)
            .expect("publish second invitee KeyPackage");
        let second_invitation = alice
            .create_space_invite(
                &mut created,
                &alice_credential,
                &charlie_key_package,
                None,
                2_001,
                Some(1),
            )
            .expect("commit second invitation after first member add");
        charlie
            .pin_identity(
                &alice.identity.public_bundle().to_bytes(),
                alice_fingerprint,
            )
            .expect("pin inviter for second invitee");
        let mut second_joined = charlie
            .join_space_from_welcome_bootstrap(
                second_invitation.welcome_bootstrap(),
                alice_fingerprint,
                &charlie_credential,
            )
            .expect("import Welcome after prior membership transition");
        assert!(second_joined.reducer().policy().is_some_and(|policy| {
            policy.members.iter().any(|member| {
                member.fingerprint == charlie_fingerprint
                    && member.status == super::space::MemberStatus::Active
            })
        }));
        let outbox = alice
            .store
            .list_outbox_page(None, 32)
            .expect("load invitation history for checkpoint replay");
        let signed_events = outbox
            .iter()
            .map(|record| {
                let stored = alice
                    .store
                    .load_event(&record.event_id)
                    .expect("load inviter history event")
                    .expect("outbox event is stored");
                VerifiedSignatureOnlyEvent::decode_verify(&stored.canonical_bytes)
                    .expect("verify inviter event")
            })
            .collect::<Vec<_>>();
        let first_invite_id = *invitation.invite_event_id();
        let first_control = signed_events
            .iter()
            .find(|event| {
                event.kind() == EventKind::MlsControl
                    && event
                        .parents()
                        .iter()
                        .any(|parent| parent.as_bytes() == &first_invite_id)
            })
            .expect("first membership control");
        let first_control_id = *first_control.event_id().as_bytes();
        let first_transition = signed_events
            .iter()
            .find(|event| {
                event.kind() == EventKind::Membership
                    && event
                        .parents()
                        .iter()
                        .any(|parent| parent.as_bytes() == &first_control_id)
            })
            .expect("first membership transition");
        let first_policy_event = signed_events
            .iter()
            .find(|event| event.event_id().as_bytes() == &first_invite_id)
            .expect("first invitation policy event");
        charlie
            .accept_synced_space_membership_transition(
                &mut second_joined,
                Some(first_policy_event.encoded_bytes()),
                first_control.encoded_bytes(),
                first_transition.encoded_bytes(),
            )
            .expect("checkpoint-covered historical transition does not replay stale MLS");
        assert_eq!(
            charlie
                .accept_synced_application_event(&mut second_joined, event.encoded_bytes())
                .expect("retain pre-checkpoint event only as signed ancestry"),
            super::SyncedApplicationOutcome::CheckpointExcluded {
                event_id: *event.event_id().as_bytes(),
            }
        );
        let post_checkpoint_message = alice
            .queue_text_message(
                &mut created,
                &alice_credential,
                channel_id,
                "message after later Welcome checkpoint",
            )
            .expect("queue message at the later MLS epoch");
        let post_checkpoint_record = alice
            .store
            .load_event(post_checkpoint_message.event_id())
            .expect("load later-epoch message")
            .expect("later-epoch message is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(
                    &mut second_joined,
                    &post_checkpoint_record.canonical_bytes
                )
                .expect("accept message after checkpoint-covered ancestry"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let history = charlie
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .expect("load only authorized text history");
        assert!(
            history
                .iter()
                .any(|message| message.content == "message after later Welcome checkpoint")
        );
        assert!(
            history
                .iter()
                .all(|message| message.content != "message after verified membership transition")
        );
        let reply = alice
            .queue_text_message_reply(
                &mut created,
                &alice_credential,
                channel_id,
                *post_checkpoint_message.event_id(),
                "reply after joining",
            )
            .expect("queue thread reply");
        let reply_record = alice
            .store
            .load_event(reply.event_id())
            .expect("load thread reply")
            .expect("thread reply is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(&mut second_joined, &reply_record.canonical_bytes)
                .expect("accept remote thread reply"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let projection = second_joined.reducer().message_history(&channel_id);
        assert!(projection.messages().iter().any(|message| {
            message.event_id == *reply.event_id()
                && message.thread_root == Some(*post_checkpoint_message.event_id())
        }));
        let reaction_add = alice
            .queue_text_message_reaction(
                &mut created,
                &alice_credential,
                &super::TextMessageReaction {
                    channel_id,
                    target: *post_checkpoint_message.event_id(),
                    token: "👍".to_owned(),
                    add: true,
                    tag: None,
                },
            )
            .expect("queue observed-add reaction");
        let reaction_add_record = alice
            .store
            .load_event(reaction_add.event_id())
            .expect("load reaction add")
            .expect("reaction add is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(
                    &mut second_joined,
                    &reaction_add_record.canonical_bytes
                )
                .expect("accept remote reaction add"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let projection = second_joined.reducer().message_history(&channel_id);
        assert!(projection.messages().iter().any(|message| {
            message.event_id == *post_checkpoint_message.event_id()
                && message.reactions.iter().any(|reaction| {
                    reaction.token == "👍" && reaction.active_tags == vec![*reaction_add.event_id()]
                })
        }));
        let reaction_remove = alice
            .queue_text_message_reaction(
                &mut created,
                &alice_credential,
                &super::TextMessageReaction {
                    channel_id,
                    target: *post_checkpoint_message.event_id(),
                    token: "👍".to_owned(),
                    add: false,
                    tag: Some(*reaction_add.event_id()),
                },
            )
            .expect("queue observed-tag reaction removal");
        let reaction_remove_record = alice
            .store
            .load_event(reaction_remove.event_id())
            .expect("load reaction removal")
            .expect("reaction removal is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(
                    &mut second_joined,
                    &reaction_remove_record.canonical_bytes
                )
                .expect("accept remote reaction removal"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let pin_add = alice
            .queue_text_message_pin(
                &mut created,
                &alice_credential,
                super::TextMessagePin {
                    channel_id,
                    target: *post_checkpoint_message.event_id(),
                    add: true,
                    tag: None,
                },
            )
            .expect("queue pin add");
        let pin_add_record = alice
            .store
            .load_event(pin_add.event_id())
            .expect("load pin add")
            .expect("pin add is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(
                    &mut second_joined,
                    &pin_add_record.canonical_bytes
                )
                .expect("accept remote pin add"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let pin_remove = alice
            .queue_text_message_pin(
                &mut created,
                &alice_credential,
                super::TextMessagePin {
                    channel_id,
                    target: *post_checkpoint_message.event_id(),
                    add: false,
                    tag: Some(*pin_add.event_id()),
                },
            )
            .expect("queue observed-tag pin removal");
        let pin_remove_record = alice
            .store
            .load_event(pin_remove.event_id())
            .expect("load pin removal")
            .expect("pin removal is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(
                    &mut second_joined,
                    &pin_remove_record.canonical_bytes
                )
                .expect("accept remote pin removal"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let projection = second_joined.reducer().message_history(&channel_id);
        assert!(projection.messages().iter().any(|message| {
            message.event_id == *post_checkpoint_message.event_id()
                && message.reactions.is_empty()
                && !message.is_pinned()
        }));
        let tombstone = alice
            .queue_text_message_tombstone(
                &mut created,
                &alice_credential,
                channel_id,
                *post_checkpoint_message.event_id(),
            )
            .expect("queue local author tombstone for cross-client sync");
        let tombstone_record = alice
            .store
            .load_event(tombstone.event_id())
            .expect("load synchronized tombstone")
            .expect("tombstone is durable");
        assert!(matches!(
            charlie
                .accept_synced_application_event(
                    &mut second_joined,
                    &tombstone_record.canonical_bytes
                )
                .expect("authorize remote tombstone"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let history_after_delete = charlie
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .expect("read history after remote tombstone");
        assert!(
            history_after_delete
                .iter()
                .all(|message| message.event_id != *post_checkpoint_message.event_id())
        );
        assert!(
            history_after_delete
                .iter()
                .any(|message| message.event_id == *reply.event_id())
        );
        let projection = second_joined.reducer().message_history(&channel_id);
        assert!(projection.messages().iter().any(|message| message.event_id
            == *post_checkpoint_message.event_id()
            && message.is_deleted()));
    }

    #[allow(clippy::too_many_lines)] // Exercises the complete persisted removal/rekey transaction.
    #[test]
    fn space_member_removal_commits_rekey_and_restores_policy() {
        let alice_database = TestDatabase::new();
        let bob_database = TestDatabase::new();
        let protector = TestProtector;
        let mut alice =
            Client::open_or_create(&alice_database.0, &protector).expect("initialize admin");
        let mut bob =
            Client::open_or_create(&bob_database.0, &protector).expect("initialize member");
        let alice_credential = test_credential(&alice.identity);
        let bob_credential = test_credential(&bob.identity);
        let bob_fingerprint = bob.identity.fingerprint();
        let mut created = alice
            .create_space(
                &alice_credential,
                vec![super::InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create Space");
        let key_package = bob
            .publish_key_package(&bob_credential, 100)
            .expect("publish member KeyPackage");
        let invitation = alice
            .create_space_invite(
                &mut created,
                &alice_credential,
                &key_package,
                None,
                2_000,
                Some(1),
            )
            .expect("add member through normal invite API");
        bob.pin_identity(
            &alice.identity.public_bundle().to_bytes(),
            alice.identity.fingerprint(),
        )
        .expect("pin inviter");
        let joined = bob
            .join_space_from_welcome_bootstrap(
                invitation.welcome_bootstrap(),
                alice.identity.fingerprint(),
                &bob_credential,
            )
            .expect("join with authenticated Welcome");
        assert!(joined.reducer().policy().is_some_and(|policy| {
            policy.members.iter().any(|member| {
                member.fingerprint == bob_fingerprint
                    && member.status == super::space::MemberStatus::Active
            })
        }));
        alice
            .restore_space(created.space_id(), created.group_reference())
            .expect("restore two-member generation before removal");

        let mut absent_fingerprint = [0xA5; 32];
        while absent_fingerprint == bob_fingerprint
            || absent_fingerprint == alice.identity.fingerprint()
        {
            absent_fingerprint[0] = absent_fingerprint[0].wrapping_add(1);
        }
        let before_failed_removal = alice
            .store
            .list_outbox_page(None, 16)
            .expect("read outbox before rejected removal")
            .len();
        assert!(
            alice
                .remove_space_member(&mut created, &alice_credential, absent_fingerprint)
                .is_err()
        );
        assert_eq!(
            alice
                .store
                .list_outbox_page(None, 16)
                .expect("read outbox after rejected removal")
                .len(),
            before_failed_removal
        );
        assert_eq!(
            created
                .reducer()
                .policy()
                .expect("membership policy")
                .revision,
            2
        );

        let removal = alice
            .remove_space_member(&mut created, &alice_credential, bob_fingerprint)
            .expect("commit authorized Remove and rekey");
        assert_eq!(removal.target_fingerprint(), &bob_fingerprint);
        assert_eq!(removal.parent_epoch(), 1);
        assert_eq!(removal.new_epoch(), 2);
        let policy = created.reducer().policy().expect("removed policy");
        assert_eq!(policy.revision, 3);
        assert!(policy.members.iter().any(|member| {
            member.fingerprint == bob_fingerprint
                && member.status == super::space::MemberStatus::Removed
        }));
        let control_record = alice
            .store
            .load_event(removal.control_event_id())
            .expect("load removal control")
            .expect("persist removal control");
        let transition_record = alice
            .store
            .load_event(removal.transition_event_id())
            .expect("load removal transition")
            .expect("persist removal transition");
        let control_event =
            VerifiedSignatureOnlyEvent::decode_verify(&control_record.canonical_bytes)
                .expect("verify removal control");
        let transition_event =
            VerifiedSignatureOnlyEvent::decode_verify(&transition_record.canonical_bytes)
                .expect("verify removal transition");
        assert!(control_event.wall_time_hint() > 0);
        assert_eq!(
            transition_event.wall_time_hint(),
            control_event.wall_time_hint()
        );
        let local_group_id = created.group_id().to_vec();
        assert_eq!(
            alice
                .with_mls_transaction(|_, provider, _| {
                    let group = GroupState::load(provider, &local_group_id)?;
                    Ok::<_, CoreError>((group.epoch(), group.member_count()))
                })
                .expect("inspect committed removal roster"),
            (2, 1)
        );
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        drop(created);
        drop(alice);

        let mut restored =
            Client::open_existing(&alice_database.0, &protector).expect("reopen admin profile");
        let restored_space = restored
            .restore_space(&space_id, &group_reference)
            .expect("restore removal checkpoint");
        assert_eq!(
            restored_space
                .reducer()
                .policy()
                .expect("restored membership policy")
                .members
                .iter()
                .find(|member| member.fingerprint == bob_fingerprint)
                .expect("removed member retained in history")
                .status,
            super::space::MemberStatus::Removed
        );
        let group_id = restored_space.group_id().to_vec();
        assert_eq!(
            restored
                .with_mls_transaction(|_, provider, _| {
                    Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
                })
                .expect("read restored MLS epoch"),
            2
        );
    }

    #[allow(clippy::too_many_lines)] // Covers the accepted join and durable history replay path.
    #[test]

    fn pinned_welcome_bootstrap_joins_and_restores_checkpoint_policy() {
        use lattice_protocol::{Value, encode_canonical};

        let alice_database = TestDatabase::new();
        let bob_database = TestDatabase::new();
        let protector = TestProtector;
        let mut alice = Client::open_or_create(&alice_database.0, &protector)
            .expect("initialize inviter profile");
        let mut bob =
            Client::open_or_create(&bob_database.0, &protector).expect("initialize recipient");
        let alice_credential = test_credential(&alice.identity);
        let bob_credential = test_credential(&bob.identity);
        let bob_fingerprint = bob.identity.fingerprint();
        let alice_fingerprint = alice.identity.fingerprint();
        let created = alice
            .create_space(
                &alice_credential,
                vec![super::InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create inviter Space");
        let group_id = created.group_id().to_vec();
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        let root_id = *created.genesis_event().event_id().as_bytes();
        let bob_key_packages = bob
            .replenish_key_packages(&bob_credential, 1, 0)
            .expect("publish recipient KeyPackage");
        assert_eq!(bob_key_packages.len(), 1);
        assert!(
            bob.replenish_key_packages(&bob_credential, 1, 0)
                .expect("leave available inventory unchanged")
                .is_empty()
        );
        assert_eq!(
            bob.store
                .available_key_package_count(0)
                .expect("count available packages"),
            1
        );
        let bob_key_package = &bob_key_packages[0];
        let key_package_hash = lattice_mls::api::key_package_wire_sha256(bob_key_package)
            .expect("hash recipient KeyPackage");
        let (welcome, control_event) = alice
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared =
                    group.prepare_add(provider, identity, &alice_credential, bob_key_package)?;
                let commit = prepared.commit().as_bytes().to_vec();
                let welcome = group.accept_prepared_add(provider, &prepared, &commit)?;
                let control = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id,
                        channel_id: None,
                        author_sequence: 2,
                        lamport: 2,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(root_id)],
                        kind: EventKind::MlsControl,
                        protected_body: commit,
                        mls_group_reference: group_reference,
                        mls_epoch: 0,
                    },
                )?;
                Ok::<_, CoreError>((welcome.as_bytes().to_vec(), control))
            })
            .expect("commit recipient membership");

        let invite_id = [0x42; 16];
        let invite_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(2)),
            (2, Value::Bytes(invite_id.to_vec())),
            (3, Value::Bytes(bob_fingerprint.to_vec())),
            (4, Value::Bytes(key_package_hash.to_vec())),
            (5, Value::Null),
            (6, Value::Null),
        ]))
        .expect("encode invite policy");
        let invite_event = VerifiedSignatureOnlyEvent::create(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: 3,
                lamport: 3,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(root_id)],
                kind: EventKind::Membership,
                protected_body: vec![0xA5],
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        )
        .expect("sign invite head");
        let invite_event_id = *invite_event.event_id().as_bytes();
        let mut policy = created.reducer().policy().expect("Genesis policy").clone();
        policy.revision = 1;
        policy.heads = vec![invite_event_id];
        policy.members.push(super::space::Member {
            fingerprint: bob_fingerprint,
            status: super::space::MemberStatus::Active,
            assigned_roles: Vec::new(),
        });
        policy
            .members
            .sort_unstable_by_key(|member| member.fingerprint);
        policy.invites.push(super::space::Invite {
            id: invite_id,
            event_id: invite_event_id,
            target: bob_fingerprint,
            key_package_hash,
            expires_at_revision: None,
            max_uses: None,
            uses: 1,
        });
        let genesis_snapshot = alice
            .store
            .load_space_genesis_snapshot(&space_id, &group_reference)
            .expect("load protected Genesis")
            .expect("Genesis snapshot exists");
        let genesis_context =
            super::space_genesis_context(&space_id, &group_reference, &genesis_snapshot.event_id);
        let encrypted_genesis = genesis_snapshot.encrypted_state;
        let genesis_plaintext = alice
            .with_mls_transaction(move |_, _, _| {
                lattice_mls::unprotect_local_record(&genesis_context, &encrypted_genesis)
                    .map_err(CoreError::from)
            })
            .expect("decrypt Genesis for inviter-signed checkpoint");
        let package = super::space_bootstrap::SpaceWelcomeBootstrapV1::sign(
            &alice.identity,
            space_id,
            group_id.clone(),
            group_reference,
            1,
            welcome,
            created.genesis_event().encoded_bytes().to_vec(),
            genesis_plaintext,
            super::bootstrap_snapshot::encode_policy_snapshot(&policy)
                .expect("encode policy checkpoint"),
            invite_event.encoded_bytes().to_vec(),
            invite_plaintext,
            vec![invite_event.encoded_bytes().to_vec()],
            Some(control_event.encoded_bytes().to_vec()),
        )
        .expect("sign versioned bootstrap package")
        .to_bytes()
        .expect("encode bootstrap package");

        assert!(matches!(
            bob.join_space_from_welcome_bootstrap_from_x509_credential(
                &package,
                alice_fingerprint,
                vec![1],
            ),
            Err(CoreError::SpaceCredentialInvalid)
        ));
        assert!(matches!(
            bob.join_space_from_welcome_bootstrap(&package, alice_fingerprint, &bob_credential),
            Err(CoreError::SpaceWelcomeBootstrapUntrustedInviter)
        ));
        assert!(
            bob.store
                .load_space_genesis_snapshot(&space_id, &group_reference)
                .expect("check that rejected package persisted nothing")
                .is_none()
        );
        bob.pin_identity(
            &alice.identity.public_bundle().to_bytes(),
            alice_fingerprint,
        )
        .expect("pin inviter full fingerprint");
        let mut joined = bob
            .join_space_from_welcome_bootstrap(&package, alice_fingerprint, &bob_credential)
            .expect("validate pinned inviter package and import Welcome");
        assert_eq!(
            bob.store
                .available_key_package_count(0)
                .expect("consumption persists"),
            0
        );
        assert!(
            bob.join_space_from_welcome_bootstrap(&package, alice_fingerprint, &bob_credential)
                .is_err(),
            "a Welcome cannot reuse the consumed non-last-resort package"
        );
        let replacement = bob
            .replenish_key_packages(&bob_credential, 1, 0)
            .expect("replenish consumed package");
        assert_eq!(replacement.len(), 1);
        assert!(
            bob.discard_key_package(&replacement[0])
                .expect("discard package whose delivery was lost")
        );
        assert!(
            !bob.discard_key_package(&replacement[0])
                .expect("lost package cannot be discarded twice")
        );
        let recovered_package = bob
            .replenish_key_packages(&bob_credential, 1, 0)
            .expect("replace the lost package");
        assert_eq!(recovered_package.len(), 1);
        assert_ne!(recovered_package[0], replacement[0]);
        assert_eq!(joined.reducer().policy().expect("joined policy"), &policy);
        let charlie_database = TestDatabase::new();
        let mut charlie = Client::open_or_create(&charlie_database.0, &protector)
            .expect("initialize next recipient");
        let charlie_credential = test_credential(&charlie.identity);
        let charlie_fingerprint = charlie.identity.fingerprint();
        let charlie_key_package = charlie
            .with_mls_transaction(|identity, provider, _| {
                let key_package =
                    GroupState::publish_key_package(provider, identity, &charlie_credential)?;
                Ok::<_, CoreError>(key_package.as_bytes().to_vec())
            })
            .expect("publish next recipient KeyPackage");
        let charlie_key_package_hash =
            lattice_mls::api::key_package_wire_sha256(&charlie_key_package)
                .expect("hash next recipient KeyPackage");
        let charlie_invite_id = [0x43; 16];
        let charlie_invite_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(2)),
            (2, Value::Bytes(charlie_invite_id.to_vec())),
            (3, Value::Bytes(charlie_fingerprint.to_vec())),
            (4, Value::Bytes(charlie_key_package_hash.to_vec())),
            (5, Value::Null),
            (6, Value::Null),
        ]))
        .expect("encode next recipient invite");
        let charlie_invite_ciphertext = alice
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &created.group_id)?;
                let ciphertext = group.encrypt_application(
                    provider,
                    identity,
                    &alice_credential,
                    &charlie_invite_plaintext,
                )?;
                Ok::<_, CoreError>(ciphertext.as_bytes().to_vec())
            })
            .expect("encrypt invite for joined member");
        let charlie_invite = VerifiedSignatureOnlyEvent::create(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: 4,
                lamport: 4,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(invite_event_id)],
                kind: EventKind::Membership,
                protected_body: charlie_invite_ciphertext,
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        )
        .expect("sign next recipient invite");
        let charlie_invite_event_id = *charlie_invite.event_id().as_bytes();
        let charlie_invite_application = bob
            .with_mls_transaction(|_, provider, _| {
                let mut group = GroupState::load(provider, &created.group_id)?;
                match group.process_incoming(provider, charlie_invite.protected_body())? {
                    IncomingResult::Application(application) => Ok(application),
                    _ => Err(CoreError::MlsEventBindingFailed),
                }
            })
            .expect("authenticate invite at joined epoch");
        let bound_charlie_invite = bind_mls_application(charlie_invite, charlie_invite_application)
            .expect("bind authenticated invite");
        bob.with_mls_transaction(|_, _, transaction| {
            super::store_received_event(transaction, bound_charlie_invite.event())
        })
        .expect("store authenticated policy invite");
        let mut policy_before_add = joined.reducer().clone();
        assert_eq!(
            policy_before_add.apply(&bound_charlie_invite, None),
            super::space::ApplyResult::Applied { revision: 2 }
        );
        joined.reducer = policy_before_add.clone();

        let channel_id = created.reducer().policy().expect("Space policy").channels[0].id;
        let message_plaintext =
            super::encode_text_message("received over MLS").expect("encode message");
        let message_ciphertext = alice
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &created.group_id)?;
                let ciphertext = group.encrypt_application(
                    provider,
                    identity,
                    &alice_credential,
                    &message_plaintext,
                )?;
                Ok::<_, CoreError>(ciphertext.as_bytes().to_vec())
            })
            .expect("encrypt incoming application message");
        let message_event = VerifiedSignatureOnlyEvent::create(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: Some(channel_id),
                author_sequence: 5,
                lamport: 5,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(
                    charlie_invite_event_id,
                )],
                kind: EventKind::Message,
                protected_body: message_ciphertext,
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        )
        .expect("sign incoming message event");
        let message_id = *message_event.event_id().as_bytes();
        assert_eq!(
            bob.accept_synced_application_event(&mut joined, message_event.encoded_bytes())
                .expect("accept synced application event"),
            super::SyncedApplicationOutcome::Accepted {
                event_id: message_id
            }
        );
        assert_eq!(
            bob.accept_synced_application_event_for_local_generation(message_event.encoded_bytes())
                .expect("restore and recognize exact duplicate"),
            super::SyncedApplicationOutcome::Duplicate {
                event_id: message_id
            }
        );
        let missing_parent = [0x99; 32];
        let pending_event = VerifiedSignatureOnlyEvent::create(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: Some(channel_id),
                author_sequence: 6,
                lamport: 6,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(missing_parent)],
                kind: EventKind::Message,
                protected_body: message_event.protected_body().to_vec(),
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        )
        .expect("sign event with an unavailable parent");
        let pending_id = *pending_event.event_id().as_bytes();
        assert_eq!(
            bob.accept_synced_application_event(&mut joined, pending_event.encoded_bytes())
                .expect("retain event until its parent arrives"),
            super::SyncedApplicationOutcome::Pending {
                event_id: pending_id,
                missing_dependencies: vec![missing_parent],
            }
        );
        assert!(
            bob.store
                .resolve_pending(pending_id)
                .expect("remove test-only pending event")
        );
        let history = bob
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .expect("read received message history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_id, message_id);
        assert_eq!(history[0].author_id, alice_fingerprint);
        assert_eq!(history[0].content, "received over MLS");
        let received_search = bob
            .search_local_text_messages(&space_id, &group_reference, &channel_id, "RECEIVED")
            .expect("search authorized received message projection offline");
        assert_eq!(received_search.total_matches, 1);
        assert_eq!(received_search.messages[0].event_id, message_id);
        assert_eq!(received_search.messages[0].content, "received over MLS");
        let edit_plaintext =
            super::encode_text_edit(message_id, "edited over MLS").expect("encode edit");
        let edit_ciphertext = alice
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &created.group_id)?;
                let ciphertext = group.encrypt_application(
                    provider,
                    identity,
                    &alice_credential,
                    &edit_plaintext,
                )?;
                Ok::<_, CoreError>(ciphertext.as_bytes().to_vec())
            })
            .expect("encrypt incoming edit");
        let edit_event = VerifiedSignatureOnlyEvent::create(
            &alice.identity,
            EventDraft {
                space_id,
                channel_id: Some(channel_id),
                author_sequence: 6,
                lamport: 6,
                wall_time_hint: 0,
                parents: vec![lattice_protocol::EventId::from_bytes(message_id)],
                kind: EventKind::Edit,
                protected_body: edit_ciphertext,
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        )
        .expect("sign incoming edit");
        assert!(matches!(
            bob.accept_synced_application_event(&mut joined, edit_event.encoded_bytes())
                .expect("accept synced edit"),
            super::SyncedApplicationOutcome::Accepted { .. }
        ));
        let edited_history = bob
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .expect("read edited incoming history");
        assert_eq!(edited_history.len(), 1);
        assert_eq!(edited_history[0].event_id, message_id);
        assert_eq!(edited_history[0].content, "edited over MLS");
        let remote_draft = |sequence, kind, parents| EventDraft {
            space_id,
            channel_id: Some(channel_id),
            author_sequence: sequence,
            lamport: sequence,
            wall_time_hint: 0,
            parents,
            kind,
            protected_body: Vec::new(),
            mls_group_reference: group_reference,
            mls_epoch: 1,
        };
        let tombstone_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(message_id.to_vec())),
            (2, Value::Unsigned(0)),
            (3, Value::Null),
        ]))
        .expect("encode remote tombstone");
        let tombstone_id = deliver_remote_application(
            &mut alice,
            &mut bob,
            &mut joined,
            &created.group_id,
            &alice_credential,
            remote_draft(
                7,
                EventKind::Tombstone,
                vec![lattice_protocol::EventId::from_bytes(message_id)],
            ),
            &tombstone_plaintext,
        );
        let deleted_search = bob
            .search_local_text_messages(&space_id, &group_reference, &channel_id, "edited over MLS")
            .expect("search excludes tombstoned cached content");
        assert_eq!(deleted_search.total_matches, 0);
        assert!(
            bob.local_text_message_history(&space_id, &group_reference, &channel_id)
                .expect("history excludes tombstoned cached content")
                .is_empty()
        );
        let history = joined.reducer().message_history(&channel_id);
        let projected = history
            .messages()
            .iter()
            .find(|message| message.event_id == message_id)
            .expect("remote tombstone target remains projected");
        assert!(projected.is_deleted());
        assert_eq!(projected.tombstones.len(), 1);
        assert_eq!(projected.tombstones[0].event_id, tombstone_id);

        let reaction_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(message_id.to_vec())),
            (2, Value::Text("wave".into())),
            (3, Value::Unsigned(0)),
            (4, Value::Null),
        ]))
        .expect("encode remote reaction");
        let reaction_event = encrypted_application_event(
            &mut alice,
            &created.group_id,
            &alice_credential,
            remote_draft(
                8,
                EventKind::Reaction,
                vec![lattice_protocol::EventId::from_bytes(message_id)],
            ),
            &reaction_plaintext,
        );
        let reaction_id = *reaction_event.event_id().as_bytes();
        let reaction_remove_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(message_id.to_vec())),
            (2, Value::Text("wave".into())),
            (3, Value::Unsigned(1)),
            (4, Value::Bytes(reaction_id.to_vec())),
        ]))
        .expect("encode remote reaction removal");
        let reaction_remove_event = encrypted_application_event(
            &mut alice,
            &created.group_id,
            &alice_credential,
            remote_draft(
                9,
                EventKind::Reaction,
                vec![lattice_protocol::EventId::from_bytes(reaction_id)],
            ),
            &reaction_remove_plaintext,
        );
        let reaction_remove_id = *reaction_remove_event.event_id().as_bytes();
        assert_eq!(
            bob.accept_synced_application_event(
                &mut joined,
                reaction_remove_event.encoded_bytes(),
            )
            .expect("retain remove before its referenced add"),
            super::SyncedApplicationOutcome::Pending {
                event_id: reaction_remove_id,
                missing_dependencies: vec![reaction_id],
            }
        );
        assert_eq!(
            bob.accept_synced_application_event(&mut joined, reaction_event.encoded_bytes())
                .expect("accept remote reaction add"),
            super::SyncedApplicationOutcome::Accepted {
                event_id: reaction_id
            }
        );
        let reaction_history = joined.reducer().message_history(&channel_id);
        let projected = reaction_history
            .messages()
            .iter()
            .find(|message| message.event_id == message_id)
            .expect("remote reaction target remains projected");
        assert_eq!(projected.reactions[0].active_tags, vec![reaction_id]);
        assert_eq!(
            bob.retry_ready_synced_application_events(&mut joined)
                .expect("retry now-ready remote reaction removal"),
            vec![super::SyncedApplicationOutcome::Accepted {
                event_id: reaction_remove_id
            }]
        );

        let pin_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(message_id.to_vec())),
            (2, Value::Bool(true)),
            (3, Value::Null),
        ]))
        .expect("encode remote pin");
        let pin_event = encrypted_application_event(
            &mut alice,
            &created.group_id,
            &alice_credential,
            remote_draft(
                10,
                EventKind::Pin,
                vec![lattice_protocol::EventId::from_bytes(message_id)],
            ),
            &pin_plaintext,
        );
        let pin_id = *pin_event.event_id().as_bytes();
        let pin_remove_plaintext = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(message_id.to_vec())),
            (2, Value::Bool(false)),
            (3, Value::Bytes(pin_id.to_vec())),
        ]))
        .expect("encode remote pin removal");
        let pin_remove_event = encrypted_application_event(
            &mut alice,
            &created.group_id,
            &alice_credential,
            remote_draft(
                11,
                EventKind::Pin,
                vec![lattice_protocol::EventId::from_bytes(pin_id)],
            ),
            &pin_remove_plaintext,
        );
        let pin_remove_id = *pin_remove_event.event_id().as_bytes();
        assert_eq!(
            bob.accept_synced_application_event(&mut joined, pin_remove_event.encoded_bytes())
                .expect("retain pin remove before its referenced add"),
            super::SyncedApplicationOutcome::Pending {
                event_id: pin_remove_id,
                missing_dependencies: vec![pin_id],
            }
        );
        assert_eq!(
            bob.accept_synced_application_event(&mut joined, pin_event.encoded_bytes())
                .expect("accept remote pin add"),
            super::SyncedApplicationOutcome::Accepted { event_id: pin_id }
        );
        let pin_history = joined.reducer().message_history(&channel_id);
        let projected = pin_history
            .messages()
            .iter()
            .find(|message| message.event_id == message_id)
            .expect("remote pin target remains projected");
        assert!(projected.is_pinned());
        assert_eq!(projected.pin_tags, vec![pin_id]);
        assert_eq!(
            bob.retry_ready_synced_application_events(&mut joined)
                .expect("retry now-ready remote pin removal"),
            vec![super::SyncedApplicationOutcome::Accepted {
                event_id: pin_remove_id
            }]
        );
        let updated_history = joined.reducer().message_history(&channel_id);
        let projected = updated_history
            .messages()
            .iter()
            .find(|message| message.event_id == message_id)
            .expect("remote update target remains projected");
        assert!(projected.is_deleted());
        assert!(projected.reactions.is_empty());
        assert!(!projected.is_pinned());

        let (control, transition) = alice
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &created.group_id)?;
                let prepared = group.prepare_add(
                    provider,
                    identity,
                    &alice_credential,
                    &charlie_key_package,
                )?;
                let commit = prepared.commit().as_bytes().to_vec();
                let control = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id,
                        channel_id: None,
                        author_sequence: 12,
                        lamport: 12,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(
                            charlie_invite_event_id,
                        )],
                        kind: EventKind::MlsControl,
                        protected_body: commit.clone(),
                        mls_group_reference: group_reference,
                        mls_epoch: 1,
                    },
                )?;
                let control_id = *control.event_id().as_bytes();
                let transition_plaintext = encode_canonical(&Value::Map(vec![
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(6)),
                    (2, Value::Unsigned(0)),
                    (3, Value::Bytes(charlie_fingerprint.to_vec())),
                    (4, Value::Bytes(charlie_invite_event_id.to_vec())),
                    (5, Value::Bytes(control_id.to_vec())),
                ]))
                .expect("encode admission transition");
                let transition_ciphertext = group.encrypt_application_for_pending_membership(
                    provider,
                    identity,
                    &alice_credential,
                    &prepared,
                    &transition_plaintext,
                )?;
                let transition = VerifiedSignatureOnlyEvent::create(
                    identity,
                    EventDraft {
                        space_id,
                        channel_id: None,
                        author_sequence: 13,
                        lamport: 13,
                        wall_time_hint: 0,
                        parents: vec![lattice_protocol::EventId::from_bytes(control_id)],
                        kind: EventKind::Membership,
                        protected_body: transition_ciphertext.as_bytes().to_vec(),
                        mls_group_reference: group_reference,
                        mls_epoch: 1,
                    },
                )?;
                let _welcome = group.accept_prepared_add(provider, &prepared, &commit)?;
                Ok::<_, CoreError>((control, transition))
            })
            .expect("commit next membership transition");
        let updated = bob
            .accept_space_membership_transition(
                &created.group_id,
                &policy_before_add,
                control,
                transition,
            )
            .expect("accept authenticated transition after Welcome");
        assert!(updated.policy().is_some_and(|current| {
            current.revision == 3
                && current.members.iter().any(|member| {
                    member.fingerprint == charlie_fingerprint
                        && member.status == super::space::MemberStatus::Active
                })
        }));

        let mut tampered = package.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(super::space_bootstrap::SpaceWelcomeBootstrapV1::from_bytes(&tampered).is_err());

        drop(joined);
        drop(bob);
        let mut reopened =
            Client::open_existing(&bob_database.0, &protector).expect("reopen recipient");
        let restored = reopened
            .restore_space(&space_id, &group_reference)
            .expect("restore joined checkpoint and Welcome group");
        let restored_policy = restored.reducer().policy().expect("restored policy");
        assert_eq!(restored_policy.revision, 3);
        assert!(restored_policy.members.iter().any(|member| {
            member.fingerprint == charlie_fingerprint
                && member.status == super::space::MemberStatus::Active
        }));
        assert_eq!(
            restored.reducer().status(),
            super::space::ReducerStatus::Active { revision: 3 }
        );
        let epoch_before_leave = reopened
            .with_mls_transaction(|_, provider, _| {
                Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
            })
            .expect("read joined epoch");
        let leave_event_id = reopened
            .request_space_leave(&restored, &bob_credential)
            .expect("queue authenticated self-removal request");
        let leave_record = reopened
            .store
            .load_event(&leave_event_id)
            .expect("read queued Leave event")
            .expect("queued Leave event exists");
        let leave_event = VerifiedSignatureOnlyEvent::decode_verify(&leave_record.canonical_bytes)
            .expect("verify queued Leave event");
        assert_eq!(leave_event.kind(), EventKind::MlsControl);
        assert_eq!(leave_event.author_fingerprint(), &bob_fingerprint);
        assert_eq!(leave_event.mls_epoch(), epoch_before_leave);
        assert_eq!(
            reopened
                .store
                .list_outbox_page(None, 10)
                .expect("read queued Leave outbox")
                .iter()
                .filter(|entry| entry.event_id == leave_event_id)
                .count(),
            1
        );
    }

    #[test]
    fn direct_message_packets_cross_profiles_and_survive_restart() {
        let alice_database = TestDatabase::new();
        let bob_database = TestDatabase::new();
        let protector = TestProtector;
        let mut alice =
            Client::open_or_create(&alice_database.0, &protector).expect("initialize Alice");
        let mut bob = Client::open_or_create(&bob_database.0, &protector).expect("initialize Bob");
        let alice_credential = test_credential(&alice.identity);
        let bob_credential = test_credential(&bob.identity);
        let alice_fingerprint = alice.identity.fingerprint();
        let bob_fingerprint = bob.identity.fingerprint();
        let bob_key_package = bob
            .publish_key_package(&bob_credential, 0)
            .expect("publish Bob KeyPackage");

        let created = alice
            .create_direct_message(&alice_credential, bob_fingerprint, &bob_key_package, 0)
            .expect("create durable direct-message pair");
        let group_reference = created.group_reference;
        assert_eq!(created.peer_identity, bob_fingerprint);
        let mut bob = accept_pending_dm_invitation(
            bob,
            &bob_database,
            &protector,
            &bob_credential,
            alice_fingerprint,
            &created,
        );

        let queued = alice
            .queue_direct_message_text(
                &alice_credential,
                group_reference,
                "hello over the pinned MLS pair",
                1,
            )
            .expect("commit encrypted direct-message outbox packet");
        alice
            .mark_direct_message_attempt(queued.packet_id, 2)
            .expect("persist transport attempt");
        assert!(matches!(
            bob.ingest_direct_message_packet(alice_fingerprint, &queued.envelope_bytes)
                .expect("authenticate cross-profile packet"),
            DirectMessageIngressOutcome::Accepted { content, .. }
                if content == "hello over the pinned MLS pair"
        ));
        assert!(matches!(
            bob.ingest_direct_message_packet(alice_fingerprint, &queued.envelope_bytes)
                .expect("deduplicate transport retry"),
            DirectMessageIngressOutcome::Duplicate { .. }
        ));
        alice
            .record_direct_message_peer_ingress_accepted(queued.packet_id)
            .expect("record peer-ingress receipt");

        let history = bob
            .direct_message_history(group_reference, 10)
            .expect("read decrypted local DM history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].author_identity, alice_fingerprint);
        assert_eq!(history[0].content, "hello over the pinned MLS pair");
        assert!(
            bob.direct_message_outbox_page(None, 10)
                .expect("read empty recipient outbox")
                .is_empty()
        );
        let alice_outbox = alice
            .direct_message_outbox_page(None, 10)
            .expect("read durable sender outbox");
        assert_eq!(alice_outbox.len(), 2);
        assert!(alice_outbox.iter().any(|entry| {
            entry.packet_id == queued.packet_id && entry.state == OutboxState::PeerIngressAccepted
        }));

        drop(alice);
        drop(bob);
        let mut reopened =
            Client::open_existing(&bob_database.0, &protector).expect("reopen Bob profile");
        let restored_history = reopened
            .direct_message_history(group_reference, 10)
            .expect("restore protected direct-message history");
        assert_eq!(restored_history, history);
        assert!(matches!(
            reopened.ingest_direct_message_packet([0x99; 32], &queued.envelope_bytes),
            Err(CoreError::DirectMessagePeerMismatch)
        ));
    }

    fn accept_pending_dm_invitation(
        mut bob: Client,
        database: &TestDatabase,
        protector: &TestProtector,
        credential: &DeviceCredentialInput,
        sender: [u8; 32],
        created: &super::CreatedDirectMessage,
    ) -> Client {
        let group_reference = created.group_reference;
        assert!(matches!(
            bob.ingest_direct_message_packet(sender, &created.invitation.envelope_bytes)
                .expect("retain invitation from authenticated peer"),
            DirectMessageIngressOutcome::InvitationPending {
                packet_id,
                group_reference: pending_group,
                peer_identity,
            } if packet_id == created.invitation.packet_id
                && pending_group == group_reference
                && peer_identity == sender
        ));
        assert!(matches!(
            bob.ingest_direct_message_packet(sender, &created.invitation.envelope_bytes)
                .expect("deduplicate pending invitation retry"),
            DirectMessageIngressOutcome::Duplicate { packet_id }
                if packet_id == created.invitation.packet_id
        ));
        assert_eq!(
            bob.pending_direct_message_invitations(10)
                .expect("list pending invitation")
                .len(),
            1
        );
        drop(bob);
        let mut bob =
            Client::open_existing(&database.0, protector).expect("reopen Bob pending profile");
        assert!(matches!(
            bob.accept_pending_direct_message_invitation(
                credential,
                sender,
                created.invitation.packet_id,
                false,
            ),
            Err(CoreError::DirectMessagePacketInvalid)
        ));
        assert_eq!(
            bob.accept_pending_direct_message_invitation(
                credential,
                sender,
                created.invitation.packet_id,
                true,
            )
            .expect("accept persisted invitation after restart"),
            group_reference
        );
        bob
    }
    #[allow(clippy::too_many_lines)] // Keep membership, protection, ingress, and restart assertions together.
    #[test]
    fn relay_mailbox_control_requires_admission_and_restores_only_exact_generation() {
        let alice_database = TestDatabase::new();
        let bob_database = TestDatabase::new();
        let protector = TestProtector;
        let mut alice =
            Client::open_or_create(&alice_database.0, &protector).expect("initialize inviter");
        let mut bob =
            Client::open_or_create(&bob_database.0, &protector).expect("initialize invitee");
        let alice_credential = test_credential(&alice.identity);
        let bob_credential = test_credential(&bob.identity);
        let alice_fingerprint = alice.identity.fingerprint();
        let mut created = alice
            .create_space(
                &alice_credential,
                vec![InitialChannel {
                    channel_type: super::space::ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create inviter Space");
        let space_id = *created.space_id();
        let old_group_reference = *created.group_reference();
        assert!(matches!(
            alice.publish_space_relay_mailbox_control(&created, &alice_credential, 1_000_000),
            Err(CoreError::SpaceRelayMailboxRequiresAdmission)
        ));
        assert_eq!(
            alice
                .space_relay_mailbox(&space_id, &old_group_reference)
                .expect("read absent mailbox"),
            None
        );

        let key_package = bob
            .publish_key_package(&bob_credential, 100)
            .expect("publish invitee KeyPackage");
        let invitation = alice
            .create_space_invite(
                &mut created,
                &alice_credential,
                &key_package,
                None,
                2_000,
                Some(1),
            )
            .expect("admit invitee");
        bob.pin_identity(
            &alice.identity.public_bundle().to_bytes(),
            alice_fingerprint,
        )
        .expect("pin inviter");
        let mut joined = bob
            .join_space_from_welcome_bootstrap(
                invitation.welcome_bootstrap(),
                alice_fingerprint,
                &bob_credential,
            )
            .expect("import admitted MLS generation");

        let published = alice
            .publish_space_relay_mailbox_control(&created, &alice_credential, 3_000_000)
            .expect("queue protected mailbox control after admission");
        let mailbox = published.mailbox();
        let local_ciphertext = alice
            .store
            .load_space_relay_mailbox(&space_id, &old_group_reference)
            .expect("read protected mailbox record")
            .expect("mailbox is persisted locally");
        assert_ne!(local_ciphertext.as_slice(), mailbox.as_bytes().as_slice());
        assert_eq!(
            alice
                .space_relay_mailbox(&space_id, &old_group_reference)
                .expect("decrypt local mailbox"),
            Some(mailbox)
        );
        let control_record = alice
            .store
            .load_event(published.event_id())
            .expect("load queued mailbox control")
            .expect("control event is durable");
        let control = VerifiedSignatureOnlyEvent::decode_verify(&control_record.canonical_bytes)
            .expect("verify signed mailbox control");
        assert_eq!(control.kind(), EventKind::RelayMailboxControl);
        assert_ne!(control.protected_body(), mailbox.as_bytes().as_slice());
        assert!(matches!(
            bob.accept_synced_application_event(&mut joined, &control_record.canonical_bytes)
                .expect("accept MLS-protected mailbox control"),
            super::SyncedApplicationOutcome::Accepted { event_id }
                if event_id == *published.event_id()
        ));
        assert_eq!(
            bob.space_relay_mailbox(&space_id, &old_group_reference)
                .expect("read received mailbox"),
            Some(mailbox)
        );
        assert!(matches!(
            bob.publish_space_relay_mailbox_control(&joined, &bob_credential, 3_100_000),
            Err(CoreError::SpaceControlRejected(
                super::space::RejectReason::Unauthorized
            ))
        ));

        drop(bob);
        let mut reopened_bob =
            Client::open_existing(&bob_database.0, &protector).expect("reopen invitee profile");
        reopened_bob
            .restore_space(&space_id, &old_group_reference)
            .expect("restore admitted generation");
        assert_eq!(
            reopened_bob
                .space_relay_mailbox(&space_id, &old_group_reference)
                .expect("restore protected mailbox token"),
            Some(mailbox)
        );

        let recovered = alice
            .create_space_recovery_generation(&created, &alice_credential)
            .expect("create new recovery generation");
        assert_ne!(recovered.group_reference(), &old_group_reference);
        assert_eq!(
            alice
                .space_relay_mailbox(&space_id, recovered.group_reference())
                .expect("new generation has no inherited mailbox"),
            None
        );
    }
}
