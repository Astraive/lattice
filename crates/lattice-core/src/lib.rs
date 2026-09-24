//! Lattice local device core.
//!
//! The facade owns a durable store and device identity. It binds verified
//! events to MLS results and can atomically create local candidate Spaces or
//! stage application authorization with exact event bytes in a caller-owned
//! `SQLite` transaction. It also atomically validates a parent-epoch member
//! transition, merges its staged MLS Commit, and stores both exact signed event
//! records. Durable reducer replay, Welcome-based Space join, and durable MLS
//! conflict recovery remain incomplete.

use std::collections::BTreeSet;
use std::path::Path;

use rusqlite::Transaction;

use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
use lattice_identity::{DeviceIdentity, IdentityError, IdentityPublicBundle, PrivateKeyProtector};
use lattice_mls::{
    ProtectedCodecError, ProtectedSqliteProvider,
    api::{DeviceCredentialInput, GroupState, IncomingResult, MlsApplication},
    migrate_protected_sqlite, with_mls_storage_key,
};
use lattice_protocol::{Value, decode_canonical, encode_canonical};
use lattice_storage::{
    CachedSpaceMessage, CommitOutcome, MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE,
    MAX_SPACE_GENESIS_PAGE_SIZE, SpaceGenesisSnapshot, Store, StoreError,
};
pub use lattice_storage::{OutboxState, SpaceGenesisCursor};
use openmls::credentials::Credential;
use openmls::prelude::CredentialType;
use thiserror::Error;
use zeroize::Zeroizing;

mod identity_pin;
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

/// Result of creating a local candidate Space and its one-member MLS generation.
pub struct CreatedSpace {
    space_id: space::SpaceId,
    group_id: Vec<u8>,
    group_reference: space::GroupReference,
    genesis_event: VerifiedSignatureOnlyEvent,
    reducer: space::SpaceReducer,
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
/// One locally retained, authorized outgoing text message.
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
    /// Locally generated Space genesis did not satisfy its exact policy schema.
    #[error("candidate Space genesis rejected: {0:?}")]
    SpaceGenesisRejected(space::RejectReason),
    /// The production X.509 credential failed validation against the local identity.
    #[error("Space X.509 credential validation failed")]
    SpaceCredentialInvalid,
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
    /// The policy membership transition was not applied.
    #[error("Space membership policy transition not applied: {0:?}")]
    SpaceMembershipNotApplied(space::ApplyResult),
    /// A received author sequence is occupied by a different event ID.
    #[error("received author sequence conflicts with event {existing_event_id:02x?}")]
    ReceivedEventEquivocation { existing_event_id: [u8; 32] },
    /// An encrypted local message cache row failed event binding or validation.
    #[error("local Space message cache entry is invalid")]
    LocalSpaceMessageCacheInvalid,
    /// A locally authored message failed the Space policy gate.
    #[error("Space message rejected: {0:?}")]
    SpaceMessageRejected(space::EventAuthorization),
    /// One of the current policy-head events is missing from local storage.
    #[error("a Space policy parent event is missing")]
    SpaceParentEventMissing,
    /// The Lamport counter cannot advance beyond the parent events.
    #[error("Space message Lamport counter is exhausted")]
    SpaceLamportExhausted,
    /// A locally created Space Genesis or encrypted projection snapshot is absent.
    #[error("local Space Genesis snapshot was not found")]
    SpaceGenesisSnapshotNotFound,
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

fn decode_text_message(plaintext: &[u8]) -> Result<String, CoreError> {
    let Value::Map(fields) = decode_canonical(plaintext)? else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    let mut fields = fields.into_iter();
    if fields.next() != Some((0, Value::Unsigned(1))) {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    let Some((1, Value::Text(content))) = fields.next() else {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    };
    if fields.next() != Some((2, Value::Null))
        || fields.next() != Some((3, Value::Bool(false)))
        || fields.next() != Some((4, Value::Array(Vec::new())))
        || fields.next().is_some()
    {
        return Err(CoreError::LocalSpaceMessageCacheInvalid);
    }
    Ok(content)
}

fn create_space_in_transaction(
    identity: &DeviceIdentity,
    provider: &ProtectedSqliteProvider<'_>,
    transaction: &Transaction<'_>,
    credential: &lattice_mls::api::DeviceCredentialInput,
    space_id: space::SpaceId,
    plaintext: Vec<u8>,
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
    match reducer.apply(&bound, None) {
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
        Self::finish_open(store, identity, protector)
    }

    /// Opens a profile only when its protected device identity already exists.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the store, protected identity, or protected MLS
    /// storage cannot be opened.
    pub fn open_existing<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
    ) -> Result<Self, CoreError> {
        let store = Store::open(database_path)?;
        let ciphertext = store
            .load_protected_identity()?
            .ok_or(CoreError::MissingIdentity)?;
        let identity = DeviceIdentity::load_protected(protector, &ciphertext)?;
        Self::finish_open(store, identity, protector)
    }

    fn finish_open<P: PrivateKeyProtector>(
        mut store: Store,
        identity: DeviceIdentity,
        protector: &P,
    ) -> Result<Self, CoreError> {
        store.with_connection_mut(|connection| {
            migrate_protected_sqlite(connection).map_err(|_| CoreError::MlsStorageMigration)
        })?;
        let mls_storage_key = load_or_create_mls_storage_key(&mut store, protector)?;
        Ok(Self {
            store,
            identity,
            mls_storage_key,
        })
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
    /// Creates a local candidate Space from a system-trusted RFC 9420 X.509 credential vector.
    ///
    /// The credential content is leaf-first TLS certificate-vector bytes. It is
    /// validated against this client's signing identity and the production OS
    /// trust path before the atomic Space-creation transaction is entered.
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
        let credential = DeviceCredentialInput::from_x509_credential(&self.identity, credential)
            .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        self.create_space(&credential, channels)
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
        let policy = created
            .reducer
            .policy()
            .ok_or(CoreError::SpaceGenesisRejected(
                space::RejectReason::MissingPolicy,
            ))?;
        let (parents, lamport) = resolve_policy_parents(&self.store, policy)?;
        let plaintext = encode_text_message(content)?;
        let message = LocalTextMessage {
            group_id: created.group_id.clone(),
            credential,
            reducer: &created.reducer,
            space_id: created.space_id,
            group_reference: created.group_reference,
            channel_id,
            parents,
            lamport,
            plaintext,
        };
        let (receipt, staged_reducer) =
            self.with_mls_transaction(|identity, provider, transaction| {
                queue_text_message_in_transaction(identity, provider, transaction, message)
            })?;
        created.reducer = staged_reducer;
        Ok(receipt)
    }

    /// Restores the local Genesis policy, validates an RFC 9420 X.509 credential,
    /// then encrypts and atomically queues a text message without network I/O.
    ///
    /// This recovery path is limited to a locally created, unchanged generation;
    /// a later MLS membership transition is rejected rather than authorized
    /// against stale Genesis policy.
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
        let credential = DeviceCredentialInput::from_x509_credential(&self.identity, credential)
            .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        let mut created = self.restore_space(space_id, group_reference)?;
        self.queue_text_message(&mut created, &credential, channel_id, content)
    }
    /// Returns the newest bounded local outgoing-message history for one channel.
    ///
    /// encrypted cache entries. Incoming messages and rows beyond the latest
    /// [`MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE`] are not included.
    ///
    /// # Errors
    ///
    /// Returns an error if the local Genesis generation cannot be restored,
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
                    || event.mls_epoch() != 0
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
                let content = decode_text_message(&plaintext)?;
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

    /// Restores a locally created Space policy projection after process restart.
    ///
    /// The event, MLS group, and AEAD-protected initial policy payload are
    /// independently checked against the requested Space and MLS generation.
    /// This restores local Genesis only; it does not recover later policy
    /// mutations, incoming groups, or in-memory MLS conflict evidence.
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
        let space_id = snapshot.space_id;
        let expected_group_reference = snapshot.group_reference;
        let event_id = snapshot.event_id;
        let group_id = snapshot.group_id;
        let group_id_for_load = group_id.clone();
        let encrypted_state = snapshot.encrypted_state;
        let context = space_genesis_context(&space_id, &expected_group_reference, &event_id);
        let restored_event = event.clone();
        let (group_reference, reducer) =
            self.with_mls_transaction(move |identity, provider, _transaction| {
                if event.author_fingerprint() != &identity.fingerprint() {
                    return Err(CoreError::SpaceGenesisRejected(
                        space::RejectReason::CreatorMismatch,
                    ));
                }
                let group = lattice_mls::api::GroupState::load(provider, &group_id_for_load)?;
                let group_reference = group.group_reference();
                if group_reference != expected_group_reference
                    || group.epoch() != 0
                    || group.member_count() != 1
                {
                    return Err(CoreError::SpaceGenesisRejected(
                        space::RejectReason::WrongGeneration,
                    ));
                }
                let plaintext = lattice_mls::unprotect_local_record(&context, &encrypted_state)?;
                let bound = MlsBoundEvent { event, plaintext };
                let mut reducer = space::SpaceReducer::new();
                match reducer.apply(&bound, None) {
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

    /// Atomically accepts one staged MLS Commit and its parent-epoch policy transition.
    ///
    /// `control_event` must carry the exact TLS Commit in its protected body.
    /// `transition_event` must carry MLS application data authenticated in the
    /// Commit's parent epoch and must pass the reducer's invite/transition
    /// policy. The Commit remains staged until that transition is accepted. The
    /// MLS group writes and both verified event records share one `SQLite`
    /// transaction. The returned reducer is a candidate; callers install it
    /// only after this method commits. Reducer replay after process restart is
    /// not implemented.
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
        let Some(policy) = reducer.policy() else {
            return Err(CoreError::SpaceMembershipNotApplied(
                space::ApplyResult::Rejected(space::RejectReason::MissingPolicy),
            ));
        };
        let expected_group_reference = policy.group_reference;
        let group_id = group_id.to_vec();
        let mut staged_reducer = reducer.clone();
        self.with_mls_transaction(move |_identity, provider, transaction| {
            let mut group = GroupState::load(provider, &group_id)?;
            if group.group_reference() != expected_group_reference {
                return Err(CoreError::SpaceMembershipNotApplied(
                    space::ApplyResult::Rejected(space::RejectReason::WrongGeneration),
                ));
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
            staged_reducer
                .observe_validated_control_event(&control_event, proof)
                .map_err(CoreError::SpaceControlRejected)?;

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
            store_received_event(transaction, &control_event)?;
            store_received_event(transaction, bound.event())?;
            group.accept_incoming_commit(provider, commit_wire)?;
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
}

struct LocalTextMessage<'a> {
    group_id: Vec<u8>,
    credential: &'a DeviceCredentialInput,
    reducer: &'a space::SpaceReducer,
    space_id: space::SpaceId,
    group_reference: space::GroupReference,
    channel_id: space::EntityId,
    parents: Vec<lattice_protocol::EventId>,
    lamport: u64,
    plaintext: Vec<u8>,
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

fn encode_text_message(content: &str) -> Result<Vec<u8>, CoreError> {
    if content.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    let plaintext = encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Text(content.to_owned())),
        (2, Value::Null),
        (3, Value::Bool(false)),
        (4, Value::Array(Vec::new())),
    ]))?;
    if plaintext.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(CoreError::SpaceMessageRejected(
            space::EventAuthorization::Rejected(space::RejectReason::PayloadTooLarge),
        ));
    }
    Ok(plaintext)
}

fn queue_text_message_in_transaction(
    identity: &DeviceIdentity,
    provider: &ProtectedSqliteProvider<'_>,
    transaction: &Transaction<'_>,
    message: LocalTextMessage<'_>,
) -> Result<(QueuedMessage, space::SpaceReducer), CoreError> {
    let mut group = GroupState::load(provider, &message.group_id)?;
    if group.group_reference() != message.group_reference
        || group.epoch() != 0
        || group.member_count() != 1
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
            wall_time_hint: 0,
            parents: message.parents,
            kind: EventKind::Message,
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
    let event_id = *event.event_id().as_bytes();
    let context = local_text_message_context(
        &message.space_id,
        &message.group_reference,
        &message.channel_id,
        &event_id,
    );
    let encrypted_content = lattice_mls::protect_local_record(&context, bound.plaintext())?;
    Store::save_cached_space_message_in_transaction(
        transaction,
        &CachedSpaceMessage {
            event_id,
            space_id: message.space_id,
            group_reference: message.group_reference,
            channel_id: message.channel_id,
            author_id: *event.author_fingerprint(),
            author_seq: sequence,
            lamport: event.lamport(),
            encrypted_content,
            outbox_state: None,
        },
    )?;
    Ok((
        QueuedMessage {
            event_id: *event.event_id().as_bytes(),
        },
        staged_reducer,
    ))
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{Client, CoreError, InitialChannel, bind_mls_application};
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
            .queue_text_message(&mut created, &credential, channel_id, "queued offline")
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
        assert_eq!(
            created.reducer().message_history(&channel_id).messages()[0]
                .current_version()
                .content
                .as_ref(),
            "queued offline"
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
            match GroupState::load(provider, &rolled_back_group_id) {
                Ok(_) => Ok(()),
                Err(error) => Err(CoreError::Mls(error)),
            }
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
        let charlie_identity = DeviceIdentity::generate().expect("Charlie identity");
        let charlie_credential = test_credential(&charlie_identity);
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
        let group_id = created.group_id().to_vec();
        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        let mut reducer = created.reducer().clone();
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

        let charlie_provider = OpenMlsRustCrypto::default();
        let charlie_key_package = GroupState::publish_key_package(
            &charlie_provider,
            &charlie_identity,
            &charlie_credential,
        )
        .expect("publish Charlie KeyPackage");
        let charlie_key_package_hash =
            lattice_mls::api::key_package_wire_sha256(charlie_key_package.as_bytes())
                .expect("hash bounded Charlie KeyPackage");
        let invite_id = [0x71; 16];
        let invite_payload = encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(2)),
            (2, Value::Bytes(invite_id.to_vec())),
            (3, Value::Bytes(charlie_identity.fingerprint().to_vec())),
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
        let invite_application = bob
            .with_mls_transaction(|_, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                match group.process_incoming(provider, invite.protected_body())? {
                    IncomingResult::Application(application) => Ok(application),
                    _ => Err(CoreError::MlsEventBindingFailed),
                }
            })
            .expect("authenticate invite application with Bob's group");
        let bound_invite = bind_mls_application(invite.clone(), invite_application)
            .expect("bind exact invite ciphertext");
        assert_eq!(
            reducer.apply(&bound_invite, None),
            super::space::ApplyResult::Applied { revision: 1 }
        );
        let invite_event_id = *invite.event_id().as_bytes();

        let (control_event, transition_event) = alice
            .with_mls_transaction(|identity, provider, _transaction| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared = group.prepare_add(
                    provider,
                    identity,
                    &alice_credential,
                    charlie_key_package.as_bytes(),
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
                    (3, Value::Bytes(charlie_identity.fingerprint().to_vec())),
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
                group.accept_prepared_add(provider, &prepared, &commit_wire)?;
                Ok::<_, CoreError>((control, transition))
            })
            .expect("prepare and commit Charlie add");

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
        let updated = bob
            .accept_space_membership_transition(
                &group_id,
                &reducer,
                control_event.clone(),
                transition_event.clone(),
            )
            .expect("commit MLS merge and admitted policy transition atomically");
        let policy = updated.policy().expect("active updated policy");
        assert_eq!(
            policy
                .members
                .iter()
                .find(|member| { member.fingerprint == charlie_identity.fingerprint() })
                .map(|member| member.status),
            Some(super::space::MemberStatus::Active)
        );
        assert_eq!(policy.invites[0].uses, 1);
        let committed_epoch = bob
            .with_mls_transaction(|_, provider, _transaction| {
                Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
            })
            .expect("reload committed Bob group");
        assert_eq!(committed_epoch, 2);
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
    }

    #[test]
    fn existing_profile_open_fails_closed_when_identity_is_missing() {
        let database = TestDatabase::new();
        assert!(matches!(
            Client::open_existing(&database.0, &TestProtector),
            Err(CoreError::MissingIdentity)
        ));
    }
}
