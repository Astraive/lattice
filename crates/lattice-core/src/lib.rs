//! Lattice local device core.
//!
//! The facade owns a durable store and device identity. It binds verified
//! events to MLS results and can atomically create local candidate Spaces or
//! stage application authorization with exact event bytes in a caller-owned
//! `SQLite` transaction. Membership trust, Space join, later policy replay, and
//! durable MLS conflict recovery remain incomplete.

use std::collections::BTreeSet;
use std::path::Path;

use rusqlite::Transaction;

use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
use lattice_identity::{DeviceIdentity, IdentityError, IdentityPublicBundle, PrivateKeyProtector};
use lattice_mls::{
    ProtectedCodecError, ProtectedSqliteProvider, api::MlsApplication, migrate_protected_sqlite,
    with_mls_storage_key,
};
use lattice_protocol::{Value, encode_canonical};
use lattice_storage::{CommitOutcome, SpaceGenesisSnapshot, Store, StoreError};
use thiserror::Error;
use zeroize::Zeroizing;

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

/// Event payload bound to an MLS application or a locally authenticated Genesis.
///
/// External applications enter through [`bind_mls_application`], which proves
/// that `OpenMLS` processed the exact event ciphertext. Local Genesis creation
/// and restore use the private `SQLite` transaction plus AEAD snapshot binding.
/// Neither route validates MLS credential trust, group-reference mapping,
/// Space/channel authorization, or application policy.
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
/// The binding rejects events whose author key, protected body, MLS epoch, or
/// event-visible MLS group reference differs from the authenticated MLS result.
/// A successful value is not authorization and must not be treated as
/// permission to mutate a Space.
///
/// # Errors
///
/// Returns [`CoreError::MlsEventBindingFailed`] if sender identity, exact
/// ciphertext bytes, MLS epoch, or group reference do not match the signed event.
pub fn bind_mls_application(
    event: VerifiedSignatureOnlyEvent,
    application: MlsApplication,
) -> Result<MlsBoundEvent, CoreError> {
    let author_key = event.identity_bundle().ed25519_public_key();
    if application.member_signature_key() != Some(&author_key)
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

/// Local core setup, protected MLS state, and durable-store failures.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Opening or writing the durable event/identity store failed.
    #[error(transparent)]
    Storage(#[from] StoreError),
    /// Creating or reopening the protected device identity failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
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
    /// A received author sequence is occupied by a different event ID.
    #[error("received author sequence conflicts with event {existing_event_id:02x?}")]
    ReceivedEventEquivocation { existing_event_id: [u8; 32] },
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

    use super::{Client, CoreError, bind_mls_application};
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::{DeviceIdentity, PrivateKeyProtectionError, PrivateKeyProtector};
    use lattice_mls::api::{DeviceCredentialInput, GroupState, IncomingResult};
    use openmls::credentials::Credential;
    use openmls::prelude::CredentialType;
    use openmls::prelude::tls_codec::{Serialize as TlsSerialize, VLBytes};
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
            VLBytes::new(b"test-only untrusted X.509 placeholder".to_vec())
                .tls_serialize_detached()
                .expect("test credential encodes"),
        );
        DeviceCredentialInput::from_x509_credential(identity, credential)
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

        let bound = bind_mls_application(event(&alice_identity, wire, 1, group_reference), proof)
            .expect("matching event and MLS proof bind");
        assert_eq!(bound.plaintext(), b"authenticated event plaintext");
        assert_eq!(
            bound.event().identity_bundle().ed25519_public_key(),
            alice_identity.public_key()
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
        let restored = reopened
            .restore_space(created.space_id(), created.group_reference())
            .expect("restore durable local Space policy");
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
    fn existing_profile_open_fails_closed_when_identity_is_missing() {
        let database = TestDatabase::new();
        assert!(matches!(
            Client::open_existing(&database.0, &TestProtector),
            Err(CoreError::MissingIdentity)
        ));
    }
}
