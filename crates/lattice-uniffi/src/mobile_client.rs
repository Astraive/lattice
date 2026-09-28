use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

use lattice_core::{
    Client, CoreError, InitialChannel, LocalTextMessageRecord, MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES,
    MAX_OUTBOX_PAGE_SIZE, MAX_SPACE_CREDENTIAL_BYTES, MAX_SPACE_WELCOME_BOOTSTRAP_BYTES,
    OutboxEntry, OutboxState, SpaceGenesisCursor, SyncedApplicationOutcome,
    space::{Channel, ChannelType, MAX_SPACE_PAYLOAD_BYTES},
};
use lattice_identity::{
    BleExp0IdentitySignature, IdentityError, PrivateKeyProtectionError, PrivateKeyProtector,
};

use super::{
    MobileChannelSummary, MobileChannelType, MobileCreatedSpace, MobileError, MobileIdentityInfo,
    MobileInitialChannel, MobileLocalTextMessage, MobileLocalTextMessageSearch, MobileOutboxEntry,
    MobileOutboxState, MobilePinnedIdentity, MobileProjectionChange, MobileQueuedMessage,
    MobileSpaceCursor, MobileSpacePage, MobileSpaceSummary, MobileSyncEventResult,
    MobileSyncEventState, PlatformKeyProtector,
};

struct ProfileProtector {
    profile_id: String,
    platform: Arc<dyn PlatformKeyProtector>,
}

impl PrivateKeyProtector for ProfileProtector {
    fn wrap(&self, clear_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        self.platform
            .wrap(self.profile_id.clone(), clear_material.to_vec())
            .map_err(|_| PrivateKeyProtectionError)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        self.platform
            .unwrap(self.profile_id.clone(), ciphertext.to_vec())
            .map_err(|_| PrivateKeyProtectionError)
    }
}

const MAX_PROJECTION_SUBSCRIPTIONS: usize = 32;
const MAX_PROJECTION_WAIT_MS: u64 = 60_000;
const SPACE_CHANGE: u8 = 1;
const MESSAGE_CHANGE: u8 = 2;
const ALL_CHANGE: u8 = 4;
const SYNCED_EVENT_CHANGE: u8 = 8;

#[derive(Default)]
struct ProjectionSignalState {
    pending: u8,
    closed: bool,
}

struct ProjectionSignal {
    state: Mutex<ProjectionSignalState>,
    changed: Condvar,
}

impl ProjectionSignal {
    fn new() -> Self {
        Self {
            state: Mutex::new(ProjectionSignalState::default()),
            changed: Condvar::new(),
        }
    }

    fn notify(&self, change: MobileProjectionChange) {
        if let Ok(mut state) = self.state.lock() {
            if !state.closed {
                state.pending |= projection_change_mask(change);
                self.changed.notify_one();
            }
        }
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        state.pending = 0;
        self.changed.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.state.lock().map(|state| state.closed).unwrap_or(true)
    }

    fn wait(&self, timeout: Duration) -> Result<Option<MobileProjectionChange>, MobileError> {
        let state = self
            .state
            .lock()
            .map_err(|_| MobileError::ProjectionObserverUnavailable)?;
        let (mut state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| state.pending == 0 && !state.closed)
            .map_err(|_| MobileError::ProjectionObserverUnavailable)?;
        if state.closed || state.pending == 0 {
            return Ok(None);
        }
        let pending = std::mem::take(&mut state.pending);
        Ok(Some(coalesced_projection_change(pending)))
    }
}

/// Cancellable bounded observer for local Core projection changes.
#[derive(uniffi::Object)]
pub struct MobileProjectionSubscription {
    signal: Arc<ProjectionSignal>,
}

#[uniffi::export]
impl MobileProjectionSubscription {
    /// Waits for one coalesced change; `None` means timeout or closure.
    pub fn wait_for_change(
        &self,
        timeout_ms: u64,
    ) -> Result<Option<MobileProjectionChange>, MobileError> {
        if timeout_ms == 0 || timeout_ms > MAX_PROJECTION_WAIT_MS {
            return Err(MobileError::InvalidProjectionWait);
        }
        self.signal.wait(Duration::from_millis(timeout_ms))
    }

    /// Reports whether this subscription has been closed.
    pub fn is_closed(&self) -> bool {
        self.signal.is_closed()
    }

    /// Closes the subscription and wakes any blocked waiter.
    pub fn cancel(&self) {
        self.signal.close();
    }
}

impl Drop for MobileProjectionSubscription {
    fn drop(&mut self) {
        self.signal.close();
    }
}

#[derive(Default)]
struct ProjectionObserverHub {
    subscriptions: Mutex<Vec<Weak<ProjectionSignal>>>,
}

impl ProjectionObserverHub {
    fn subscribe(&self) -> Result<Arc<MobileProjectionSubscription>, MobileError> {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .map_err(|_| MobileError::ProjectionObserverUnavailable)?;
        subscriptions.retain(|subscription| {
            subscription
                .upgrade()
                .is_some_and(|signal| !signal.is_closed())
        });
        if subscriptions.len() >= MAX_PROJECTION_SUBSCRIPTIONS {
            return Err(MobileError::ProjectionObserverLimit);
        }
        let signal = Arc::new(ProjectionSignal::new());
        subscriptions.push(Arc::downgrade(&signal));
        Ok(Arc::new(MobileProjectionSubscription { signal }))
    }

    fn publish(&self, change: MobileProjectionChange) {
        let Ok(mut subscriptions) = self.subscriptions.lock() else {
            return;
        };
        subscriptions.retain(|subscription| {
            if let Some(signal) = subscription.upgrade() {
                signal.notify(change);
                !signal.is_closed()
            } else {
                false
            }
        });
    }
}

fn projection_change_mask(change: MobileProjectionChange) -> u8 {
    match change {
        MobileProjectionChange::Spaces => SPACE_CHANGE,
        MobileProjectionChange::Messages => MESSAGE_CHANGE,
        MobileProjectionChange::All => ALL_CHANGE,
        MobileProjectionChange::SyncedEvents => SYNCED_EVENT_CHANGE,
    }
}

fn coalesced_projection_change(pending: u8) -> MobileProjectionChange {
    if pending & SYNCED_EVENT_CHANGE != 0 {
        MobileProjectionChange::SyncedEvents
    } else if pending & ALL_CHANGE != 0
        || pending & (SPACE_CHANGE | MESSAGE_CHANGE) == (SPACE_CHANGE | MESSAGE_CHANGE)
    {
        MobileProjectionChange::All
    } else if pending & MESSAGE_CHANGE != 0 {
        MobileProjectionChange::Messages
    } else {
        MobileProjectionChange::Spaces
    }
}

fn ingress_projection_change(state: MobileSyncEventState) -> Option<MobileProjectionChange> {
    (state == MobileSyncEventState::Accepted).then_some(MobileProjectionChange::SyncedEvents)
}

fn publish_ingress_projection_change(
    observers: &ProjectionObserverHub,
    state: MobileSyncEventState,
) {
    if let Some(change) = ingress_projection_change(state) {
        observers.publish(change);
    }
}

#[cfg(test)]
mod projection_observer_tests {
    use super::*;

    #[test]
    fn accepted_ingress_notifies_but_other_outcomes_do_not() {
        let hub = ProjectionObserverHub::default();
        let subscription = hub.subscribe().unwrap();
        for state in [
            MobileSyncEventState::Duplicate,
            MobileSyncEventState::Pending,
            MobileSyncEventState::CheckpointExcluded,
        ] {
            publish_ingress_projection_change(&hub, state);
            assert_eq!(
                subscription.wait_for_change(1).unwrap(),
                None,
                "unexpected notification for {state:?}"
            );
        }
        publish_ingress_projection_change(&hub, MobileSyncEventState::Accepted);
        assert_eq!(
            subscription.wait_for_change(1).unwrap(),
            Some(MobileProjectionChange::SyncedEvents)
        );
    }

    #[test]
    fn observer_burst_is_bounded_and_coalesced() {
        let signal = ProjectionSignal::new();
        for change in [
            MobileProjectionChange::Spaces,
            MobileProjectionChange::Messages,
            MobileProjectionChange::SyncedEvents,
        ] {
            signal.notify(change);
        }
        assert_eq!(
            signal.wait(Duration::from_millis(1)).unwrap(),
            Some(MobileProjectionChange::SyncedEvents)
        );
        assert_eq!(signal.wait(Duration::from_millis(1)).unwrap(), None);
    }

    #[test]
    fn closing_subscription_wakes_waiter_and_rejects_new_notifications() {
        let signal = Arc::new(ProjectionSignal::new());
        let waiter = Arc::clone(&signal);
        let thread = std::thread::spawn(move || waiter.wait(Duration::from_secs(5)).unwrap());
        signal.close();
        assert_eq!(thread.join().unwrap(), None);
        signal.notify(MobileProjectionChange::Messages);
        assert_eq!(signal.wait(Duration::from_millis(1)).unwrap(), None);
    }

    #[test]
    fn observer_registry_enforces_limit_and_reuses_closed_slots() {
        let hub = ProjectionObserverHub::default();
        let subscriptions: Vec<_> = (0..MAX_PROJECTION_SUBSCRIPTIONS)
            .map(|_| hub.subscribe().unwrap())
            .collect();
        assert!(matches!(
            hub.subscribe(),
            Err(MobileError::ProjectionObserverLimit)
        ));
        subscriptions[0].cancel();
        assert!(hub.subscribe().is_ok());
    }

    struct ObserverTestProtector;

    impl PlatformKeyProtector for ObserverTestProtector {
        fn wrap(
            &self,
            _profile_id: String,
            clear_material: Vec<u8>,
        ) -> Result<Vec<u8>, super::super::ProtectorError> {
            Ok(clear_material)
        }

        fn unwrap(
            &self,
            _profile_id: String,
            ciphertext: Vec<u8>,
        ) -> Result<Vec<u8>, super::super::ProtectorError> {
            Ok(ciphertext)
        }
    }

    #[test]
    fn rejected_ingress_does_not_notify_subscribers() {
        let directory = tempfile::tempdir().unwrap();
        let client = MobileClient::open_or_create(
            directory
                .path()
                .join("observer.sqlite")
                .to_string_lossy()
                .into_owned(),
            "observer-test".to_owned(),
            Arc::new(ObserverTestProtector),
        )
        .unwrap();
        let subscription = client.subscribe_projection_changes().unwrap();
        assert!(matches!(
            client.ingest_synced_application_event(Vec::new()),
            Err(MobileError::SyncIngestFailed)
        ));
        assert_eq!(subscription.wait_for_change(1).unwrap(), None);
    }

    #[test]
    fn invalid_wait_durations_are_rejected() {
        let subscription = MobileProjectionSubscription {
            signal: Arc::new(ProjectionSignal::new()),
        };
        assert!(matches!(
            subscription.wait_for_change(0),
            Err(MobileError::InvalidProjectionWait)
        ));
        assert!(matches!(
            subscription.wait_for_change(MAX_PROJECTION_WAIT_MS + 1),
            Err(MobileError::InvalidProjectionWait)
        ));
    }
}

/// Thread-safe handle to one durable local profile.
#[derive(uniffi::Object)]
pub struct MobileClient {
    client: Mutex<Client>,
    projection_observers: ProjectionObserverHub,
}

#[uniffi::export]
impl MobileClient {
    /// Opens a durable profile using a caller-provided OS keystore bridge.
    ///
    /// This API has no software-key fallback. The profile identifier is passed
    /// to the native protector for key binding and must remain stable.
    ///
    /// # Errors
    ///
    /// Returns `InvalidProfileId` for a malformed identifier,
    /// `KeyProtectionFailed` when the OS keystore refuses access, or
    /// `ProfileOpenFailed` for storage or profile initialization failures.
    #[uniffi::constructor]
    pub fn open_or_create(
        database_path: String,
        profile_id: String,
        protector: Arc<dyn PlatformKeyProtector>,
    ) -> Result<Arc<Self>, MobileError> {
        if profile_id.is_empty()
            || profile_id.len() > 128
            || !profile_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(MobileError::InvalidProfileId);
        }

        let platform = ProfileProtector {
            profile_id,
            platform: protector,
        };
        let client = Client::open_or_create(database_path, &platform)
            .map_err(|error| map_open_error(&error))?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
            projection_observers: ProjectionObserverHub::default(),
        }))
    }

    /// Subscribes to bounded, coalesced Core projection changes.
    pub fn subscribe_projection_changes(
        &self,
    ) -> Result<Arc<MobileProjectionSubscription>, MobileError> {
        self.projection_observers.subscribe()
    }

    /// Returns the non-secret public identity information for native UI.
    ///
    /// # Errors
    ///
    /// Returns `ProfileUnavailable` if the local profile lock is poisoned.
    pub fn identity_info(&self) -> Result<MobileIdentityInfo, MobileError> {
        let client = self.lock_client()?;
        Ok(client.identity_info().into())
    }

    /// Creates a DER PKCS#10 request for the local identity without exposing private keys.
    ///
    /// # Errors
    ///
    /// Returns `ProfileUnavailable` for a poisoned profile lock and
    /// `CertificateSigningRequestFailed` when the bounded CSR cannot be encoded.
    pub fn certificate_signing_request(&self) -> Result<Vec<u8>, MobileError> {
        let client = self.lock_client()?;
        client
            .certificate_signing_request()
            .map_err(|_| MobileError::CertificateSigningRequestFailed)
    }

    /// Stores one exact identity bundle after checking its caller-supplied full
    /// fingerprint.
    ///
    /// The caller must obtain `expected_fingerprint` through out-of-band human
    /// verification or a session-bound comparison. This method validates and
    /// persists the exact match; it does not attest that comparison, authenticate
    /// a Noise session, validate an MLS credential, or grant membership.
    ///
    /// # Errors
    ///
    /// Returns `InvalidFingerprint` for a non-32-byte digest,
    /// `InvalidIdentityBundle` for malformed bytes,
    /// `FingerprintMismatch` for a valid but nonmatching bundle, or
    /// `PinnedIdentityConflict` if that fingerprint already maps to other bytes.
    // UniFFI exports byte buffers as owned Vec values at the Rust boundary.
    #[allow(clippy::needless_pass_by_value)]
    pub fn pin_identity(
        &self,
        public_bundle: Vec<u8>,
        expected_fingerprint: Vec<u8>,
    ) -> Result<MobilePinnedIdentity, MobileError> {
        let expected_fingerprint: [u8; 32] = expected_fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let mut client = self.lock_client()?;
        client
            .pin_identity(&public_bundle, expected_fingerprint)
            .map(Into::into)
            .map_err(|error| map_pin_error(&error))
    }

    /// Loads and revalidates one pinned peer by its full fingerprint.
    ///
    /// # Errors
    ///
    /// Returns `InvalidFingerprint` for a non-32-byte digest,
    /// `InvalidIdentityBundle` or `FingerprintMismatch` for corrupt stored data,
    /// and `ProfileUnavailable` if the profile cannot be read.
    pub fn pinned_identity(
        &self,
        fingerprint: Vec<u8>,
    ) -> Result<Option<MobilePinnedIdentity>, MobileError> {
        let fingerprint: [u8; 32] = fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        self.lock_client()?
            .pinned_identity(&fingerprint)
            .map(|pinned| pinned.map(Into::into))
            .map_err(|error| map_pin_error(&error))
    }

    /// Removes one full-fingerprint peer pin from this local profile.
    ///
    /// This revokes trust only on this device. It does not revoke the remote
    /// identity or change Space membership.
    ///
    /// # Errors
    ///
    /// Returns `InvalidFingerprint` for a non-32-byte fingerprint, or
    /// `ProfileUnavailable` if the profile cannot update its trust store.
    // UniFFI exports byte buffers as owned Vec values at the Rust boundary.
    #[allow(clippy::needless_pass_by_value)]
    pub fn unpin_identity(&self, fingerprint: Vec<u8>) -> Result<bool, MobileError> {
        let fingerprint: [u8; 32] = fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        self.lock_client()?
            .unpin_identity(&fingerprint)
            .map_err(|error| map_pin_error(&error))
    }

    /// Returns the next durable author sequence for this identity.
    ///
    /// # Errors
    ///
    /// Returns `ProfileUnavailable` if the profile lock or sequence lookup fails.
    pub fn next_author_sequence(&self) -> Result<u64, MobileError> {
        self.lock_client()?
            .next_author_sequence()
            .map_err(|_| MobileError::ProfileUnavailable)
    }
    /// Creates a local one-member Space after OS-trust validation of the supplied RFC 9420 X.509 vector.
    ///
    /// This operation creates only the caller's local candidate generation; it
    /// does not join or assert that any other member has joined.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceCredential` for malformed, mismatched, or untrusted
    /// credential bytes; `InvalidSpaceInput` for bounded channel policy input
    /// errors; `ProfileUnavailable` if the profile lock is poisoned; and
    /// `SpaceCreationFailed` for other core transaction failures.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_local_space(
        &self,
        credential_vector: Vec<u8>,
        channels: Vec<MobileInitialChannel>,
    ) -> Result<MobileCreatedSpace, MobileError> {
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        if channels.is_empty()
            || channels.len() > 64
            || channels.iter().any(|channel| {
                channel.name.is_empty() || channel.name.len() > 128 || channel.name.contains('\0')
            })
        {
            return Err(MobileError::InvalidSpaceInput);
        }
        let channels = channels
            .into_iter()
            .map(|channel| InitialChannel {
                channel_type: match channel.channel_type {
                    MobileChannelType::Text => ChannelType::Text,
                    MobileChannelType::Announcement => ChannelType::Announcement,
                    MobileChannelType::Voice => ChannelType::Voice,
                },
                name: channel.name,
                default_allow: channel.default_allow,
                default_deny: channel.default_deny,
                role_overrides: Vec::new(),
            })
            .collect();
        let mut client = self.lock_client()?;
        let created = client
            .create_space_from_x509_credential(credential_vector, channels)
            .map_err(|error| map_create_space_error(&error))?;
        let result = MobileCreatedSpace {
            space_id: created.space_id().to_vec(),
            group_reference: created.group_reference().to_vec(),
            genesis_event_id: created.genesis_event().event_id().as_bytes().to_vec(),
            channels: channel_summaries(
                created
                    .reducer()
                    .policy()
                    .into_iter()
                    .flat_map(|p| &p.channels),
            ),
        };
        drop(client);
        self.projection_observers
            .publish(MobileProjectionChange::Spaces);
        Ok(result)
    }
    /// Joins one validated MLS Welcome using a signed policy checkpoint from
    /// an explicitly pinned inviter.
    ///
    /// The result restores the signed checkpoint and exact Welcome generation;
    /// it does not claim that relays or other recipients received the package.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceBootstrap` for empty or oversized package bytes,
    /// `InvalidFingerprint` for a malformed inviter fingerprint,
    /// `InvalidSpaceCredential` for malformed or untrusted X.509 bytes,
    /// `UntrustedSpaceInviter` when the exact inviter bundle is not pinned, and
    /// `SpaceJoinFailed` for other policy, MLS, or storage failures.
    #[allow(clippy::needless_pass_by_value)]
    pub fn join_space_from_welcome_bootstrap(
        &self,
        bootstrap_package: Vec<u8>,
        expected_inviter_fingerprint: Vec<u8>,
        credential_vector: Vec<u8>,
    ) -> Result<MobileCreatedSpace, MobileError> {
        if bootstrap_package.is_empty()
            || bootstrap_package.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES
        {
            return Err(MobileError::InvalidSpaceBootstrap);
        }
        let expected_inviter_fingerprint: [u8; 32] = expected_inviter_fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        let created = self
            .lock_client()?
            .join_space_from_welcome_bootstrap_from_x509_credential(
                &bootstrap_package,
                expected_inviter_fingerprint,
                credential_vector,
            )
            .map_err(|error| map_welcome_join_error(&error))?;
        let result = MobileCreatedSpace {
            space_id: created.space_id().to_vec(),
            group_reference: created.group_reference().to_vec(),
            genesis_event_id: created.genesis_event().event_id().as_bytes().to_vec(),
            channels: channel_summaries(
                created
                    .reducer()
                    .policy()
                    .into_iter()
                    .flat_map(|policy| &policy.channels),
            ),
        };
        self.projection_observers
            .publish(MobileProjectionChange::All);
        Ok(result)
    }
    /// Restores a named local generation, then creates its authorized one-member recovery generation.
    ///
    /// This creates a new local root for the same Space; it does not rejoin
    /// prior members or establish network membership.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for incorrectly sized identifiers,
    /// `InvalidSpaceCredential` for an empty, oversized, malformed, or untrusted
    /// credential, `ProfileUnavailable` if the profile lock is poisoned, and
    /// `SpaceRecoveryFailed` if restoring the prior generation or creating the
    /// recovery generation fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn recover_local_space_generation(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
    ) -> Result<MobileCreatedSpace, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        let created = self
            .lock_client()?
            .recover_space_generation_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
            )
            .map_err(|error| map_recovery_space_error(&error))?;
        let result = MobileCreatedSpace {
            space_id: created.space_id().to_vec(),
            group_reference: created.group_reference().to_vec(),
            genesis_event_id: created.genesis_event().event_id().as_bytes().to_vec(),
            channels: channel_summaries(
                created
                    .reducer()
                    .policy()
                    .into_iter()
                    .flat_map(|policy| &policy.channels),
            ),
        };
        self.projection_observers
            .publish(MobileProjectionChange::All);
        Ok(result)
    }

    /// Restores one bounded page of local Genesis snapshots.
    ///
    /// This lists locally created candidate generations only. It does not
    /// establish current membership or restore later policy events.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceCursor` for malformed cursor byte lengths or
    /// `ProfileUnavailable` when a snapshot or profile cannot be restored.
    pub fn list_local_spaces(
        &self,
        after: Option<MobileSpaceCursor>,
    ) -> Result<MobileSpacePage, MobileError> {
        let after = after.map(SpaceGenesisCursor::try_from).transpose()?;
        let mut client = self.lock_client()?;
        let page = client
            .restore_space_page(after)
            .map_err(|_| MobileError::ProfileUnavailable)?;
        let spaces = page
            .spaces()
            .iter()
            .map(|space| MobileSpaceSummary {
                space_id: space.space_id().to_vec(),
                group_reference: space.group_reference().to_vec(),
                channels: channel_summaries(
                    space
                        .reducer()
                        .policy()
                        .into_iter()
                        .flat_map(|policy| &policy.channels),
                ),
            })
            .collect();
        Ok(MobileSpacePage {
            spaces,
            next_cursor: page.next_cursor().map(Into::into),
        })
    }
    /// Returns a bounded keyset page of exact durable opaque envelopes.
    ///
    /// Entries are not delivery confirmations; the router owns retry and
    /// forwarding transitions. The caller must preserve the envelope bytes.
    ///
    /// # Errors
    ///
    /// `InvalidOutboxCursor` for a non-32-byte cursor,
    /// `InvalidOutboxPage` for a zero or oversized page, and
    /// `OutboxUnavailable` for storage failures.
    #[allow(clippy::needless_pass_by_value)]
    pub fn outbox_page(
        &self,
        after_event_id: Option<Vec<u8>>,
        limit: i32,
    ) -> Result<Vec<MobileOutboxEntry>, MobileError> {
        let after_event_id = after_event_id
            .map(|id| {
                id.as_slice()
                    .try_into()
                    .map_err(|_| MobileError::InvalidOutboxCursor)
            })
            .transpose()?;
        let limit = usize::try_from(limit).map_err(|_| MobileError::InvalidOutboxPage)?;
        if limit == 0 || limit > MAX_OUTBOX_PAGE_SIZE {
            return Err(MobileError::InvalidOutboxPage);
        }
        let client = self.lock_client()?;
        let entries = client
            .outbox_page(after_event_id, limit)
            .map_err(|_| MobileError::OutboxUnavailable)?;
        Ok(entries.into_iter().map(mobile_outbox_entry).collect())
    }
    /// Persists one forwarding attempt before its envelope is placed on transport.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxEventId`, `InvalidOutboxSchedule`, or
    /// `OutboxTransitionRejected`.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes owned bytes as generated byte arrays.
    pub fn mark_outbox_attempt(
        &self,
        event_id: Vec<u8>,
        next_attempt_ms: i64,
    ) -> Result<(), MobileError> {
        let event_id: [u8; 32] = event_id
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        if next_attempt_ms < 0 {
            return Err(MobileError::InvalidOutboxSchedule);
        }
        self.lock_client()?
            .mark_outbox_attempt(event_id, next_attempt_ms)
            .map_err(|_| MobileError::OutboxTransitionRejected)
    }

    /// Records only authenticated peer acceptance into bounded BLE ingress.
    /// It is not proof of destination delivery or reading.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxEventId` or `OutboxTransitionRejected`.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes owned bytes as generated byte arrays.
    pub fn record_peer_ingress_accepted(&self, event_id: Vec<u8>) -> Result<(), MobileError> {
        let event_id: [u8; 32] = event_id
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        self.lock_client()?
            .record_peer_ingress_accepted(event_id)
            .map_err(|_| MobileError::OutboxTransitionRejected)
    }

    /// Sends one signed event through Rust's signature, MLS, dependency, and
    /// local Space authorization gates.
    ///
    /// `Pending` means missing parents were retained. `CheckpointExcluded`
    /// means signed ciphertext predates the local MLS checkpoint and is retained
    /// only to preserve DAG ancestry; neither outcome is authorized content.
    ///
    /// # Errors
    ///
    /// Returns `SyncIngestFailed` unless Core accepts, recognizes, excludes, or
    /// safely retains the event as pending.
    #[allow(clippy::needless_pass_by_value)]
    pub fn ingest_synced_application_event(
        &self,
        canonical_bytes: Vec<u8>,
    ) -> Result<MobileSyncEventResult, MobileError> {
        let mut client = self.lock_client()?;
        let outcome = client
            .accept_synced_application_event_for_local_generation(&canonical_bytes)
            .map_err(|_| MobileError::SyncIngestFailed)?;
        let (event_id, state, missing_dependencies) = match outcome {
            SyncedApplicationOutcome::Accepted { event_id } => {
                (event_id, MobileSyncEventState::Accepted, Vec::new())
            }
            SyncedApplicationOutcome::Duplicate { event_id } => {
                (event_id, MobileSyncEventState::Duplicate, Vec::new())
            }
            SyncedApplicationOutcome::CheckpointExcluded { event_id } => (
                event_id,
                MobileSyncEventState::CheckpointExcluded,
                Vec::new(),
            ),
            SyncedApplicationOutcome::Pending {
                event_id,
                missing_dependencies,
            } => (
                event_id,
                MobileSyncEventState::Pending,
                missing_dependencies
                    .into_iter()
                    .map(|id| id.to_vec())
                    .collect(),
            ),
        };
        let result = MobileSyncEventResult {
            event_id: event_id.to_vec(),
            state,
            missing_dependencies,
        };
        drop(client);
        publish_ingress_projection_change(&self.projection_observers, state);
        Ok(result)
    }

    /// Returns the newest bounded history of locally retained authorized text messages.
    ///
    /// History includes messages accepted from peers as well as locally authored
    /// messages. Rows beyond the newest local page are available through search;
    /// outbox states never imply remote delivery.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifier lengths and
    /// `MessageHistoryUnavailable` when local recovery or authentication fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn list_local_text_messages(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        channel_id: Vec<u8>,
    ) -> Result<Vec<MobileLocalTextMessage>, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let channel_id: [u8; 16] = channel_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let mut client = self.lock_client()?;
        let messages = client
            .local_text_message_history(&space_id, &group_reference, &channel_id)
            .map_err(|_| MobileError::MessageHistoryUnavailable)?;
        Ok(messages.into_iter().map(mobile_text_message).collect())
    }
    /// Searches all locally retained authorized messages in one channel offline.
    ///
    /// The Core query limit is measured in UTF-8 bytes. At most the 100 newest
    /// matches are returned; the total match and scanned-message counts remain
    /// bounded by the local cache quota.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed IDs, `InvalidMessageSearch`
    /// for an empty or oversized query, and `MessageHistoryUnavailable` when
    /// local recovery, decryption, or event validation fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn search_local_text_messages(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        channel_id: Vec<u8>,
        query: String,
    ) -> Result<MobileLocalTextMessageSearch, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let channel_id: [u8; 16] = channel_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if query.is_empty() || query.len() > MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES {
            return Err(MobileError::InvalidMessageSearch);
        }
        let mut client = self.lock_client()?;
        let result = client
            .search_local_text_messages(&space_id, &group_reference, &channel_id, &query)
            .map_err(|error| match error {
                CoreError::InvalidLocalTextMessageSearch => MobileError::InvalidMessageSearch,
                _ => MobileError::MessageHistoryUnavailable,
            })?;
        Ok(MobileLocalTextMessageSearch {
            messages: result
                .messages
                .into_iter()
                .map(mobile_text_message)
                .collect(),
            total_matches: result
                .total_matches
                .try_into()
                .map_err(|_| MobileError::MessageHistoryUnavailable)?,
            scanned_messages: result
                .scanned_messages
                .try_into()
                .map_err(|_| MobileError::MessageHistoryUnavailable)?,
        })
    }
    /// Validates and commits a text event to this device's local durable outbox.
    ///
    /// Queueing does not forward the event or claim that any other member
    /// received or delivered it. The Core path revalidates the credential and
    /// only restores an unchanged locally created Genesis generation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for identifiers with incorrect byte
    /// lengths, `InvalidSpaceCredential` for malformed or untrusted credentials,
    /// `InvalidMessageInput` for text exceeding the payload bound,
    /// `MessageRejected` when local policy denies the message, and
    /// `MessageQueueFailed` for other queue/restore failures.
    #[allow(clippy::needless_pass_by_value)]
    pub fn queue_local_text_message(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        content: String,
    ) -> Result<MobileQueuedMessage, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let channel_id: [u8; 16] = channel_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        if content.len() > MAX_SPACE_PAYLOAD_BYTES {
            return Err(MobileError::InvalidMessageInput);
        }
        let queued = self
            .lock_client()?
            .queue_text_message_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                channel_id,
                &content,
            )
            .map_err(|error| map_queue_message_error(&error))?;
        let result = MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        };
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(result)
    }

    /// Queues a locally authorized immutable Edit event and updates the
    /// encrypted local message cache.
    ///
    /// This operation does not forward the edit or claim recipient delivery.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `InvalidSpaceCredential` for malformed or untrusted credentials,
    /// `InvalidMessageInput` for oversized text, `MessageRejected` when local
    /// policy denies the edit, or `MessageQueueFailed` for other failures.
    #[allow(clippy::needless_pass_by_value)]
    pub fn queue_local_text_message_edit(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        target_message_id: Vec<u8>,
        content: String,
    ) -> Result<MobileQueuedMessage, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let channel_id: [u8; 16] = channel_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let target: [u8; 32] = target_message_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        if content.len() > MAX_SPACE_PAYLOAD_BYTES {
            return Err(MobileError::InvalidMessageInput);
        }
        let queued = self
            .lock_client()?
            .queue_text_message_edit_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                channel_id,
                target,
                &content,
            )
            .map_err(|error| map_queue_message_error(&error))?;
        let result = MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        };
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(result)
    }
}

fn mobile_text_message(message: LocalTextMessageRecord) -> MobileLocalTextMessage {
    MobileLocalTextMessage {
        event_id: message.event_id.to_vec(),
        author_id: message.author_id.to_vec(),
        author_sequence: message.author_sequence,
        lamport: message.lamport,
        content: message.content,
        outbox_state: message.outbox_state.map(|state| {
            match state {
                OutboxState::Queued => "queued",
                OutboxState::Forwarding => "forwarding",
                OutboxState::Forwarded => "forwarded",
                OutboxState::PeerIngressAccepted => "peer_ingress_accepted",
                OutboxState::Delivered => "delivered",
                OutboxState::Failed => "failed",
            }
            .to_owned()
        }),
    }
}

fn mobile_outbox_entry(entry: OutboxEntry) -> MobileOutboxEntry {
    MobileOutboxEntry {
        event_id: entry.event_id.to_vec(),
        envelope_bytes: entry.envelope_bytes,
        next_attempt_ms: entry.next_attempt_ms,
        attempt_count: entry.attempt_count,
        state: match entry.state {
            OutboxState::Queued => MobileOutboxState::Queued,
            OutboxState::Forwarding => MobileOutboxState::Forwarding,
            OutboxState::Forwarded => MobileOutboxState::Forwarded,
            OutboxState::PeerIngressAccepted => MobileOutboxState::PeerIngressAccepted,
            OutboxState::Delivered => MobileOutboxState::Delivered,
            OutboxState::Failed => MobileOutboxState::Failed,
        },
    }
}

fn channel_summaries<'a>(
    channels: impl IntoIterator<Item = &'a Channel>,
) -> Vec<MobileChannelSummary> {
    channels
        .into_iter()
        .map(|channel| MobileChannelSummary {
            id: channel.id.to_vec(),
            name: channel.name.clone(),
            channel_type: match channel.channel_type {
                ChannelType::Text => MobileChannelType::Text,
                ChannelType::Announcement => MobileChannelType::Announcement,
                ChannelType::Voice => MobileChannelType::Voice,
            },
            archived: channel.archived,
        })
        .collect()
}
fn map_queue_message_error(error: &CoreError) -> MobileError {
    match error {
        CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
        CoreError::SpaceMessageRejected(_) | CoreError::SpaceGenesisRejected(_) => {
            MobileError::MessageRejected
        }
        _ => MobileError::MessageQueueFailed,
    }
}

fn map_create_space_error(error: &CoreError) -> MobileError {
    match error {
        CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
        CoreError::SpaceGenesisRejected(_) => MobileError::InvalidSpaceInput,
        _ => MobileError::SpaceCreationFailed,
    }
}

fn map_recovery_space_error(error: &CoreError) -> MobileError {
    match error {
        CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
        _ => MobileError::SpaceRecoveryFailed,
    }
}
fn map_welcome_join_error(error: &CoreError) -> MobileError {
    match error {
        CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
        CoreError::SpaceWelcomeBootstrapInvalid => MobileError::InvalidSpaceBootstrap,
        CoreError::SpaceWelcomeBootstrapUntrustedInviter => MobileError::UntrustedSpaceInviter,
        _ => MobileError::SpaceJoinFailed,
    }
}

impl MobileClient {
    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, MobileError> {
        self.client
            .lock()
            .map_err(|_| MobileError::ProfileUnavailable)
    }
    pub(crate) fn sign_ble_exp0_identity_signature(
        &self,
        signature: &BleExp0IdentitySignature,
    ) -> Result<[u8; 64], MobileError> {
        self.lock_client()?
            .sign_ble_exp0_identity_signature(signature)
            .map_err(|_| MobileError::BleSessionFailed)
    }
}

fn map_open_error(error: &CoreError) -> MobileError {
    if matches!(error, CoreError::Identity(IdentityError::Protection(_))) {
        MobileError::KeyProtectionFailed
    } else {
        MobileError::ProfileOpenFailed
    }
}

fn map_pin_error(error: &CoreError) -> MobileError {
    match error {
        CoreError::Identity(IdentityError::FingerprintMismatch) => MobileError::FingerprintMismatch,
        CoreError::Identity(IdentityError::Protection(_)) => MobileError::KeyProtectionFailed,
        CoreError::Identity(_) => MobileError::InvalidIdentityBundle,
        CoreError::PinnedIdentityConflict => MobileError::PinnedIdentityConflict,
        _ => MobileError::ProfileUnavailable,
    }
}
