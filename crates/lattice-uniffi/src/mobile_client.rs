use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lattice_core::{
    Client, CoreError, DirectMessageIngressOutcome, InitialChannel, LocalTextMessageRecord,
    MAX_DIRECT_MESSAGE_PACKET_BYTES, MAX_DIRECT_MESSAGE_PENDING_INVITATIONS,
    MAX_DIRECT_MESSAGE_TEXT_BYTES, MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES, MAX_OUTBOX_PAGE_SIZE,
    MAX_SPACE_CREDENTIAL_BYTES, MAX_SPACE_WELCOME_BOOTSTRAP_BYTES, OutboxEntry, OutboxState,
    SpaceGenesisCursor, SyncedApplicationOutcome, TextMessagePin, TextMessageReaction,
    space::{Channel, ChannelType, MAX_SPACE_PAYLOAD_BYTES, MemberStatus},
};
use lattice_files::{
    AttachmentManifest, AttachmentStagingLimits, AttachmentStagingStore, CHUNK_SIZE,
    StreamedAttachmentReceiver,
};
use lattice_identity::{
    BleExp0IdentitySignature, IdentityError, PrivateKeyProtectionError, PrivateKeyProtector,
};

use lattice_node::sync::{
    AttachmentReceiveResult, AuthenticatedDirectMessageExchange, DirectMessageIngressReceipt,
    DirectMessageIngressState, execute_authenticated_direct_message_once,
    receive_authenticated_attachment_once, send_authenticated_attachment_once,
    serve_authenticated_direct_message_once,
};
use lattice_platform::{MAX_ENVELOPE_BYTES, TransportError};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use tokio_util::sync::CancellationToken;

use super::{
    MobileAttachmentExport, MobileAttachmentManifest, MobileAttachmentQueueReceipt,
    MobileAttachmentStagingStatus, MobileAttachmentTransferReceipt,
    MobileAuthorizedAttachmentManifest, MobileChannelSummary, MobileChannelType,
    MobileCreatedDirectMessage, MobileCreatedSpace, MobileDirectMessageConversation,
    MobileDirectMessageExchange, MobileDirectMessageHistoryEntry, MobileDirectMessageIngressResult,
    MobileDirectMessageOutboxEntry, MobileDirectMessagePacket,
    MobileDirectMessagePendingInvitation, MobileError, MobileForwardableEventEntry,
    MobileIdentityInfo, MobileInitialChannel, MobileLocalTextMessage, MobileLocalTextMessageSearch,
    MobileOutboxEntry, MobileOutboxState, MobilePinnedIdentity, MobileProjectionChange,
    MobileQueuedMessage, MobileSpaceCursor, MobileSpaceInvitation, MobileSpacePage,
    MobileSpaceSummary, MobileSyncEventResult, MobileSyncEventState, PlatformKeyProtector,
};

#[derive(Clone)]
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
const MAX_SPACE_INVITE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
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
        if let Ok(mut state) = self.state.lock()
            && !state.closed
        {
            state.pending |= projection_change_mask(change);
            self.changed.notify_one();
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
        self.state.lock().map_or(true, |state| state.closed)
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
    ///
    /// # Errors
    ///
    /// Returns `InvalidProjectionWait` for a timeout outside the supported
    /// range, or `ProjectionObserverUnavailable` if observer synchronization
    /// fails.
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
    #[must_use]
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
            client.ingest_synced_application_event(Vec::new(), None),
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

#[cfg(test)]
mod direct_message_lan_tests {
    use super::*;

    struct TestProtector;

    impl PlatformKeyProtector for TestProtector {
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

    fn available_loopback_address() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
        let address = listener.local_addr().expect("read test port");
        drop(listener);
        address
    }

    #[test]
    fn two_profiles_exchange_over_exact_pin_authenticated_tcp() {
        let directory = tempfile::tempdir().expect("create test profiles");
        let alice = MobileClient::open_or_create(
            directory
                .path()
                .join("alice.sqlite")
                .to_string_lossy()
                .into_owned(),
            "alice-lan-test".to_owned(),
            Arc::new(TestProtector),
        )
        .expect("open Alice");
        let bob = MobileClient::open_or_create(
            directory
                .path()
                .join("bob.sqlite")
                .to_string_lossy()
                .into_owned(),
            "bob-lan-test".to_owned(),
            Arc::new(TestProtector),
        )
        .expect("open Bob");
        let alice_identity = alice.identity_info().expect("read Alice identity");
        let bob_identity = bob.identity_info().expect("read Bob identity");
        alice
            .pin_identity(
                bob_identity.public_bundle.clone(),
                bob_identity.fingerprint.clone(),
            )
            .expect("Alice pins Bob");
        bob.pin_identity(
            alice_identity.public_bundle.clone(),
            alice_identity.fingerprint.clone(),
        )
        .expect("Bob pins Alice");

        let alice_listen = available_loopback_address();
        let bob_listen = available_loopback_address();
        let mut unpinned_fingerprint = bob_identity.fingerprint.clone();
        unpinned_fingerprint[0] ^= 1;
        assert!(matches!(
            alice.exchange_direct_messages_once(
                bob_listen.to_string(),
                alice_listen.to_string(),
                unpinned_fingerprint,
            ),
            Err(MobileError::DirectMessageFailed)
        ));

        let alice_task = {
            let alice = Arc::clone(&alice);
            let peer_fingerprint = bob_identity.fingerprint.clone();
            std::thread::spawn(move || {
                alice.exchange_direct_messages_once(
                    bob_listen.to_string(),
                    alice_listen.to_string(),
                    peer_fingerprint,
                )
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        let bob_task = {
            let bob = Arc::clone(&bob);
            let peer_fingerprint = alice_identity.fingerprint.clone();
            std::thread::spawn(move || {
                bob.exchange_direct_messages_once(
                    alice_listen.to_string(),
                    bob_listen.to_string(),
                    peer_fingerprint,
                )
            })
        };
        let alice_exchange = alice_task
            .join()
            .expect("Alice LAN worker")
            .expect("Alice exchange");
        let bob_exchange = bob_task
            .join()
            .expect("Bob LAN worker")
            .expect("Bob exchange");
        assert_eq!(alice_exchange.peer_fingerprint, bob_identity.fingerprint);
        assert_eq!(bob_exchange.peer_fingerprint, alice_identity.fingerprint);
        assert_eq!(alice_exchange.listen_address, alice_listen.to_string());
        assert_eq!(bob_exchange.listen_address, bob_listen.to_string());
        assert_eq!(alice_exchange.outgoing_packet_id, None);
        assert_eq!(alice_exchange.incoming_packet_id, None);
        assert_eq!(bob_exchange.outgoing_packet_id, None);
        assert_eq!(bob_exchange.incoming_packet_id, None);
    }
}

/// Thread-safe handle to one durable local profile.
#[derive(uniffi::Object)]
pub struct MobileClient {
    client: Mutex<Client>,
    database_path: String,
    profile_protector: ProfileProtector,
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
        let client = Client::open_or_create(&database_path, &platform)
            .map_err(|error| map_open_error(&error))?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
            database_path,
            profile_protector: platform,
            projection_observers: ProjectionObserverHub::default(),
        }))
    }

    /// Subscribes to bounded, coalesced Core projection changes.
    ///
    /// # Errors
    ///
    /// Returns `ProfileUnavailable` if the subscription limit is reached or
    /// the observer registry is unavailable.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned record and byte buffers at the FFI boundary.
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
    /// Publishes one locally retained X.509 `KeyPackage` for offline invitation.
    ///
    /// The output is intended for explicit out-of-band transfer; no relay or
    /// network is contacted. The matching private `KeyPackage` remains local.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceCredential` for empty or oversized credential
    /// bytes, `ProfileUnavailable` if the profile lock is poisoned, and
    /// `SpaceKeyPackagePublicationFailed` if publication fails.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned byte buffer at the FFI boundary.
    pub fn publish_space_key_package(
        &self,
        credential_vector: Vec<u8>,
    ) -> Result<Vec<u8>, MobileError> {
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MobileError::SpaceKeyPackagePublicationFailed)?
            .as_secs();
        self.lock_client()?
            .publish_x509_key_package(credential_vector, now)
            .map_err(|error| match error {
                CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
                _ => MobileError::SpaceKeyPackagePublicationFailed,
            })
    }

    /// Commits an offline invitation for one published target `KeyPackage`.
    ///
    /// The invitation event and Welcome checkpoint are created by Core as one
    /// membership transaction. The token and bootstrap are returned for an
    /// explicit out-of-band handoff; no network is contacted.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `InvalidSpaceCredential` or `InvalidSpaceKeyPackage` for invalid input,
    /// `InvalidSpaceInput` for invalid expiry/use limits, and
    /// `SpaceInvitationFailed` if restoring or committing the invitation fails.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn create_space_invitation(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        key_package_wire: Vec<u8>,
        expires_at_unix_seconds: u64,
        max_uses: Option<u32>,
    ) -> Result<MobileSpaceInvitation, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        if key_package_wire.is_empty() || key_package_wire.len() > MAX_SPACE_PAYLOAD_BYTES {
            return Err(MobileError::InvalidSpaceKeyPackage);
        }
        let max_uses = max_uses
            .map(|value| u16::try_from(value).map_err(|_| MobileError::InvalidSpaceInput))
            .transpose()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MobileError::SpaceInvitationFailed)?
            .as_secs();
        if expires_at_unix_seconds <= now
            || expires_at_unix_seconds - now > MAX_SPACE_INVITE_TTL_SECONDS
            || max_uses == Some(0)
        {
            return Err(MobileError::InvalidSpaceInput);
        }
        let mut client = self.lock_client()?;
        let mut space = client
            .restore_space(&space_id, &group_reference)
            .map_err(|_| MobileError::SpaceInvitationFailed)?;
        let invitation = client
            .create_space_invite_from_x509_credential(
                &mut space,
                credential_vector,
                &key_package_wire,
                None,
                expires_at_unix_seconds,
                max_uses,
            )
            .map_err(|error| match error {
                CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
                _ => MobileError::SpaceInvitationFailed,
            })?;
        let result = MobileSpaceInvitation {
            invite_event_id: invitation.invite_event_id().to_vec(),
            target_fingerprint: invitation.target_fingerprint().to_vec(),
            token: invitation.token().to_vec(),
            welcome_bootstrap: invitation.welcome_bootstrap().to_vec(),
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned cursor byte buffer at the FFI boundary.
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
    /// Lists accepted signed events not yet retained by the authenticated peer.
    ///
    /// Event bytes remain exact. Forwarding attempts and peer acknowledgements
    /// persist independently, so interrupted contacts resume after restart.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid peer/cursor IDs, timestamps, page limits,
    /// or unavailable persisted relay state.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned buffers at the FFI boundary.
    pub fn forwardable_event_page(
        &self,
        peer_identity: Vec<u8>,
        after_event_id: Option<Vec<u8>>,
        now_ms: i64,
        limit: i32,
    ) -> Result<Vec<MobileForwardableEventEntry>, MobileError> {
        let peer_identity: [u8; 32] = peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
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
        if now_ms < 0 {
            return Err(MobileError::InvalidOutboxSchedule);
        }
        self.lock_client()?
            .forwardable_event_page(&peer_identity, after_event_id, now_ms, limit)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| MobileForwardableEventEntry {
                        event_id: entry.event_id.to_vec(),
                        canonical_bytes: entry.canonical_bytes,
                        next_attempt_ms: entry.next_attempt_ms,
                        attempt_count: entry.attempt_count,
                    })
                    .collect()
            })
            .map_err(|_| MobileError::OutboxUnavailable)
    }

    /// Persists a retryable attempt to carry one accepted event to one peer.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid peer/event IDs, an invalid retry time, or
    /// a rejected relay-state transition.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned buffers at the FFI boundary.
    pub fn mark_relay_event_attempt(
        &self,
        peer_identity: Vec<u8>,
        event_id: Vec<u8>,
        next_attempt_ms: i64,
    ) -> Result<(), MobileError> {
        let peer_identity: [u8; 32] = peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        if next_attempt_ms < 0 {
            return Err(MobileError::InvalidOutboxSchedule);
        }
        self.lock_client()?
            .mark_relay_event_attempt(&peer_identity, event_id, next_attempt_ms)
            .map_err(|_| MobileError::OutboxTransitionRejected)
    }

    /// Records authenticated peer acceptance, not destination delivery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid peer/event IDs, an ineligible event, or a
    /// storage failure.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned buffers at the FFI boundary.
    pub fn record_relay_event_peer_acceptance(
        &self,
        peer_identity: Vec<u8>,
        event_id: Vec<u8>,
    ) -> Result<(), MobileError> {
        let peer_identity: [u8; 32] = peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        self.lock_client()?
            .record_relay_event_peer_acceptance(&peer_identity, event_id)
            .map_err(|_| MobileError::OutboxTransitionRejected)
    }

    /// Persists one forwarding attempt before its envelope is placed on transport.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxEventId`, `InvalidOutboxSchedule`, or
    /// `OutboxTransitionRejected`.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned byte buffer at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned byte buffer at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned byte buffer at the FFI boundary.
    pub fn ingest_synced_application_event(
        &self,
        canonical_bytes: Vec<u8>,
        authenticated_peer_identity: Option<Vec<u8>>,
    ) -> Result<MobileSyncEventResult, MobileError> {
        let peer_identity = authenticated_peer_identity
            .map(|identity| {
                identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| MobileError::InvalidFingerprint)
            })
            .transpose()?;
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
        if matches!(
            state,
            MobileSyncEventState::Accepted | MobileSyncEventState::Duplicate
        ) && let Some(peer_identity) = peer_identity
        {
            client
                .record_relay_event_peer_acceptance(&peer_identity, event_id)
                .map_err(|_| MobileError::SyncIngestFailed)?;
        }
        let result = MobileSyncEventResult {
            event_id: event_id.to_vec(),
            state,
            missing_dependencies,
        };
        drop(client);
        publish_ingress_projection_change(&self.projection_observers, state);
        Ok(result)
    }

    /// Computes bounded manifest metadata from one app-private imported source.
    ///
    /// The identifier is an opaque lowercase-hex token; this API never accepts
    /// a caller-selected filesystem path.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentOperationFailed` if the source cannot be read or its
    /// metadata cannot be computed.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned strings at the FFI boundary.
    pub fn create_attachment_manifest(
        &self,
        source_id: String,
        filename: String,
    ) -> Result<MobileAttachmentManifest, MobileError> {
        let mut source = open_attachment_import(&self.database_path, &source_id)?;
        let manifest = AttachmentManifest::from_reader(&mut source, &filename, None)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        Ok(mobile_attachment_preview(&manifest))
    }

    /// Queues one Core-authorized signed Space manifest and durably stages the
    /// verified source under its event-bound transfer identity.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `InvalidSpaceCredential` for invalid credentials,
    /// `AttachmentOperationFailed` for invalid metadata or staging failures,
    /// `AttachmentManifestSourceChanged` if the imported file no longer matches
    /// the preview, or `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned arguments at the FFI boundary.
    pub fn queue_attachment_manifest(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        source_id: String,
        preview: MobileAttachmentManifest,
    ) -> Result<MobileAttachmentQueueReceipt, MobileError> {
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
        if preview.file_hash.len() != 32 || preview.file_size > MAX_MOBILE_ATTACHMENT_BYTES {
            return Err(MobileError::AttachmentOperationFailed);
        }

        let mut source = open_attachment_import(&self.database_path, &source_id)?;
        let manifest = AttachmentManifest::from_reader(&mut source, &preview.filename, None)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        if !attachment_preview_matches(&preview, &manifest) {
            return Err(MobileError::AttachmentManifestSourceChanged);
        }

        let mut client = self.lock_client()?;
        let queued = client
            .queue_file_manifest_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                channel_id,
                &manifest,
            )
            .map_err(|error| match error {
                CoreError::SpaceCredentialInvalid => MobileError::InvalidSpaceCredential,
                _ => MobileError::AttachmentOperationFailed,
            })?;
        let event_id = *queued.event_id();
        let source_retained =
            persist_sender_source(&self.database_path, &manifest, event_id, &mut source).is_ok();
        drop(source);
        if source_retained && let Ok(path) = attachment_import_path(&self.database_path, &source_id)
        {
            let _ = fs::remove_file(path);
        }

        let transfer_id = manifest
            .transfer_id(&event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let receipt = MobileAttachmentQueueReceipt {
            manifest: MobileAuthorizedAttachmentManifest {
                event_id: event_id.to_vec(),
                space_id: space_id.to_vec(),
                group_reference: group_reference.to_vec(),
                filename: manifest.filename.clone(),
                mime_type: manifest.mime_type.clone(),
                file_size: manifest.file_size,
                file_hash: manifest.file_hash.to_vec(),
                transfer_id: transfer_id.0.to_vec(),
            },
            source_retained,
        };
        drop(client);
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(receipt)
    }

    /// Returns a display-only summary only when Core authorizes this exact
    /// event ID in the restored Space generation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `AttachmentNotAuthorized` unless Core authorizes the exact manifest, or
    /// `AttachmentOperationFailed` if its summary cannot be formed.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn authorized_attachment_manifest(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        event_id: Vec<u8>,
    ) -> Result<MobileAuthorizedAttachmentManifest, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let mut client = self.lock_client()?;
        let space = client
            .restore_space(&space_id, &group_reference)
            .map_err(|_| MobileError::AttachmentNotAuthorized)?;
        let authorized = space
            .reducer()
            .authorized_attachment_manifest(&event_id)
            .ok_or(MobileError::AttachmentNotAuthorized)?;
        mobile_authorized_attachment_manifest(space_id, group_reference, &authorized)
    }
    /// Reopens the private receiver store and verifies staged chunks before
    /// reporting resumable progress.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `AttachmentNotAuthorized` unless Core authorizes the exact manifest, or
    /// `AttachmentOperationFailed` when staged data cannot be verified.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn attachment_staging_status(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        event_id: Vec<u8>,
    ) -> Result<MobileAttachmentStagingStatus, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let mut client = self.lock_client()?;
        let space = client
            .restore_space(&space_id, &group_reference)
            .map_err(|_| MobileError::AttachmentNotAuthorized)?;
        let authorized = space
            .reducer()
            .authorized_attachment_manifest(&event_id)
            .ok_or(MobileError::AttachmentNotAuthorized)?;
        let manifest = authorized.manifest().clone();
        ensure_mobile_attachment_size(&manifest)?;
        let transfer_id = manifest
            .transfer_id(&event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let total_chunks = manifest.chunk_hashes.len();
        if !staged_transfer_exists(&self.database_path, "receives", transfer_id.0)? {
            return Ok(MobileAttachmentStagingStatus {
                event_id: event_id.to_vec(),
                file_size: manifest.file_size,
                verified_chunks: 0,
                total_chunks: total_chunks as u64,
                complete: false,
            });
        }
        let store = receive_attachment_store(&self.database_path)?;
        let staged_file = store
            .open(&manifest, &event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let mut receiver = StreamedAttachmentReceiver::new(
            manifest.clone(),
            MAX_MOBILE_ATTACHMENT_BYTES,
            staged_file,
        )
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
        receiver
            .accept()
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let missing_chunks = receiver
            .missing_ranges()
            .map_err(|_| MobileError::AttachmentOperationFailed)?
            .iter()
            .map(|range| range.end_exclusive.saturating_sub(range.start))
            .sum::<usize>();
        let verified_chunks = total_chunks.saturating_sub(missing_chunks);
        Ok(MobileAttachmentStagingStatus {
            event_id: event_id.to_vec(),
            file_size: manifest.file_size,
            verified_chunks: verified_chunks as u64,
            total_chunks: total_chunks as u64,
            complete: receiver.is_complete(),
        })
    }

    /// Sends one authorized manifest over TCP and a separately domain-bound
    /// Noise session pinned to the exact active Space member.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` or `InvalidFingerprint` for malformed
    /// identifiers, `AttachmentPeerNotPinned` or `AttachmentPeerNotAuthorized`
    /// when the exact peer lacks required trust/membership, and
    /// `AttachmentNotAuthorized` or `AttachmentOperationFailed` for
    /// authorization, connection, verification, or transfer failures.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers and strings at the FFI boundary.
    pub fn send_attachment_once(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        event_id: Vec<u8>,
        peer_fingerprint: Vec<u8>,
        connect_address: String,
    ) -> Result<MobileAttachmentTransferReceipt, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let peer_fingerprint: [u8; 32] = peer_fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let connect_address = connect_address
            .parse::<SocketAddr>()
            .map_err(|_| MobileError::AttachmentOperationFailed)?;

        let mut client = self.lock_client()?;
        let manifest = authorized_attachment_manifest_for_peer(
            &mut client,
            space_id,
            group_reference,
            event_id,
            peer_fingerprint,
        )?;
        let transfer_id = manifest
            .transfer_id(&event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let mut source = open_verified_sender_source(&self.database_path, &manifest, event_id)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let adapter = runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    TcpPeerAdapter::connect(connect_address, ATTACHMENT_FRAME_LIMIT),
                )
                .await
            })
            .map_err(|_| MobileError::AttachmentOperationFailed)?
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let cancellation = CancellationToken::new();
        let transfer = runtime
            .block_on(async {
                tokio::time::timeout(
                    ATTACHMENT_SESSION_TIMEOUT,
                    client.with_pinned_identity(
                        &peer_fingerprint,
                        |identity, pinned_peer| async move {
                            send_authenticated_attachment_once(
                                &adapter,
                                identity,
                                pinned_peer,
                                event_id,
                                &manifest,
                                &mut source,
                                |authenticated_peer, candidate_event_id, candidate_manifest| {
                                    authenticated_peer.fingerprint() == peer_fingerprint
                                        && candidate_event_id == &event_id
                                        && candidate_manifest == &manifest
                                },
                                &cancellation,
                            )
                            .await
                        },
                    ),
                )
                .await
            })
            .map_err(|_| MobileError::AttachmentOperationFailed)?
            .map_err(|_| MobileError::AttachmentOperationFailed)?
            .ok_or(MobileError::AttachmentPeerNotPinned)?
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        if transfer.authenticated_peer.fingerprint() != peer_fingerprint
            || transfer.transfer_id != transfer_id
            || !transfer.receiver_verified_complete
        {
            return Err(MobileError::AttachmentOperationFailed);
        }
        Ok(MobileAttachmentTransferReceipt {
            event_id: event_id.to_vec(),
            peer_fingerprint: peer_fingerprint.to_vec(),
            transfer_id: transfer_id.0.to_vec(),
            is_sender: true,
            chunks_transferred: transfer.chunks_sent as u64,
            peer_verified: true,
            local_file_verified_complete: true,
            remote_file_verified_complete: transfer.receiver_verified_complete,
        })
    }

    /// Receives one authorized manifest into persistent private staging after
    /// explicit user consent and exact pinned-peer authorization.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentConsentRequired` without explicit consent,
    /// `InvalidSpaceMessageId` or `InvalidFingerprint` for malformed
    /// identifiers, `AttachmentPeerNotPinned` or `AttachmentPeerNotAuthorized`
    /// when the exact peer lacks required trust/membership, and
    /// `AttachmentNotAuthorized` or `AttachmentOperationFailed` for
    /// authorization, connection, verification, or transfer failures.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers and strings at the FFI boundary.
    pub fn receive_attachment_once(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        event_id: Vec<u8>,
        peer_fingerprint: Vec<u8>,
        listen_address: String,
        user_consented: bool,
    ) -> Result<MobileAttachmentTransferReceipt, MobileError> {
        if !user_consented {
            return Err(MobileError::AttachmentConsentRequired);
        }
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let peer_fingerprint: [u8; 32] = peer_fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let listen_address = listen_address
            .parse::<SocketAddr>()
            .map_err(|_| MobileError::AttachmentOperationFailed)?;

        let mut client = self.lock_client()?;
        let manifest = authorized_attachment_manifest_for_peer(
            &mut client,
            space_id,
            group_reference,
            event_id,
            peer_fingerprint,
        )?;
        let transfer_id = manifest
            .transfer_id(&event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let store = receive_attachment_store(&self.database_path)?;
        let staged_file = store
            .open(&manifest, &event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let mut receiver = StreamedAttachmentReceiver::new(
            manifest.clone(),
            MAX_MOBILE_ATTACHMENT_BYTES,
            staged_file,
        )
        .map_err(|_| MobileError::AttachmentOperationFailed)?;

        let transfer = run_attachment_receive(
            &mut client,
            listen_address,
            peer_fingerprint,
            event_id,
            &manifest,
            &mut receiver,
            user_consented,
        )?;
        if transfer.authenticated_peer.fingerprint() != peer_fingerprint
            || transfer.transfer_id != transfer_id
            || !transfer.verified_complete
        {
            return Err(MobileError::AttachmentOperationFailed);
        }
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(MobileAttachmentTransferReceipt {
            event_id: event_id.to_vec(),
            peer_fingerprint: peer_fingerprint.to_vec(),
            transfer_id: transfer_id.0.to_vec(),
            is_sender: false,
            chunks_transferred: transfer.chunks_received as u64,
            peer_verified: true,
            local_file_verified_complete: transfer.verified_complete,
            remote_file_verified_complete: false,
        })
    }

    /// Copies an already-complete staged attachment to a bounded app-private
    /// temporary file for the native document picker to export.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `AttachmentNotAuthorized` unless Core authorizes the exact manifest,
    /// `AttachmentOperationFailed` if staged bytes are incomplete or fail
    /// verification, or a profile/filesystem error.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn prepare_attachment_export(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        event_id: Vec<u8>,
    ) -> Result<MobileAttachmentExport, MobileError> {
        let space_id: [u8; 16] = space_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let event_id: [u8; 32] = event_id
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let mut client = self.lock_client()?;
        let space = client
            .restore_space(&space_id, &group_reference)
            .map_err(|_| MobileError::AttachmentNotAuthorized)?;
        let authorized = space
            .reducer()
            .authorized_attachment_manifest(&event_id)
            .ok_or(MobileError::AttachmentNotAuthorized)?;
        let manifest = authorized.manifest().clone();
        ensure_mobile_attachment_size(&manifest)?;
        let transfer_id = manifest
            .transfer_id(&event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        ensure_staged_transfer_exists(&self.database_path, "receives", transfer_id.0)?;
        let store = receive_attachment_store(&self.database_path)?;
        let staged_file = store
            .open(&manifest, &event_id)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        let mut receiver = StreamedAttachmentReceiver::new(
            manifest.clone(),
            MAX_MOBILE_ATTACHMENT_BYTES,
            staged_file,
        )
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
        receiver
            .accept()
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        if !receiver.is_complete() {
            return Err(MobileError::AttachmentOperationFailed);
        }

        let export_id = lower_hex(&transfer_id.0);
        let export_path = attachment_export_path(&self.database_path, &export_id)?;
        let (mut output, already_verified) = create_private_export_file(&export_path, &manifest)?;
        if !already_verified {
            if receiver.copy_verified_to(&mut output).is_err() {
                let _ = fs::remove_file(&export_path);
                return Err(MobileError::AttachmentOperationFailed);
            }
            output
                .sync_all()
                .map_err(|_| MobileError::AttachmentOperationFailed)?;
        }
        Ok(MobileAttachmentExport {
            export_id,
            filename: manifest.filename,
            file_size: manifest.file_size,
            file_hash: manifest.file_hash.to_vec(),
        })
    }

    /// Removes one internal export temporary file after document-picker use.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentOperationFailed` for an invalid export identifier or
    /// when the temporary file cannot safely be removed.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned string at the FFI boundary.
    pub fn finish_attachment_export(&self, export_id: String) -> Result<bool, MobileError> {
        let path = attachment_export_path(&self.database_path, &export_id)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(path).map_err(|_| MobileError::AttachmentOperationFailed)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Ok(_) | Err(_) => Err(MobileError::AttachmentOperationFailed),
        }
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers and query text at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned bytes and text at the FFI boundary.
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
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned bytes and text at the FFI boundary.
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
    /// Queues a locally authorized immutable thread reply.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `InvalidSpaceCredential` for malformed or untrusted credentials,
    /// `InvalidMessageInput` for oversized text, `MessageRejected` when local
    /// policy denies the reply, or `MessageQueueFailed` for other failures.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned bytes and text at the FFI boundary.
    pub fn queue_local_text_message_reply(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        thread_root: Vec<u8>,
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
        let thread_root: [u8; 32] = thread_root
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
            .queue_text_message_reply_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                channel_id,
                thread_root,
                &content,
            )
            .map_err(|error| map_queue_message_error(&error))?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        })
    }

    /// Queues a locally authorized tombstone for a locally authored message.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers,
    /// `InvalidSpaceCredential` for malformed or untrusted credentials,
    /// `MessageRejected` when local policy denies the tombstone, or
    /// `MessageQueueFailed` for other failures.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned bytes at the FFI boundary.
    pub fn queue_local_text_message_tombstone(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        target_message_id: Vec<u8>,
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
        let queued = self
            .lock_client()?
            .queue_text_message_tombstone_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                channel_id,
                target,
            )
            .map_err(|error| map_queue_message_error(&error))?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        })
    }

    /// Queues a tagged reaction add or observed-tag removal.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers or tags,
    /// `InvalidSpaceCredential` for malformed or untrusted credentials,
    /// `InvalidMessageInput` for an invalid reaction token, `MessageRejected`
    /// when local policy denies the reaction, or `MessageQueueFailed` for
    /// other failures.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned bytes and token text at the FFI boundary.
    #[allow(clippy::too_many_arguments)] // The UniFFI positional API is already public and cannot be grouped without a breaking change.
    pub fn queue_local_text_message_reaction(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        target_message_id: Vec<u8>,
        token: String,
        add: bool,
        tag: Option<Vec<u8>>,
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
        let tag = tag
            .map(|tag| {
                tag.try_into()
                    .map_err(|_| MobileError::InvalidSpaceMessageId)
            })
            .transpose()?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        if token.is_empty() || token.len() > 64 {
            return Err(MobileError::InvalidMessageInput);
        }
        let queued = self
            .lock_client()?
            .queue_text_message_reaction_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                &TextMessageReaction {
                    channel_id,
                    target,
                    token,
                    add,
                    tag,
                },
            )
            .map_err(|error| map_queue_message_error(&error))?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        })
    }

    /// Queues a pin add or observed-tag removal.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for malformed identifiers or tags,
    /// `InvalidSpaceCredential` for malformed or untrusted credentials,
    /// `MessageRejected` when local policy denies the pin, or
    /// `MessageQueueFailed` for other failures.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned bytes at the FFI boundary.
    #[allow(clippy::too_many_arguments)] // The UniFFI positional API is already public and cannot be grouped without a breaking change.
    pub fn queue_local_text_message_pin(
        &self,
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        credential_vector: Vec<u8>,
        channel_id: Vec<u8>,
        target_message_id: Vec<u8>,
        add: bool,
        tag: Option<Vec<u8>>,
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
        let tag = tag
            .map(|tag| {
                tag.try_into()
                    .map_err(|_| MobileError::InvalidSpaceMessageId)
            })
            .transpose()?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        let queued = self
            .lock_client()?
            .queue_text_message_pin_from_x509_credential(
                &space_id,
                &group_reference,
                credential_vector,
                TextMessagePin {
                    channel_id,
                    target,
                    add,
                    tag,
                },
            )
            .map_err(|error| map_queue_message_error(&error))?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        })
    }

    /// Publishes one validated local `KeyPackage` for a pairwise DM invitation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceCredential` for empty or oversized credentials,
    /// `ProfileUnavailable` if the profile lock is poisoned, or
    /// `DirectMessageFailed` if Core cannot publish the package.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned credential buffer at the FFI boundary.
    pub fn publish_direct_message_key_package(
        &self,
        credential_vector: Vec<u8>,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, MobileError> {
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        self.lock_client()?
            .publish_direct_message_key_package(credential_vector, now_unix_seconds)
            .map_err(|_| MobileError::DirectMessageFailed)
    }

    /// Creates and durably queues an opaque MLS Welcome invitation packet.
    ///
    /// # Errors
    ///
    /// Returns `InvalidFingerprint` for malformed peer identity bytes,
    /// `DirectMessageFailed` for invalid package/scheduling input or failed
    /// creation, or `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn create_direct_message(
        &self,
        credential_vector: Vec<u8>,
        peer_identity: Vec<u8>,
        peer_key_package: Vec<u8>,
        next_attempt_ms: i64,
    ) -> Result<MobileCreatedDirectMessage, MobileError> {
        let peer_identity: [u8; 32] = peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        if credential_vector.is_empty()
            || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES
            || peer_key_package.is_empty()
            || peer_key_package.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES
            || next_attempt_ms < 0
        {
            return Err(MobileError::DirectMessageFailed);
        }
        let created = self
            .lock_client()?
            .create_direct_message_from_x509_credential(
                credential_vector,
                peer_identity,
                &peer_key_package,
                next_attempt_ms,
            )
            .map_err(|_| MobileError::DirectMessageFailed)?;
        Ok(MobileCreatedDirectMessage {
            conversation: MobileDirectMessageConversation {
                group_reference: created.group_reference.to_vec(),
                peer_identity: created.peer_identity.to_vec(),
                closed: false,
            },
            invitation: mobile_direct_message_packet(created.invitation),
        })
    }

    /// Imports a routed Welcome only after explicit user acceptance.
    ///
    /// # Errors
    ///
    /// Returns `DirectMessageNotAccepted` without explicit acceptance,
    /// `InvalidFingerprint` for malformed peer identity bytes,
    /// `DirectMessageFailed` for invalid packet/credential bytes or failed
    /// import, or `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn accept_direct_message_invitation(
        &self,
        credential_vector: Vec<u8>,
        authenticated_peer_identity: Vec<u8>,
        invitation_packet: Vec<u8>,
        user_accepted: bool,
    ) -> Result<Vec<u8>, MobileError> {
        if !user_accepted {
            return Err(MobileError::DirectMessageNotAccepted);
        }
        let authenticated_peer_identity: [u8; 32] = authenticated_peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        if credential_vector.is_empty()
            || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES
            || invitation_packet.is_empty()
            || invitation_packet.len() > MAX_DIRECT_MESSAGE_PACKET_BYTES
        {
            return Err(MobileError::DirectMessageFailed);
        }
        let group_reference = self
            .lock_client()?
            .accept_direct_message_invitation_from_x509_credential(
                credential_vector,
                authenticated_peer_identity,
                &invitation_packet,
                true,
            )
            .map_err(|_| MobileError::DirectMessageFailed)?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(group_reference.to_vec())
    }

    /// Encrypts text locally and commits the resulting opaque packet to Core.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for a malformed conversation ID,
    /// `DirectMessageFailed` for invalid input or a failed queue operation, or
    /// `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers and text at the FFI boundary.
    pub fn queue_direct_message_text(
        &self,
        credential_vector: Vec<u8>,
        group_reference: Vec<u8>,
        content: String,
        next_attempt_ms: i64,
    ) -> Result<MobileDirectMessagePacket, MobileError> {
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if credential_vector.is_empty()
            || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES
            || content.is_empty()
            || content.len() > MAX_DIRECT_MESSAGE_TEXT_BYTES
            || next_attempt_ms < 0
        {
            return Err(MobileError::DirectMessageFailed);
        }
        let packet = self
            .lock_client()?
            .queue_direct_message_text_from_x509_credential(
                credential_vector,
                group_reference,
                &content,
                next_attempt_ms,
            )
            .map_err(|_| MobileError::DirectMessageFailed)?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(mobile_direct_message_packet(packet))
    }

    /// Authenticates one opaque application packet from the pinned peer.
    ///
    /// # Errors
    ///
    /// Returns `InvalidFingerprint` for malformed peer identity bytes,
    /// `DirectMessageFailed` for invalid packets or failed authenticated
    /// ingress, or `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn ingest_direct_message_packet(
        &self,
        authenticated_peer_identity: Vec<u8>,
        envelope_bytes: Vec<u8>,
    ) -> Result<MobileDirectMessageIngressResult, MobileError> {
        let authenticated_peer_identity: [u8; 32] = authenticated_peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_DIRECT_MESSAGE_PACKET_BYTES {
            return Err(MobileError::DirectMessageFailed);
        }
        let outcome = self
            .lock_client()?
            .ingest_direct_message_packet(authenticated_peer_identity, &envelope_bytes)
            .map_err(|_| MobileError::DirectMessageFailed)?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(match outcome {
            DirectMessageIngressOutcome::Accepted { packet_id, content } => {
                MobileDirectMessageIngressResult {
                    packet_id: packet_id.to_vec(),
                    duplicate: false,
                    invitation_pending: false,
                    group_reference: None,
                    peer_identity: None,
                    content: Some(content),
                }
            }
            DirectMessageIngressOutcome::InvitationPending {
                packet_id,
                group_reference,
                peer_identity,
            } => MobileDirectMessageIngressResult {
                packet_id: packet_id.to_vec(),
                duplicate: false,
                invitation_pending: true,
                group_reference: Some(group_reference.to_vec()),
                peer_identity: Some(peer_identity.to_vec()),
                content: None,
            },
            DirectMessageIngressOutcome::Duplicate { packet_id } => {
                MobileDirectMessageIngressResult {
                    packet_id: packet_id.to_vec(),
                    duplicate: true,
                    invitation_pending: false,
                    group_reference: None,
                    peer_identity: None,
                    content: None,
                }
            }
        })
    }

    /// Lists local pairwise conversations in stable bounded order.
    ///
    /// # Errors
    ///
    /// Returns `DirectMessageFailed` for an invalid page size or failed
    /// conversation lookup, or `ProfileUnavailable` if the profile lock is
    /// unavailable.
    pub fn direct_message_conversations(
        &self,
        limit: u32,
    ) -> Result<Vec<MobileDirectMessageConversation>, MobileError> {
        if limit == 0 || limit as usize > MAX_OUTBOX_PAGE_SIZE {
            return Err(MobileError::DirectMessageFailed);
        }
        self.lock_client()?
            .direct_message_conversations(limit as usize)
            .map(|conversations| {
                conversations
                    .into_iter()
                    .map(|conversation| MobileDirectMessageConversation {
                        group_reference: conversation.group_reference.to_vec(),
                        peer_identity: conversation.peer_identity.to_vec(),
                        closed: conversation.closed,
                    })
                    .collect()
            })
            .map_err(|_| MobileError::DirectMessageFailed)
    }

    /// Verifies that an outbox packet targets the authenticated BLE peer.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` or `InvalidFingerprint` for malformed
    /// IDs, `DirectMessageFailed` if the conversation lookup fails, or
    /// `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn direct_message_is_for_peer(
        &self,
        group_reference: Vec<u8>,
        peer_identity: Vec<u8>,
    ) -> Result<bool, MobileError> {
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        let peer_identity: [u8; 32] = peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        self.lock_client()?
            .direct_message_is_for_peer(group_reference, peer_identity)
            .map_err(|_| MobileError::DirectMessageFailed)
    }

    /// Reads decrypted local history for one pairwise conversation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceMessageId` for a malformed conversation ID,
    /// `DirectMessageFailed` for an invalid page size or failed history lookup,
    /// or `ProfileUnavailable` if the profile lock is unavailable.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned byte buffer at the FFI boundary.
    pub fn direct_message_history(
        &self,
        group_reference: Vec<u8>,
        limit: u32,
    ) -> Result<Vec<MobileDirectMessageHistoryEntry>, MobileError> {
        let group_reference: [u8; 32] = group_reference
            .try_into()
            .map_err(|_| MobileError::InvalidSpaceMessageId)?;
        if limit == 0 || limit as usize > MAX_OUTBOX_PAGE_SIZE {
            return Err(MobileError::DirectMessageFailed);
        }
        self.lock_client()?
            .direct_message_history(group_reference, limit as usize)
            .map(|history| {
                history
                    .into_iter()
                    .map(|message| MobileDirectMessageHistoryEntry {
                        packet_id: message.packet_id.to_vec(),
                        group_reference: message.group_reference.to_vec(),
                        author_identity: message.author_identity.to_vec(),
                        content: message.content,
                    })
                    .collect()
            })
            .map_err(|_| MobileError::DirectMessageFailed)
    }

    /// Reads a bounded page of durable opaque DM packets awaiting forwarding.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxCursor` for a malformed cursor,
    /// `InvalidOutboxPage` for an invalid page size, `OutboxUnavailable` for
    /// storage failures, or `ProfileUnavailable` if the profile lock fails.
    pub fn direct_message_outbox_page(
        &self,
        after_packet_id: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<MobileDirectMessageOutboxEntry>, MobileError> {
        let after_packet_id = after_packet_id
            .map(|packet_id| {
                packet_id
                    .try_into()
                    .map_err(|_| MobileError::InvalidOutboxCursor)
            })
            .transpose()?;
        if limit == 0 || limit as usize > MAX_OUTBOX_PAGE_SIZE {
            return Err(MobileError::InvalidOutboxPage);
        }
        self.lock_client()?
            .direct_message_outbox_page(after_packet_id, limit as usize)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(mobile_direct_message_outbox_entry)
                    .collect()
            })
            .map_err(|_| MobileError::OutboxUnavailable)
    }

    /// Persists the retry attempt before routing the DM packet.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxEventId` for a malformed packet ID,
    /// `InvalidOutboxSchedule` for a negative retry time, or
    /// `OutboxTransitionRejected` if the state transition is invalid.
    pub fn mark_direct_message_attempt(
        &self,
        packet_id: Vec<u8>,
        next_attempt_ms: i64,
    ) -> Result<(), MobileError> {
        let packet_id: [u8; 32] = packet_id
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        if next_attempt_ms < 0 {
            return Err(MobileError::InvalidOutboxSchedule);
        }
        self.lock_client()?
            .mark_direct_message_attempt(packet_id, next_attempt_ms)
            .map_err(|_| MobileError::OutboxTransitionRejected)
    }

    /// Records authenticated peer-ingress acceptance, not destination delivery.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxEventId` for a malformed packet ID or
    /// `OutboxTransitionRejected` if the ingress transition is invalid.
    pub fn record_direct_message_peer_ingress_accepted(
        &self,
        packet_id: Vec<u8>,
    ) -> Result<(), MobileError> {
        let packet_id: [u8; 32] = packet_id
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        self.lock_client()?
            .record_direct_message_peer_ingress_accepted(packet_id)
            .map_err(|_| MobileError::OutboxTransitionRejected)
    }

    /// Runs one authenticated, pinned TCP direct-message exchange over a local
    /// LAN path. It sends at most one due opaque packet in each direction.
    ///
    /// # Errors
    ///
    /// Returns `InvalidFingerprint` for a malformed fingerprint,
    /// `DirectMessageFailed` for invalid addresses, an unpinned peer, or
    /// exchange failures, `OutboxUnavailable` for storage failures,
    /// `OutboxTransitionRejected` for invalid state changes, or
    /// `ProfileOpenFailed` if a read-only ingress client cannot be opened.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned strings and byte buffers at the FFI boundary.
    pub fn exchange_direct_messages_once(
        &self,
        connect_address: String,
        listen_address: String,
        peer_fingerprint: Vec<u8>,
    ) -> Result<MobileDirectMessageExchange, MobileError> {
        let connect = connect_address
            .parse::<SocketAddr>()
            .map_err(|_| MobileError::DirectMessageFailed)?;
        let listen = listen_address
            .parse::<SocketAddr>()
            .map_err(|_| MobileError::DirectMessageFailed)?;
        let peer_fingerprint: [u8; 32] = peer_fingerprint
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let mut client = self.lock_client()?;
        let local_fingerprint = client.identity_info().fingerprint;
        if local_fingerprint == peer_fingerprint
            || client
                .pinned_identity(&peer_fingerprint)
                .map_err(|_| MobileError::DirectMessageFailed)?
                .is_none()
        {
            return Err(MobileError::DirectMessageFailed);
        }

        let now_ms = unix_millis_i64();
        let mut cursor = None;
        let mut outgoing = None;
        loop {
            let page = client
                .direct_message_outbox_page(cursor, 64)
                .map_err(|_| MobileError::OutboxUnavailable)?;
            for packet in &page {
                if packet.next_attempt_ms <= now_ms
                    && matches!(
                        packet.state,
                        OutboxState::Queued | OutboxState::Forwarding | OutboxState::Forwarded
                    )
                    && client
                        .direct_message_is_for_peer(packet.group_reference, peer_fingerprint)
                        .map_err(|_| MobileError::DirectMessageFailed)?
                {
                    outgoing = Some(packet.clone());
                    break;
                }
            }
            if outgoing.is_some() || page.len() < 64 {
                break;
            }
            cursor = page.last().map(|packet| packet.packet_id);
        }
        let outgoing_id = outgoing.as_ref().map(|packet| packet.packet_id);
        let outgoing_bytes = outgoing
            .as_ref()
            .map(|packet| packet.envelope_bytes.as_slice());
        if outgoing_bytes.is_some_and(|bytes| bytes.len() > MAX_ENVELOPE_BYTES) {
            return Err(MobileError::DirectMessageFailed);
        }
        if let Some(packet_id) = outgoing_id {
            client
                .mark_direct_message_attempt(packet_id, now_ms.saturating_add(30_000))
                .map_err(|_| MobileError::OutboxTransitionRejected)?;
        }

        let (bound, exchange) = run_direct_message_exchange(
            &mut client,
            DirectMessageExchangeRequest {
                database_path: &self.database_path,
                profile_protector: &self.profile_protector,
                connect,
                listen,
                local_fingerprint,
                peer_fingerprint,
                outgoing: outgoing_id.zip(outgoing_bytes),
            },
        )?;
        if let Some(receipt) = exchange.outgoing {
            if Some(receipt.packet_id) != outgoing_id {
                return Err(MobileError::DirectMessageFailed);
            }
            client
                .record_direct_message_peer_ingress_accepted(receipt.packet_id)
                .map_err(|_| MobileError::OutboxTransitionRejected)?;
        }
        if exchange.incoming.is_some() || exchange.outgoing.is_some() {
            self.projection_observers
                .publish(MobileProjectionChange::Messages);
        }
        Ok(MobileDirectMessageExchange {
            listen_address: bound.to_string(),
            peer_fingerprint: peer_fingerprint.to_vec(),
            outgoing_packet_id: exchange.outgoing.map(|receipt| receipt.packet_id.to_vec()),
            outgoing_ingress_state: exchange
                .outgoing
                .map(|receipt| direct_message_ingress_label(receipt.state).to_owned()),
            incoming_packet_id: exchange.incoming.map(|receipt| receipt.packet_id.to_vec()),
            incoming_ingress_state: exchange
                .incoming
                .map(|receipt| direct_message_ingress_label(receipt.state).to_owned()),
        })
    }

    /// Lists bounded invitations saved from authenticated transport ingress.
    ///
    /// # Errors
    ///
    /// Returns `DirectMessageFailed` for an invalid page size or failed lookup,
    /// or `ProfileUnavailable` if the profile lock is unavailable.
    pub fn pending_direct_message_invitations(
        &self,
        limit: u32,
    ) -> Result<Vec<MobileDirectMessagePendingInvitation>, MobileError> {
        if limit == 0 || limit as usize > MAX_DIRECT_MESSAGE_PENDING_INVITATIONS {
            return Err(MobileError::DirectMessageFailed);
        }
        self.lock_client()?
            .pending_direct_message_invitations(limit as usize)
            .map(|invitations| {
                invitations
                    .into_iter()
                    .map(|invitation| MobileDirectMessagePendingInvitation {
                        packet_id: invitation.packet_id.to_vec(),
                        group_reference: invitation.group_reference.to_vec(),
                        peer_identity: invitation.peer_identity.to_vec(),
                    })
                    .collect()
            })
            .map_err(|_| MobileError::DirectMessageFailed)
    }

    /// Accepts a persisted invitation only with user consent and matching peer.
    ///
    /// # Errors
    ///
    /// Returns `DirectMessageNotAccepted` without explicit acceptance,
    /// `InvalidFingerprint` or `InvalidOutboxEventId` for malformed identifiers,
    /// `InvalidSpaceCredential` for invalid credentials, or
    /// `DirectMessageFailed` if importing the accepted invitation fails.
    #[allow(clippy::needless_pass_by_value)] // UniFFI requires owned byte buffers at the FFI boundary.
    pub fn accept_pending_direct_message_invitation(
        &self,
        credential_vector: Vec<u8>,
        authenticated_peer_identity: Vec<u8>,
        packet_id: Vec<u8>,
        user_accepted: bool,
    ) -> Result<Vec<u8>, MobileError> {
        if !user_accepted {
            return Err(MobileError::DirectMessageNotAccepted);
        }
        let authenticated_peer_identity: [u8; 32] = authenticated_peer_identity
            .try_into()
            .map_err(|_| MobileError::InvalidFingerprint)?;
        let packet_id: [u8; 32] = packet_id
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        if credential_vector.is_empty() || credential_vector.len() > MAX_SPACE_CREDENTIAL_BYTES {
            return Err(MobileError::InvalidSpaceCredential);
        }
        let group_reference = self
            .lock_client()?
            .accept_pending_direct_message_invitation_from_x509_credential(
                credential_vector,
                authenticated_peer_identity,
                packet_id,
                true,
            )
            .map_err(|_| MobileError::DirectMessageFailed)?;
        self.projection_observers
            .publish(MobileProjectionChange::Messages);
        Ok(group_reference.to_vec())
    }

    /// Declines a pending invitation without importing its MLS Welcome.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOutboxEventId` for a malformed packet ID or
    /// `DirectMessageFailed` if the pending invitation cannot be declined.
    pub fn decline_pending_direct_message_invitation(
        &self,
        packet_id: Vec<u8>,
    ) -> Result<bool, MobileError> {
        let packet_id: [u8; 32] = packet_id
            .try_into()
            .map_err(|_| MobileError::InvalidOutboxEventId)?;
        self.lock_client()?
            .decline_pending_direct_message_invitation(packet_id)
            .map_err(|_| MobileError::DirectMessageFailed)
    }
}
#[derive(Clone, Copy)]
struct DirectMessageExchangeRequest<'a> {
    database_path: &'a str,
    profile_protector: &'a ProfileProtector,
    connect: SocketAddr,
    listen: SocketAddr,
    local_fingerprint: [u8; 32],
    peer_fingerprint: [u8; 32],
    outgoing: Option<([u8; 32], &'a [u8])>,
}

async fn connect_direct_message_peer(
    connect: SocketAddr,
) -> Result<TcpPeerAdapter, TransportError> {
    loop {
        match TcpPeerAdapter::connect(connect, MAX_ENVELOPE_BYTES).await {
            Err(TransportError::Unavailable) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            result => return result,
        }
    }
}

fn run_direct_message_exchange(
    client: &mut Client,
    request: DirectMessageExchangeRequest<'_>,
) -> Result<(SocketAddr, AuthenticatedDirectMessageExchange), MobileError> {
    let DirectMessageExchangeRequest {
        database_path,
        profile_protector,
        connect,
        listen,
        local_fingerprint,
        peer_fingerprint,
        outgoing,
    } = request;
    let mut ingress_client = Client::open_existing(database_path, profile_protector)
        .map_err(|_| MobileError::ProfileOpenFailed)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| MobileError::DirectMessageFailed)?;
    let listener = runtime
        .block_on(TcpPeerListener::bind(listen, MAX_ENVELOPE_BYTES))
        .map_err(|_| MobileError::DirectMessageFailed)?;
    let bound = listener
        .local_addr()
        .map_err(|_| MobileError::DirectMessageFailed)?;
    let (outbound, (inbound, _remote)) = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::try_join!(connect_direct_message_peer(connect), listener.accept())
            })
            .await
        })
        .map_err(|_| MobileError::DirectMessageFailed)?
        .map_err(|_| MobileError::DirectMessageFailed)?;
    let is_initiator = local_fingerprint < peer_fingerprint;
    let exchange = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(30),
                client.with_pinned_identity(
                    &peer_fingerprint,
                    |identity, pinned_peer| async move {
                        let cancellation = CancellationToken::new();
                        let mut ingest = |peer: &lattice_identity::PinnedIdentity, bytes: &[u8]| {
                            let outcome = ingress_client
                                .ingest_direct_message_packet(peer.fingerprint(), bytes)
                                .map_err(|error| error.to_string())?;
                            let (packet_id, state) = match outcome {
                                DirectMessageIngressOutcome::Accepted { packet_id, .. } => {
                                    (packet_id, DirectMessageIngressState::Accepted)
                                }
                                DirectMessageIngressOutcome::InvitationPending {
                                    packet_id,
                                    ..
                                } => (packet_id, DirectMessageIngressState::InvitationPending),
                                DirectMessageIngressOutcome::Duplicate { packet_id } => {
                                    (packet_id, DirectMessageIngressState::Duplicate)
                                }
                            };
                            Ok(DirectMessageIngressReceipt { packet_id, state })
                        };
                        if is_initiator {
                            execute_authenticated_direct_message_once(
                                &outbound,
                                identity,
                                pinned_peer,
                                outgoing,
                                &mut ingest,
                                &cancellation,
                            )
                            .await
                        } else {
                            serve_authenticated_direct_message_once(
                                &inbound,
                                identity,
                                pinned_peer,
                                outgoing,
                                &mut ingest,
                                &cancellation,
                            )
                            .await
                        }
                        .map_err(|_| MobileError::DirectMessageFailed)
                    },
                ),
            )
            .await
        })
        .map_err(|_| MobileError::DirectMessageFailed)?
        .map_err(|_| MobileError::DirectMessageFailed)?
        .ok_or(MobileError::DirectMessageFailed)??;
    Ok((bound, exchange))
}
fn run_attachment_receive<S: io::Read + io::Write + Seek>(
    client: &mut Client,
    listen_address: SocketAddr,
    peer_fingerprint: [u8; 32],
    event_id: [u8; 32],
    manifest: &AttachmentManifest,
    receiver: &mut StreamedAttachmentReceiver<S>,
    user_consented: bool,
) -> Result<AttachmentReceiveResult, MobileError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let listener = runtime
        .block_on(TcpPeerListener::bind(
            listen_address,
            ATTACHMENT_FRAME_LIMIT,
        ))
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let (adapter, _) = runtime
        .block_on(async {
            tokio::time::timeout(ATTACHMENT_SESSION_TIMEOUT, listener.accept()).await
        })
        .map_err(|_| MobileError::AttachmentOperationFailed)?
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let cancellation = CancellationToken::new();
    runtime
        .block_on(async {
            tokio::time::timeout(
                ATTACHMENT_SESSION_TIMEOUT,
                client.with_pinned_identity(
                    &peer_fingerprint,
                    |identity, pinned_peer| async move {
                        receive_authenticated_attachment_once(
                            &adapter,
                            identity,
                            pinned_peer,
                            event_id,
                            manifest,
                            receiver,
                            |authenticated_peer, candidate_event_id, candidate_manifest| {
                                authenticated_peer.fingerprint() == peer_fingerprint
                                    && candidate_event_id == &event_id
                                    && candidate_manifest == manifest
                            },
                            |_authenticated_peer, _candidate_manifest| async move {
                                user_consented
                            },
                            &cancellation,
                        )
                        .await
                    },
                ),
            )
            .await
        })
        .map_err(|_| MobileError::AttachmentOperationFailed)?
        .map_err(|_| MobileError::AttachmentOperationFailed)?
        .ok_or(MobileError::AttachmentPeerNotPinned)?
        .map_err(|_| MobileError::AttachmentOperationFailed)
}

const ATTACHMENT_FRAME_LIMIT: usize = CHUNK_SIZE + 1024;
const ATTACHMENT_SESSION_TIMEOUT: Duration = Duration::from_mins(30);
const MAX_MOBILE_ATTACHMENT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_MOBILE_ATTACHMENT_STAGING_BYTES: u64 = 512 * 1024 * 1024;

fn mobile_attachment_preview(manifest: &AttachmentManifest) -> MobileAttachmentManifest {
    MobileAttachmentManifest {
        filename: manifest.filename.clone(),
        file_size: manifest.file_size,
        file_hash: manifest.file_hash.to_vec(),
    }
}

fn attachment_preview_matches(
    preview: &MobileAttachmentManifest,
    manifest: &AttachmentManifest,
) -> bool {
    preview.filename == manifest.filename
        && preview.file_size == manifest.file_size
        && preview.file_hash.as_slice() == manifest.file_hash.as_slice()
}

fn ensure_mobile_attachment_size(manifest: &AttachmentManifest) -> Result<(), MobileError> {
    if manifest.file_size > MAX_MOBILE_ATTACHMENT_BYTES {
        Err(MobileError::AttachmentOperationFailed)
    } else {
        Ok(())
    }
}
fn authorized_attachment_manifest_for_peer(
    client: &mut Client,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    event_id: [u8; 32],
    peer_fingerprint: [u8; 32],
) -> Result<AttachmentManifest, MobileError> {
    let local_fingerprint = client.identity_info().fingerprint;
    if local_fingerprint == peer_fingerprint
        || client
            .pinned_identity(&peer_fingerprint)
            .map_err(|_| MobileError::AttachmentOperationFailed)?
            .is_none()
    {
        return Err(MobileError::AttachmentPeerNotPinned);
    }
    let space = client
        .restore_space(&space_id, &group_reference)
        .map_err(|_| MobileError::AttachmentNotAuthorized)?;
    if !space_has_active_member(&space, &peer_fingerprint) {
        return Err(MobileError::AttachmentPeerNotAuthorized);
    }
    let authorized = space
        .reducer()
        .authorized_attachment_manifest(&event_id)
        .ok_or(MobileError::AttachmentNotAuthorized)?;
    let manifest = authorized.manifest().clone();
    ensure_mobile_attachment_size(&manifest)?;
    Ok(manifest)
}

fn mobile_authorized_attachment_manifest(
    space_id: [u8; 16],
    group_reference: [u8; 32],
    authorized: &lattice_core::space::AuthorizedAttachmentManifest,
) -> Result<MobileAuthorizedAttachmentManifest, MobileError> {
    let manifest = authorized.manifest();
    let transfer_id = authorized
        .transfer_id()
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    Ok(MobileAuthorizedAttachmentManifest {
        event_id: authorized.event_id().to_vec(),
        space_id: space_id.to_vec(),
        group_reference: group_reference.to_vec(),
        filename: manifest.filename.clone(),
        mime_type: manifest.mime_type.clone(),
        file_size: manifest.file_size,
        file_hash: manifest.file_hash.to_vec(),
        transfer_id: transfer_id.0.to_vec(),
    })
}

fn space_has_active_member(space: &lattice_core::CreatedSpace, fingerprint: &[u8; 32]) -> bool {
    space.reducer().policy().is_some_and(|policy| {
        policy.members.iter().any(|member| {
            member.fingerprint == *fingerprint && member.status == MemberStatus::Active
        })
    })
}

fn attachment_root(database_path: &str) -> Result<PathBuf, MobileError> {
    let database_parent = Path::new(database_path)
        .parent()
        .ok_or(MobileError::AttachmentOperationFailed)?;
    let root = database_parent.join("attachments");
    ensure_private_directory(&root)?;
    Ok(root)
}

fn attachment_subdirectory(database_path: &str, name: &str) -> Result<PathBuf, MobileError> {
    let root = attachment_root(database_path)?;
    let directory = root.join(name);
    ensure_private_directory(&directory)?;
    let root = fs::canonicalize(root).map_err(|_| MobileError::AttachmentOperationFailed)?;
    let directory =
        fs::canonicalize(directory).map_err(|_| MobileError::AttachmentOperationFailed)?;
    if directory.parent() != Some(root.as_path()) {
        return Err(MobileError::AttachmentOperationFailed);
    }
    Ok(directory)
}

fn ensure_private_directory(path: &Path) -> Result<(), MobileError> {
    fs::create_dir_all(path).map_err(|_| MobileError::AttachmentOperationFailed)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| MobileError::AttachmentOperationFailed)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(MobileError::AttachmentOperationFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, permissions)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
    }
    Ok(())
}

fn valid_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn attachment_import_path(database_path: &str, source_id: &str) -> Result<PathBuf, MobileError> {
    if !valid_lower_hex(source_id, 32) {
        return Err(MobileError::AttachmentOperationFailed);
    }
    Ok(attachment_subdirectory(database_path, "imports")?.join(format!("{source_id}.import")))
}

fn open_attachment_import(database_path: &str, source_id: &str) -> Result<File, MobileError> {
    let path = attachment_import_path(database_path, source_id)?;
    let before = fs::symlink_metadata(&path).map_err(|_| MobileError::AttachmentOperationFailed)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() > MAX_MOBILE_ATTACHMENT_BYTES
    {
        return Err(MobileError::AttachmentOperationFailed);
    }
    let file = File::open(path).map_err(|_| MobileError::AttachmentOperationFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    if !metadata.is_file()
        || metadata.len() != before.len()
        || metadata.len() > MAX_MOBILE_ATTACHMENT_BYTES
    {
        return Err(MobileError::AttachmentOperationFailed);
    }
    Ok(file)
}

fn attachment_staging_limits(retention: Duration) -> Result<AttachmentStagingLimits, MobileError> {
    AttachmentStagingLimits::new(
        MAX_MOBILE_ATTACHMENT_BYTES,
        MAX_MOBILE_ATTACHMENT_STAGING_BYTES,
        64,
        retention,
    )
    .map_err(|_| MobileError::AttachmentOperationFailed)
}

fn sender_attachment_store(database_path: &str) -> Result<AttachmentStagingStore, MobileError> {
    let directory = attachment_subdirectory(database_path, "senders")?;
    AttachmentStagingStore::new(
        directory,
        attachment_staging_limits(Duration::from_hours(168))?,
    )
    .map_err(|_| MobileError::AttachmentOperationFailed)
}

fn receive_attachment_store(database_path: &str) -> Result<AttachmentStagingStore, MobileError> {
    let directory = attachment_subdirectory(database_path, "receives")?;
    AttachmentStagingStore::new(
        directory,
        attachment_staging_limits(Duration::from_hours(720))?,
    )
    .map_err(|_| MobileError::AttachmentOperationFailed)
}

fn persist_sender_source(
    database_path: &str,
    manifest: &AttachmentManifest,
    event_id: [u8; 32],
    source: &mut File,
) -> Result<(), MobileError> {
    let store = sender_attachment_store(database_path)?;
    let staged_file = store
        .open(manifest, &event_id)
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let mut receiver =
        StreamedAttachmentReceiver::new(manifest.clone(), MAX_MOBILE_ATTACHMENT_BYTES, staged_file)
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
    receiver
        .accept()
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let missing_ranges = receiver
        .missing_ranges()
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let mut chunk = Vec::new();
    chunk
        .try_reserve_exact(CHUNK_SIZE)
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    chunk.resize(CHUNK_SIZE, 0);
    for range in missing_ranges {
        for index in range.start..range.end_exclusive {
            let offset = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(CHUNK_SIZE as u64))
                .ok_or(MobileError::AttachmentOperationFailed)?;
            let chunk_length = manifest
                .file_size
                .checked_sub(offset)
                .map(|remaining| remaining.min(CHUNK_SIZE as u64))
                .and_then(|length| usize::try_from(length).ok())
                .ok_or(MobileError::AttachmentOperationFailed)?;
            manifest
                .read_verified_chunk_into(source, index, &mut chunk[..chunk_length])
                .map_err(|_| MobileError::AttachmentOperationFailed)?;
            receiver
                .submit_chunk(index, &chunk[..chunk_length])
                .map_err(|_| MobileError::AttachmentOperationFailed)?;
        }
    }
    if !receiver.is_complete() {
        return Err(MobileError::AttachmentOperationFailed);
    }
    receiver
        .copy_verified_to(&mut io::sink())
        .map_err(|_| MobileError::AttachmentOperationFailed)
}

fn transfer_record_path(
    database_path: &str,
    store_name: &str,
    transfer_id: [u8; 32],
    suffix: &str,
) -> Result<PathBuf, MobileError> {
    let directory = attachment_subdirectory(database_path, store_name)?;
    let key = lower_hex(&transfer_id);
    Ok(directory.join(format!("{key}.{suffix}")))
}

fn staged_transfer_exists(
    database_path: &str,
    store_name: &str,
    transfer_id: [u8; 32],
) -> Result<bool, MobileError> {
    let data = transfer_record_path(database_path, store_name, transfer_id, "part")?;
    let reservation = transfer_record_path(database_path, store_name, transfer_id, "reserve")?;
    let data_metadata = match fs::symlink_metadata(data) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(MobileError::AttachmentOperationFailed),
    };
    let reservation_metadata = match fs::symlink_metadata(reservation) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(MobileError::AttachmentOperationFailed),
    };
    if !data_metadata.is_file()
        || data_metadata.file_type().is_symlink()
        || !reservation_metadata.is_file()
        || reservation_metadata.file_type().is_symlink()
        || reservation_metadata.len() != 16
    {
        return Err(MobileError::AttachmentOperationFailed);
    }
    Ok(true)
}

fn ensure_staged_transfer_exists(
    database_path: &str,
    store_name: &str,
    transfer_id: [u8; 32],
) -> Result<(), MobileError> {
    if staged_transfer_exists(database_path, store_name, transfer_id)? {
        Ok(())
    } else {
        Err(MobileError::AttachmentOperationFailed)
    }
}

fn open_verified_sender_source(
    database_path: &str,
    manifest: &AttachmentManifest,
    event_id: [u8; 32],
) -> Result<lattice_files::ManagedAttachmentFile, MobileError> {
    let transfer_id = manifest
        .transfer_id(&event_id)
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    ensure_staged_transfer_exists(database_path, "senders", transfer_id.0)?;
    let store = sender_attachment_store(database_path)?;
    let mut source = store
        .open(manifest, &event_id)
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    let observed = AttachmentManifest::from_reader(
        &mut source,
        &manifest.filename,
        manifest.mime_type.as_deref(),
    )
    .map_err(|_| MobileError::AttachmentOperationFailed)?;
    if observed != *manifest {
        return Err(MobileError::AttachmentManifestSourceChanged);
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    Ok(source)
}

fn attachment_export_path(database_path: &str, export_id: &str) -> Result<PathBuf, MobileError> {
    if !valid_lower_hex(export_id, 64) {
        return Err(MobileError::AttachmentOperationFailed);
    }
    Ok(attachment_subdirectory(database_path, "exports")?.join(format!("{export_id}.export")))
}

fn create_private_export_file(
    path: &Path,
    manifest: &AttachmentManifest,
) -> Result<(File, bool), MobileError> {
    let directory = path
        .parent()
        .ok_or(MobileError::AttachmentOperationFailed)?;
    let file_name = path
        .file_name()
        .ok_or(MobileError::AttachmentOperationFailed)?;
    for entry in fs::read_dir(directory).map_err(|_| MobileError::AttachmentOperationFailed)? {
        let entry = entry.map_err(|_| MobileError::AttachmentOperationFailed)?;
        if entry.file_name() == file_name {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !entry.file_name().to_string_lossy().ends_with(".export")
        {
            return Err(MobileError::AttachmentOperationFailed);
        }
        if metadata
            .modified()
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age >= Duration::from_hours(24))
        {
            fs::remove_file(entry.path()).map_err(|_| MobileError::AttachmentOperationFailed)?;
        } else {
            return Err(MobileError::AttachmentOperationFailed);
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(MobileError::AttachmentOperationFailed);
            }
            let mut existing =
                File::open(path).map_err(|_| MobileError::AttachmentOperationFailed)?;
            let existing_manifest = AttachmentManifest::from_reader(
                &mut existing,
                &manifest.filename,
                manifest.mime_type.as_deref(),
            )
            .map_err(|_| MobileError::AttachmentOperationFailed)?;
            if existing_manifest == *manifest {
                return Ok((existing, true));
            }
            fs::remove_file(path).map_err(|_| MobileError::AttachmentOperationFailed)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(MobileError::AttachmentOperationFailed),
    }
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let output = options
        .open(path)
        .map_err(|_| MobileError::AttachmentOperationFailed)?;
    Ok((output, false))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn mobile_direct_message_packet(
    packet: lattice_core::DirectMessagePacket,
) -> MobileDirectMessagePacket {
    MobileDirectMessagePacket {
        packet_id: packet.packet_id.to_vec(),
        group_reference: packet.group_reference.to_vec(),
        envelope_bytes: packet.envelope_bytes,
    }
}

fn mobile_direct_message_outbox_entry(
    entry: lattice_core::DirectMessageOutboxEntry,
) -> MobileDirectMessageOutboxEntry {
    MobileDirectMessageOutboxEntry {
        packet_id: entry.packet_id.to_vec(),
        group_reference: entry.group_reference.to_vec(),
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

fn unix_millis_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

const fn direct_message_ingress_label(state: DirectMessageIngressState) -> &'static str {
    match state {
        DirectMessageIngressState::Accepted => "accepted",
        DirectMessageIngressState::InvitationPending => "invitation_pending_user_consent",
        DirectMessageIngressState::Duplicate => "duplicate",
    }
}
