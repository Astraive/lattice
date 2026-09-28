//! UniFFI-owned mobile boundary for the local Rust profile.

use lattice_core::{DeviceIdentityInfo as CoreIdentityInfo, SpaceGenesisCursor};
use thiserror::Error;

mod ble_exp0;
mod identity;
mod mobile_client;
pub use ble_exp0::{MobileBlePeerInfo, MobileBleRole, MobileBleSession};
pub use identity::MobilePinnedIdentity;
pub use mobile_client::{MobileClient, MobileProjectionSubscription};

uniffi::setup_scaffolding!();

/// OS keystore bridge. Implementations must wrap bytes with a non-exportable,
/// profile-bound platform key and must fail closed when that key is unavailable.
#[derive(Debug, Error, uniffi::Error)]
pub enum ProtectorError {
    /// The native keystore denied access or could not protect the bytes.
    #[error("platform key protection failed")]
    Failure,
}

#[uniffi::export(with_foreign)]
pub trait PlatformKeyProtector: Send + Sync {
    /// Wraps private material for the exact profile identifier.
    ///
    /// # Errors
    ///
    /// Returns `ProtectorError` when the native keystore refuses protection.
    fn wrap(&self, profile_id: String, clear_material: Vec<u8>) -> Result<Vec<u8>, ProtectorError>;

    /// Unwraps ciphertext only for the exact profile identifier.
    ///
    /// # Errors
    ///
    /// Returns `ProtectorError` when the native keystore refuses or cannot
    /// authenticate the ciphertext.
    fn unwrap(&self, profile_id: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, ProtectorError>;
}

/// Public, non-secret identity snapshot for native UI presentation.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileIdentityInfo {
    /// Versioned public identity bundle.
    pub public_bundle: Vec<u8>,
    /// Domain-separated fingerprint of the exact public bundle.
    pub fingerprint: Vec<u8>,
}

impl From<CoreIdentityInfo> for MobileIdentityInfo {
    fn from(info: CoreIdentityInfo) -> Self {
        Self {
            public_bundle: info.public_bundle.to_vec(),
            fingerprint: info.fingerprint.to_vec(),
        }
    }
}

/// Stable cursor for paginating locally recoverable Space generations.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSpaceCursor {
    /// Space identifier bytes.
    pub space_id: Vec<u8>,
    /// MLS group reference bytes.
    pub group_reference: Vec<u8>,
}

impl TryFrom<MobileSpaceCursor> for SpaceGenesisCursor {
    type Error = MobileError;

    fn try_from(cursor: MobileSpaceCursor) -> Result<Self, Self::Error> {
        Ok(Self {
            space_id: cursor
                .space_id
                .as_slice()
                .try_into()
                .map_err(|_| MobileError::InvalidSpaceCursor)?,
            group_reference: cursor
                .group_reference
                .as_slice()
                .try_into()
                .map_err(|_| MobileError::InvalidSpaceCursor)?,
        })
    }
}

impl From<SpaceGenesisCursor> for MobileSpaceCursor {
    fn from(cursor: SpaceGenesisCursor) -> Self {
        Self {
            space_id: cursor.space_id.to_vec(),
            group_reference: cursor.group_reference.to_vec(),
        }
    }
}

/// Non-secret identifier summary for one locally restored Space generation.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSpaceSummary {
    /// Space identifier bytes.
    pub space_id: Vec<u8>,
    /// MLS group reference bytes.
    pub group_reference: Vec<u8>,
    /// Channels in the locally restored Genesis policy.
    pub channels: Vec<MobileChannelSummary>,
}
/// Supported candidate channel types for local Space creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileChannelType {
    Text,
    Announcement,
    Voice,
}

/// Non-secret projection of one channel in the local Genesis policy.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileChannelSummary {
    /// Random channel identifier bytes.
    pub id: Vec<u8>,
    /// Display name.
    pub name: String,
    /// Channel type.
    pub channel_type: MobileChannelType,
    /// Whether the channel was archived in Genesis.
    pub archived: bool,
}

/// Result of committing a text event to the local durable outbox.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileQueuedMessage {
    /// Immutable identifier of the committed event.
    pub event_id: Vec<u8>,
}
/// Durable local outbox state. Only a verified destination receipt may be `Delivered`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileOutboxState {
    Queued,
    Forwarding,
    Forwarded,
    PeerIngressAccepted,
    Delivered,
    Failed,
}

/// Exact persisted envelope and retry metadata for native transport owners.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileOutboxEntry {
    /// Immutable signed-event identifier.
    pub event_id: Vec<u8>,
    /// Opaque envelope bytes; transport code must not reinterpret them.
    pub envelope_bytes: Vec<u8>,
    /// Persisted retry schedule in Unix milliseconds.
    pub next_attempt_ms: i64,
    /// Number of recorded forwarding attempts.
    pub attempt_count: u32,
    /// Local outbox state; this is not proof of destination receipt.
    pub state: MobileOutboxState,
}
/// Outcome class from Core's authenticated sync-event acceptance path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileSyncEventState {
    Accepted,
    Duplicate,
    Pending,
    CheckpointExcluded,
}

/// Result of handing one signed application event to Rust Core.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSyncEventResult {
    pub event_id: Vec<u8>,
    pub state: MobileSyncEventState,
    pub missing_dependencies: Vec<Vec<u8>>,
}

/// Coalesced reason that a local Core projection may need refreshing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileProjectionChange {
    Spaces,
    Messages,
    All,
    SyncedEvents,
}
/// One locally retained authorized message from bounded history or search.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileLocalTextMessage {
    /// Immutable signed message event identifier.
    pub event_id: Vec<u8>,
    /// Stable author fingerprint.
    pub author_id: Vec<u8>,
    /// Author sequence for detecting local gaps.
    pub author_sequence: u64,
    /// Causal Lamport value.
    pub lamport: u64,
    /// Decrypted text retained by the local encrypted cache.
    pub content: String,
    /// Local outbox state, when the envelope remains queued.
    pub outbox_state: Option<String>,
}

/// Bounded offline search result over locally retained message history.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileLocalTextMessageSearch {
    /// Up to 100 newest matching messages in chronological order.
    pub messages: Vec<MobileLocalTextMessage>,
    /// Exact number of matches in the local channel cache.
    pub total_matches: u64,
    /// Number of local messages scanned.
    pub scanned_messages: u64,
}

/// Bounded caller-selected policy inputs for one initial channel.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileInitialChannel {
    /// Candidate channel type.
    pub channel_type: MobileChannelType,
    /// Display-only channel name, limited to 128 UTF-8 bytes.
    pub name: String,
    /// Initial channel-level permission allow mask.
    pub default_allow: u64,
    /// Initial channel-level permission deny mask.
    pub default_deny: u64,
}
/// Non-secret identifiers returned after a local Space transaction commits.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileCreatedSpace {
    /// Randomly generated Space identifier.
    pub space_id: Vec<u8>,
    /// Event-visible MLS group reference.
    pub group_reference: Vec<u8>,
    /// Identifier of the committed signed Genesis event.
    pub genesis_event_id: Vec<u8>,
    /// Initial channels committed in Genesis.
    pub channels: Vec<MobileChannelSummary>,
}

/// Bounded page of locally verified Space Genesis snapshots.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSpacePage {
    /// Restored generations in this page.
    pub spaces: Vec<MobileSpaceSummary>,
    /// Exclusive cursor to request the next page.
    pub next_cursor: Option<MobileSpaceCursor>,
}

/// Stable mobile-safe failures that do not disclose key material or SQL details.
#[derive(Debug, Error, uniffi::Error)]
pub enum MobileError {
    /// Profile identifiers must be 1–128 printable ASCII characters.
    #[error("invalid profile identifier")]
    InvalidProfileId,
    /// The local profile could not be opened with its OS-protected keys.
    #[error("profile could not be opened")]
    ProfileOpenFailed,
    /// The native key protector failed or denied access.
    #[error("platform key protection failed")]
    KeyProtectionFailed,
    /// The profile lock was poisoned by a prior Rust panic.
    #[error("profile is unavailable")]
    ProfileUnavailable,
    /// The protected device key could not create a certificate signing request.
    #[error("device certificate signing request could not be generated")]
    CertificateSigningRequestFailed,
    /// The caller supplied a Space cursor with an invalid identifier length.
    #[error("invalid Space page cursor")]
    InvalidSpaceCursor,
    /// The public identity bundle is malformed or uses unsupported keys.
    #[error("invalid identity bundle")]
    InvalidIdentityBundle,
    /// The caller supplied a fingerprint with a length other than 32 bytes.
    #[error("invalid identity fingerprint length")]
    InvalidFingerprint,
    /// The supplied full fingerprint does not match the exact bundle.
    #[error("identity fingerprint does not match the bundle")]
    FingerprintMismatch,
    /// A previously stored fingerprint is mapped to different bundle bytes.
    #[error("identity fingerprint is already pinned to another bundle")]
    PinnedIdentityConflict,
    /// The supplied RFC 9420 X.509 credential is malformed, untrusted, or mismatched.
    #[error("invalid Space X.509 credential")]
    InvalidSpaceCredential,
    /// Initial channel inputs exceed bounds or violate Space policy.
    #[error("invalid Space creation inputs")]
    InvalidSpaceInput,
    /// The local Space transaction could not be committed.
    #[error("Space creation failed")]
    SpaceCreationFailed,
    /// A local Space generation could not be restored or recovered.
    #[error("local Space recovery generation failed")]
    SpaceRecoveryFailed,
    /// Bootstrap package bytes are empty, oversized, or invalid.
    #[error("invalid Space Welcome bootstrap package")]
    InvalidSpaceBootstrap,
    /// The Welcome inviter's complete identity bundle is not pinned.
    #[error("Space Welcome inviter is not trusted")]
    UntrustedSpaceInviter,
    /// A validated Welcome could not be imported into the local profile.
    #[error("Space Welcome join failed")]
    SpaceJoinFailed,
    /// The bounded Core projection observer limit has been reached.
    #[error("too many Core projection observers")]
    ProjectionObserverLimit,
    /// The Core projection observer wait duration is outside its supported range.
    #[error("invalid Core projection observer wait duration")]
    InvalidProjectionWait,
    /// The Core projection observer synchronization state is unavailable.
    #[error("Core projection observer is unavailable")]
    ProjectionObserverUnavailable,

    /// A supplied Space, group, or channel identifier has the wrong byte length.
    #[error("invalid Space message identifier")]
    InvalidSpaceMessageId,
    /// Text exceeds the bounded Space application payload size.
    #[error("invalid text message size")]
    InvalidMessageInput,
    /// The local message-search query is empty or exceeds its byte limit.
    #[error("invalid local message search query")]
    InvalidMessageSearch,
    /// The valid message was not authorized by the locally restored policy.
    #[error("local message rejected by Space policy")]
    MessageRejected,
    /// A local message could not be committed to the durable outbox.
    #[error("local message queue failed")]
    MessageQueueFailed,
    /// Local encrypted message history could not be authenticated or restored.
    #[error("local message history is unavailable")]
    MessageHistoryUnavailable,
    /// Invalid signed-event identifier supplied for an outbox transition.
    #[error("invalid durable outbox event identifier")]
    InvalidOutboxEventId,
    /// Negative retry timestamp supplied for a forwarding attempt.
    #[error("invalid durable outbox retry schedule")]
    InvalidOutboxSchedule,
    /// An outbox state transition could not be applied.
    #[error("durable outbox transition was rejected")]
    OutboxTransitionRejected,
    /// Invalid event-ID cursor supplied to the bounded outbox page API.
    #[error("invalid durable outbox cursor")]
    InvalidOutboxCursor,
    /// Requested outbox page size is outside the supported bound.
    #[error("invalid durable outbox page size")]
    InvalidOutboxPage,
    /// The durable outbox could not be read.
    #[error("durable outbox is unavailable")]
    OutboxUnavailable,
    /// Signed event failed verification, MLS binding, local policy, or storage.
    #[error("authenticated sync event could not be ingested")]
    SyncIngestFailed,
    /// The advertised exp0 token has an invalid width.
    #[error("invalid BLE discovery token")]
    InvalidBleDiscoveryToken,
    /// The authenticated exp0 session could not advance safely.
    #[error("BLE session failed")]
    BleSessionFailed,
    /// An exp0 control or identity record failed its exact encoding or signature.
    #[error("BLE record rejected")]
    BleRecordRejected,
    /// The remote identity has not been explicitly pinned on this device.
    #[error("BLE peer identity is not pinned")]
    BlePeerNotPinned,
    /// The remote identity differs from this device's existing pin.
    #[error("BLE peer identity does not match its pin")]
    BlePeerIdentityMismatch,
    /// Application records are forbidden before transcript confirmation.
    #[error("BLE peer is not authenticated")]
    BlePeerNotAuthenticated,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{MobileBleRole, MobileBleSession, MobileClient, MobileError, PlatformKeyProtector};

    #[derive(Default)]
    struct TestProtector {
        key: Mutex<Option<[u8; 32]>>,
    }

    impl PlatformKeyProtector for TestProtector {
        fn wrap(
            &self,
            _profile_id: String,
            clear_material: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            let mut key = self
                .key
                .lock()
                .map_err(|_| super::ProtectorError::Failure)?;
            let key = key.get_or_insert([0xD3; 32]);
            let mut output = Vec::with_capacity(clear_material.len());
            output.extend(
                clear_material
                    .iter()
                    .zip(key.iter().cycle())
                    .map(|(byte, mask)| *byte ^ *mask),
            );
            Ok(output)
        }

        fn unwrap(
            &self,
            profile_id: String,
            ciphertext: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            self.wrap(profile_id, ciphertext)
        }
    }

    struct DenyProtector;

    impl PlatformKeyProtector for DenyProtector {
        fn wrap(
            &self,
            _profile_id: String,
            _clear_material: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            Err(super::ProtectorError::Failure)
        }

        fn unwrap(
            &self,
            _profile_id: String,
            _ciphertext: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            Err(super::ProtectorError::Failure)
        }
    }

    #[test]
    fn reports_keystore_denial_without_software_fallback() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let result = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-test-profile".to_owned(),
            std::sync::Arc::new(DenyProtector),
        );
        assert!(matches!(result, Err(MobileError::KeyProtectionFailed)));
    }

    #[test]
    fn opens_and_reopens_profile_with_same_platform_identity() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let database_path = directory
            .path()
            .join("profile.sqlite")
            .to_string_lossy()
            .into_owned();
        let protector = std::sync::Arc::new(TestProtector::default());
        let client = MobileClient::open_or_create(
            database_path.clone(),
            "android-test-profile".to_owned(),
            protector.clone(),
        )
        .expect("open local profile");

        let identity = client.identity_info().expect("public identity");
        assert_eq!(identity.public_bundle.len(), 65);
        assert_eq!(identity.fingerprint.len(), 32);
        assert_eq!(client.next_author_sequence().expect("first sequence"), 1);
        drop(client);

        let reopened = MobileClient::open_or_create(
            database_path,
            "android-test-profile".to_owned(),
            protector,
        )
        .expect("reopen local profile");
        assert_eq!(
            reopened.identity_info().expect("restored identity"),
            identity
        );
    }

    #[test]
    fn recovery_api_rejects_malformed_ids_and_unusable_credentials() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let client = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-recovery-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert!(matches!(
            client.recover_local_space_generation(vec![0; 15], vec![0; 32], vec![1]),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.recover_local_space_generation(vec![0; 16], vec![0; 31], vec![1]),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.recover_local_space_generation(vec![0; 16], vec![0; 32], Vec::new()),
            Err(MobileError::InvalidSpaceCredential)
        ));
    }

    #[test]
    fn welcome_join_rejects_invalid_input_bounds() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let client = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-welcome-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert!(matches!(
            client.join_space_from_welcome_bootstrap(Vec::new(), vec![0; 32], vec![1]),
            Err(MobileError::InvalidSpaceBootstrap)
        ));
        assert!(matches!(
            client.join_space_from_welcome_bootstrap(
                vec![0; lattice_core::MAX_SPACE_WELCOME_BOOTSTRAP_BYTES + 1],
                vec![0; 32],
                vec![1],
            ),
            Err(MobileError::InvalidSpaceBootstrap)
        ));
        assert!(matches!(
            client.join_space_from_welcome_bootstrap(vec![0], vec![0; 31], vec![1]),
            Err(MobileError::InvalidFingerprint)
        ));
        assert!(matches!(
            client.join_space_from_welcome_bootstrap(vec![0], vec![0; 32], Vec::new()),
            Err(MobileError::InvalidSpaceCredential)
        ));
    }

    #[test]
    fn stores_only_exactly_fingerprinted_identity_pins() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let database_path = directory
            .path()
            .join("profile.sqlite")
            .to_string_lossy()
            .into_owned();
        let client = MobileClient::open_or_create(
            database_path,
            "android-pin-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");
        let identity = client.identity_info().expect("local identity");

        assert!(matches!(
            client.pin_identity(identity.public_bundle.clone(), vec![0; 31]),
            Err(MobileError::InvalidFingerprint)
        ));
        let mut wrong_fingerprint = identity.fingerprint.clone();
        wrong_fingerprint[0] ^= 1;
        assert!(matches!(
            client.pin_identity(identity.public_bundle.clone(), wrong_fingerprint),
            Err(MobileError::FingerprintMismatch)
        ));
        assert!(matches!(
            client.pin_identity(vec![0; 64], identity.fingerprint.clone()),
            Err(MobileError::InvalidIdentityBundle)
        ));
        let mut non_contributory_bundle = identity.public_bundle.clone();
        non_contributory_bundle[33..].fill(0);
        assert!(matches!(
            client.pin_identity(non_contributory_bundle, identity.fingerprint.clone()),
            Err(MobileError::InvalidIdentityBundle)
        ));
        assert_eq!(
            client
                .pinned_identity(identity.fingerprint.clone())
                .expect("query absent pin"),
            None
        );
        assert!(matches!(
            client.pinned_identity(vec![0; 31]),
            Err(MobileError::InvalidFingerprint)
        ));

        let pinned = client
            .pin_identity(identity.public_bundle.clone(), identity.fingerprint.clone())
            .expect("pin exact identity bundle");
        assert_eq!(pinned.public_bundle, identity.public_bundle);
        assert_eq!(pinned.fingerprint, identity.fingerprint);
        assert_eq!(
            client
                .pinned_identity(identity.fingerprint.clone())
                .expect("load exact pin"),
            Some(pinned)
        );
        assert!(
            client
                .unpin_identity(identity.fingerprint.clone())
                .expect("remove exact local pin")
        );
        assert_eq!(
            client
                .pinned_identity(identity.fingerprint.clone())
                .expect("query removed pin"),
            None
        );
        assert!(
            !client
                .unpin_identity(identity.fingerprint.clone())
                .expect("repeat local removal")
        );
        assert!(matches!(
            client.unpin_identity(vec![0; 31]),
            Err(MobileError::InvalidFingerprint)
        ));
    }

    #[test]
    fn lists_empty_local_space_pages_and_rejects_malformed_cursor() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let database_path = directory
            .path()
            .join("profile.sqlite")
            .to_string_lossy()
            .into_owned();
        let client = MobileClient::open_or_create(
            database_path,
            "android-test-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert_eq!(
            client
                .list_local_spaces(None)
                .expect("list empty local page"),
            super::MobileSpacePage {
                spaces: Vec::new(),
                next_cursor: None,
            }
        );
        assert!(matches!(
            client.list_local_spaces(Some(super::MobileSpaceCursor {
                space_id: vec![0; 15],
                group_reference: vec![0; 32],
            })),
            Err(MobileError::InvalidSpaceCursor)
        ));
    }

    #[test]
    fn lists_bounded_opaque_outbox_pages_and_rejects_invalid_inputs() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let client = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-outbox-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert!(
            client
                .outbox_page(None, 16)
                .expect("read empty outbox")
                .is_empty()
        );
        assert!(matches!(
            client.outbox_page(Some(vec![0; 31]), 16),
            Err(MobileError::InvalidOutboxCursor)
        ));
        let invalid_large_limit = i32::try_from(lattice_core::MAX_OUTBOX_PAGE_SIZE)
            .expect("outbox page limit fits in i32")
            .checked_add(1)
            .expect("invalid outbox page limit fits in i32");
        for limit in [0, -1, invalid_large_limit] {
            assert!(matches!(
                client.outbox_page(None, limit),
                Err(MobileError::InvalidOutboxPage)
            ));
        }
        assert!(matches!(
            client.mark_outbox_attempt(vec![0; 31], 0),
            Err(MobileError::InvalidOutboxEventId)
        ));
        assert!(matches!(
            client.mark_outbox_attempt(vec![0; 32], -1),
            Err(MobileError::InvalidOutboxSchedule)
        ));
        assert!(matches!(
            client.record_peer_ingress_accepted(vec![0; 31]),
            Err(MobileError::InvalidOutboxEventId)
        ));
        assert!(matches!(
            client.record_peer_ingress_accepted(vec![0; 32]),
            Err(MobileError::OutboxTransitionRejected)
        ));
    }

    #[test]
    fn queue_local_message_rejects_malformed_ids_credentials_and_empty_history() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let client = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-queue-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert!(matches!(
            client.queue_local_text_message(
                vec![0; 15],
                vec![0; 32],
                vec![1],
                vec![0; 16],
                "hello".into()
            ),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.queue_local_text_message(
                vec![0; 16],
                vec![0; 31],
                vec![1],
                vec![0; 16],
                "hello".into()
            ),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.queue_local_text_message(
                vec![0; 16],
                vec![0; 32],
                vec![],
                vec![0; 16],
                "hello".into()
            ),
            Err(MobileError::InvalidSpaceCredential)
        ));
        assert!(matches!(
            client.queue_local_text_message(
                vec![0; 16],
                vec![0; 32],
                b"not an X.509 credential".to_vec(),
                vec![0; 16],
                "hello".into()
            ),
            Err(MobileError::InvalidSpaceCredential)
        ));
        assert!(matches!(
            client.queue_local_text_message(
                vec![0; 16],
                vec![0; 32],
                vec![1],
                vec![0; 15],
                "hello".into()
            ),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.list_local_text_messages(vec![0; 15], vec![0; 32], vec![0; 16]),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.list_local_text_messages(vec![0; 16], vec![0; 32], vec![0; 16]),
            Err(MobileError::MessageHistoryUnavailable)
        ));
        assert!(matches!(
            client.search_local_text_messages(
                vec![0; 15],
                vec![0; 32],
                vec![0; 16],
                "needle".to_owned(),
            ),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client
                .search_local_text_messages(vec![0; 16], vec![0; 32], vec![0; 16], String::new(),),
            Err(MobileError::InvalidMessageSearch)
        ));
        assert!(matches!(
            client.search_local_text_messages(
                vec![0; 16],
                vec![0; 32],
                vec![0; 16],
                "x".repeat(lattice_core::MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES + 1),
            ),
            Err(MobileError::InvalidMessageSearch)
        ));
    }

    #[test]
    fn queue_and_edit_local_message_reject_oversized_payloads() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let client = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-queue-size-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert!(matches!(
            client.queue_local_text_message(
                vec![0; 16],
                vec![0; 32],
                vec![1],
                vec![0; 16],
                "x".repeat(lattice_core::space::MAX_SPACE_PAYLOAD_BYTES + 1),
            ),
            Err(MobileError::InvalidMessageInput)
        ));
        assert!(matches!(
            client.queue_local_text_message_edit(
                vec![0; 16],
                vec![0; 32],
                vec![1],
                vec![0; 16],
                vec![0; 31],
                "edit".into()
            ),
            Err(MobileError::InvalidSpaceMessageId)
        ));
        assert!(matches!(
            client.queue_local_text_message_edit(
                vec![0; 16],
                vec![0; 32],
                vec![1],
                vec![0; 16],
                vec![0; 32],
                "x".repeat(lattice_core::space::MAX_SPACE_PAYLOAD_BYTES + 1),
            ),
            Err(MobileError::InvalidMessageInput)
        ));
    }

    #[test]
    fn rejects_untrusted_space_credential_without_creating_a_local_space() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let database_path = directory
            .path()
            .join("profile.sqlite")
            .to_string_lossy()
            .into_owned();
        let client = MobileClient::open_or_create(
            database_path,
            "android-space-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert!(matches!(
            client.create_local_space(
                b"test-only untrusted X.509 placeholder".to_vec(),
                vec![super::MobileInitialChannel {
                    channel_type: super::MobileChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                }],
            ),
            Err(MobileError::InvalidSpaceCredential)
        ));
        assert!(
            client
                .list_local_spaces(None)
                .expect("list local spaces")
                .spaces
                .is_empty()
        );
    }

    #[test]
    fn ble_sessions_authenticate_pinned_peers_before_application_records() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let protector = std::sync::Arc::new(TestProtector::default());
        let initiator = MobileClient::open_or_create(
            directory
                .path()
                .join("initiator.sqlite")
                .to_string_lossy()
                .into_owned(),
            "ble-initiator".to_owned(),
            protector.clone(),
        )
        .expect("open initiator");
        let responder = MobileClient::open_or_create(
            directory
                .path()
                .join("responder.sqlite")
                .to_string_lossy()
                .into_owned(),
            "ble-responder".to_owned(),
            protector,
        )
        .expect("open responder");
        let token = vec![0x5a; 9];
        let initiator_session =
            MobileBleSession::new(initiator.clone(), MobileBleRole::Initiator, token.clone())
                .expect("create initiator session");
        let responder_session =
            MobileBleSession::new(responder.clone(), MobileBleRole::Responder, token.clone())
                .expect("create responder session");
        let rejected_session =
            MobileBleSession::new(responder.clone(), MobileBleRole::Responder, token.clone())
                .expect("create rejected-token test session");
        assert!(matches!(
            rejected_session.validate_active_responder_token(vec![0x5b; 9]),
            Err(MobileError::BleRecordRejected)
        ));
        assert!(
            !rejected_session
                .is_authenticated()
                .expect("rejected session closed")
        );

        let (initiator_peer, responder_peer) =
            exchange_ble_identity_proofs(&initiator_session, &responder_session, &token);
        assert_eq!(initiator_peer.safety_number, responder_peer.safety_number);
        assert!(!initiator_peer.already_pinned);
        assert!(!responder_peer.already_pinned);
        assert!(matches!(
            initiator_session.encrypt_record(b"before pin".to_vec()),
            Err(MobileError::BlePeerNotAuthenticated)
        ));
        assert!(matches!(
            initiator_session.write_confirmation(),
            Err(MobileError::BlePeerNotPinned)
        ));

        initiator
            .pin_identity(responder_peer.identity_bundle, responder_peer.fingerprint)
            .expect("pin responder identity");
        responder
            .pin_identity(initiator_peer.identity_bundle, initiator_peer.fingerprint)
            .expect("pin initiator identity");
        confirm_ble_peers(&initiator_session, &responder_session);

        let application_record = b"opaque lattice envelope";
        let ciphertext = initiator_session
            .encrypt_record(application_record.to_vec())
            .expect("encrypt authenticated envelope");
        assert_eq!(
            responder_session
                .decrypt_record(ciphertext)
                .expect("decrypt authenticated envelope"),
            application_record
        );
        let response = responder_session
            .encrypt_record(b"reply".to_vec())
            .expect("encrypt response envelope");
        assert_eq!(
            initiator_session
                .decrypt_record(response)
                .expect("decrypt response envelope"),
            b"reply"
        );
    }
    fn confirm_ble_peers(initiator: &MobileBleSession, responder: &MobileBleSession) {
        let initiator_confirmation = initiator
            .write_confirmation()
            .expect("write initiator confirmation");
        responder
            .read_confirmation(initiator_confirmation)
            .expect("verify initiator confirmation");
        let responder_confirmation = responder
            .write_confirmation()
            .expect("write responder confirmation");
        responder
            .confirmation_write_succeeded()
            .expect("GATT accepted responder confirmation");
        initiator
            .read_confirmation(responder_confirmation)
            .expect("verify responder confirmation");
        assert!(initiator.is_authenticated().expect("initiator auth"));
        assert!(responder.is_authenticated().expect("responder auth"));
    }
    fn exchange_ble_identity_proofs(
        initiator: &MobileBleSession,
        responder: &MobileBleSession,
        token: &[u8],
    ) -> (super::MobileBlePeerInfo, super::MobileBlePeerInfo) {
        let message_1 = initiator
            .write_handshake_message()
            .expect("write Noise message 1");
        responder
            .read_handshake_message(message_1)
            .expect("read Noise message 1");
        let message_2 = responder
            .write_handshake_message()
            .expect("write Noise message 2");
        initiator
            .read_handshake_message(message_2)
            .expect("read Noise message 2");
        let message_3 = initiator
            .write_handshake_message()
            .expect("write Noise message 3");
        responder
            .read_handshake_message(message_3)
            .expect("read Noise message 3");
        assert!(initiator.handshake_complete().expect("initiator complete"));
        assert!(responder.handshake_complete().expect("responder complete"));
        assert!(matches!(
            responder.read_identity_proof(vec![0]),
            Err(MobileError::BleRecordRejected)
        ));
        responder
            .validate_active_responder_token(token.to_vec())
            .expect("match currently advertised responder token");

        let initiator_peer = responder
            .read_identity_proof(
                initiator
                    .write_identity_proof()
                    .expect("write initiator proof"),
            )
            .expect("verify initiator proof");
        let responder_peer = initiator
            .read_identity_proof(
                responder
                    .write_identity_proof()
                    .expect("write responder proof"),
            )
            .expect("verify responder proof");
        (initiator_peer, responder_peer)
    }
    #[test]
    fn rejects_profile_identifier_before_calling_the_platform_protector() {
        let result = MobileClient::open_or_create(
            "unused.sqlite".to_owned(),
            "bad\nprofile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        );
        assert!(matches!(result, Err(MobileError::InvalidProfileId)));
    }
}
