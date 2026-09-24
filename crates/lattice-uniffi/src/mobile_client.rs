use std::sync::{Arc, Mutex, MutexGuard};

use lattice_core::{
    Client, CoreError, InitialChannel, MAX_SPACE_CREDENTIAL_BYTES, OutboxState, SpaceGenesisCursor,
    space::{Channel, ChannelType, MAX_SPACE_PAYLOAD_BYTES},
};
use lattice_identity::{IdentityError, PrivateKeyProtectionError, PrivateKeyProtector};

use super::{
    MobileChannelSummary, MobileChannelType, MobileCreatedSpace, MobileError, MobileIdentityInfo,
    MobileInitialChannel, MobileLocalTextMessage, MobilePinnedIdentity, MobileQueuedMessage,
    MobileSpaceCursor, MobileSpacePage, MobileSpaceSummary, PlatformKeyProtector,
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

/// Thread-safe handle to one durable local profile.
#[derive(uniffi::Object)]
pub struct MobileClient {
    client: Mutex<Client>,
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
        }))
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
        Ok(MobileCreatedSpace {
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
        })
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
    /// Returns the bounded recent, locally retained outgoing text history.
    ///
    /// This does not fetch incoming messages or messages outside the latest
    /// local page; returned outbox states never imply remote delivery.
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
        Ok(messages
            .into_iter()
            .map(|message| MobileLocalTextMessage {
                event_id: message.event_id.to_vec(),
                author_id: message.author_id.to_vec(),
                author_sequence: message.author_sequence,
                lamport: message.lamport,
                content: message.content,
                outbox_state: message.outbox_state.map(|state| {
                    match state {
                        OutboxState::Queued => "queued",
                        OutboxState::Forwarded => "forwarded",
                        OutboxState::Delivered => "delivered",
                        OutboxState::Failed => "failed",
                    }
                    .to_owned()
                }),
            })
            .collect())
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
        Ok(MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        })
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
        Ok(MobileQueuedMessage {
            event_id: queued.event_id().to_vec(),
        })
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

impl MobileClient {
    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, MobileError> {
        self.client
            .lock()
            .map_err(|_| MobileError::ProfileUnavailable)
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
