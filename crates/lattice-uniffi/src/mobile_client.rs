use std::sync::{Arc, Mutex, MutexGuard};

use lattice_core::{Client, CoreError, SpaceGenesisCursor};
use lattice_identity::{IdentityError, PrivateKeyProtectionError, PrivateKeyProtector};

use super::{
    MobileError, MobileIdentityInfo, MobilePinnedIdentity, MobileSpaceCursor, MobileSpacePage,
    MobileSpaceSummary, PlatformKeyProtector,
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
            })
            .collect();
        Ok(MobileSpacePage {
            spaces,
            next_cursor: page.next_cursor().map(Into::into),
        })
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
