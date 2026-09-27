use std::future::Future;

use lattice_identity::{DeviceIdentity, IdentityPublicBundle, PinnedIdentity};
use lattice_storage::{StoreError, TrustedIdentityRecord};

use super::{Client, CoreError};

impl Client {
    /// Pins a peer bundle only when it matches a caller-supplied full fingerprint.
    ///
    /// The caller must obtain `expected_full_fingerprint` through out-of-band
    /// human verification or a session-bound comparison. This method validates
    /// exact bundle/fingerprint consistency and persists the pair without
    /// replacing a conflicting existing pin. It does not attest the comparison,
    /// authenticate a Noise session, validate an MLS credential, or grant
    /// membership.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Identity`] for malformed bytes or a fingerprint
    /// mismatch, [`CoreError::PinnedIdentityConflict`] for an existing pin
    /// mapped to another bundle, or [`CoreError::Storage`] for other failures.
    pub fn pin_identity(
        &mut self,
        public_bundle: &[u8],
        expected_full_fingerprint: [u8; 32],
    ) -> Result<PinnedIdentity, CoreError> {
        let bundle = IdentityPublicBundle::from_bytes(public_bundle)?;
        let pinned = PinnedIdentity::from_verified_fingerprint(bundle, expected_full_fingerprint)?;
        match self.store.save_trusted_identity(TrustedIdentityRecord {
            fingerprint: pinned.fingerprint(),
            public_bundle: pinned.bundle().to_bytes(),
        }) {
            Ok(()) => {}
            Err(StoreError::TrustedIdentityConflict) => {
                return Err(CoreError::PinnedIdentityConflict);
            }
            Err(error) => return Err(error.into()),
        }
        Ok(pinned)
    }

    /// Loads and revalidates one previously pinned identity bundle.
    ///
    /// Rechecking the fingerprint protects against malformed or externally
    /// modified database contents. A pin is not MLS membership authorization.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Identity`] for stored bundle/fingerprint mismatch
    /// or malformed bytes, and [`CoreError::Storage`] for database failures.
    pub fn pinned_identity(
        &self,
        fingerprint: &[u8; 32],
    ) -> Result<Option<PinnedIdentity>, CoreError> {
        let Some(record) = self.store.load_trusted_identity(fingerprint)? else {
            return Ok(None);
        };
        let bundle = IdentityPublicBundle::from_bytes(&record.public_bundle)?;
        let pinned = PinnedIdentity::from_verified_fingerprint(bundle, record.fingerprint)?;
        Ok(Some(pinned))
    }

    /// Removes one local peer pin, blocking future operations that require it.
    ///
    /// This revokes trust only in this profile. It does not revoke the remote
    /// identity, notify other devices, or remove MLS membership.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] if the pin cannot be removed.
    pub fn unpin_identity(&mut self, fingerprint: &[u8; 32]) -> Result<bool, CoreError> {
        Ok(self.store.remove_trusted_identity(fingerprint)?)
    }

    /// Runs an asynchronous operation with the local identity borrowed and an
    /// exact persisted peer pin loaded and revalidated first.
    ///
    /// The callback is not invoked when the fingerprint is not pinned. The
    /// local private-key bytes are never exported; the callback receives only
    /// a borrow of the live [`DeviceIdentity`] and the validated public pin.
    /// The pin proves only key possession after a protocol verifies it; callers
    /// remain responsible for scope and MLS authorization.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if loading or validating the persisted pin fails.
    pub async fn with_pinned_identity<'a, T, F, Fut>(
        &'a self,
        fingerprint: &[u8; 32],
        operation: F,
    ) -> Result<Option<T>, CoreError>
    where
        F: FnOnce(&'a DeviceIdentity, PinnedIdentity) -> Fut,
        Fut: Future<Output = T> + 'a,
    {
        let Some(pinned) = self.pinned_identity(fingerprint)? else {
            return Ok(None);
        };
        Ok(Some(operation(&self.identity, pinned).await))
    }
}
