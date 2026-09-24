use lattice_identity::{IdentityPublicBundle, PinnedIdentity};
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
}
