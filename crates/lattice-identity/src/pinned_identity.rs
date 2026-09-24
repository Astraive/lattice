use super::{IdentityError, IdentityPublicBundle};

/// A public bundle whose exact full fingerprint matches a caller-supplied value.
///
/// The caller must obtain `expected_full_fingerprint` through out-of-band human
/// verification or a session-bound comparison (for example, QR or SAS). This
/// constructor only checks that the supplied fingerprint is consistent with
/// the bundle; it does not perform or attest that comparison, bind a Noise
/// session, validate certificates, or authorize membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedIdentity {
    bundle: IdentityPublicBundle,
    fingerprint: [u8; 32],
}

impl PinnedIdentity {
    /// Creates a match value only when the supplied full fingerprint equals the
    /// bundle's fingerprint over its exact 65-byte versioned encoding.
    ///
    /// `expected_full_fingerprint` must come from caller-performed out-of-band
    /// human verification or a session-bound comparison. This method checks
    /// consistency only and does not assert that such a comparison occurred.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::FingerprintMismatch`] if the fingerprints differ.
    pub fn from_verified_fingerprint(
        bundle: IdentityPublicBundle,
        expected_full_fingerprint: [u8; 32],
    ) -> Result<Self, IdentityError> {
        if bundle.fingerprint() != expected_full_fingerprint {
            return Err(IdentityError::FingerprintMismatch);
        }
        Ok(Self {
            bundle,
            fingerprint: expected_full_fingerprint,
        })
    }

    /// Returns the matched public identity bundle.
    #[must_use]
    pub const fn bundle(&self) -> IdentityPublicBundle {
        self.bundle
    }

    /// Returns the caller-supplied full fingerprint that matched the bundle.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
