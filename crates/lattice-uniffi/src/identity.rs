use lattice_identity::PinnedIdentity;

/// A durable local match between a public bundle and its full fingerprint.
///
/// This record does not attest human comparison, authenticate a session, or
/// authorize MLS membership.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobilePinnedIdentity {
    /// Exact versioned public identity bundle.
    pub public_bundle: Vec<u8>,
    /// Full fingerprint of the exact bundle bytes.
    pub fingerprint: Vec<u8>,
}

impl From<PinnedIdentity> for MobilePinnedIdentity {
    fn from(pinned: PinnedIdentity) -> Self {
        Self {
            public_bundle: pinned.bundle().to_bytes().to_vec(),
            fingerprint: pinned.fingerprint().to_vec(),
        }
    }
}
