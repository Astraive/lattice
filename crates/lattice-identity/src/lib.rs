//! Local Ed25519/X25519 device identity and public-key verification.
//!
//! Keychain/Keystore persistence and secure wrapping require a real OS provider
//! before production onboarding; the candidate public bundle is not frozen.
mod pinned_identity;

pub use pinned_identity::PinnedIdentity;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

const FINGERPRINT_DOMAIN: &[u8] = b"lattice:identity-bundle:v1\0";
const PUBLIC_BUNDLE_VERSION: u8 = 1;
const PUBLIC_BUNDLE_LEN: usize = 1 + 32 + 32;

const PROTECTED_MATERIAL_VERSION: u8 = 1;
const PROTECTED_MATERIAL_LEN: usize = 1 + 32 + 32 + 32 + 32;
const MAX_PROTECTED_CIPHERTEXT_LEN: usize = 4096;

/// Opaque failure from a platform/private-key protector.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("private-key protection failed")]
pub struct PrivateKeyProtectionError;

/// Wraps and unwraps private identity material with a platform-protected key.
///
/// Implementations must use an appropriate OS-backed protection mechanism and
/// return ciphertext, never plaintext, from [`wrap`](Self::wrap). Unwrapped
/// material is consumed only inside this crate by [`DeviceIdentity::load_protected`].
/// This trait does not itself provide an OS keystore implementation.
pub trait PrivateKeyProtector {
    /// Protects raw identity material and returns only its opaque ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform protection operation fails.
    fn wrap(&self, private_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError>;

    /// Unwraps ciphertext for immediate validation and key reconstruction.
    ///
    /// # Errors
    ///
    /// Returns an error when ciphertext cannot be unwrapped.
    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError>;
}

/// Errors from identity generation, protected identity handling, and key operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    /// The operating system CSPRNG could not provide key material.
    #[error("operating system random number generator failed")]
    RandomSource,
    /// A protector failed to wrap or unwrap key material.
    #[error(transparent)]
    Protection(#[from] PrivateKeyProtectionError),
    /// A public key, signature, or bundle has an invalid byte length.
    #[error("invalid {kind} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Name of the malformed input.
        kind: &'static str,
        /// Required byte count.
        expected: usize,
        /// Supplied byte count.
        actual: usize,
    },
    /// A protector input or output exceeded the bounded ciphertext size.
    #[error("{kind} exceeds {maximum} bytes: got {actual}")]
    ProtectedCiphertextTooLarge {
        /// Whether the oversized byte string was supplied or returned.
        kind: &'static str,
        /// Maximum permitted ciphertext byte count.
        maximum: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// The public identity bundle uses an unsupported version.
    #[error("unsupported public identity bundle version: {0}")]
    UnsupportedBundleVersion(u8),
    /// Protected private material is malformed, unsupported, or inconsistent.
    #[error("protected identity material is invalid")]
    InvalidProtectedMaterial,
    /// The public bytes do not encode a valid Ed25519 verification key.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// X25519 peer input is low-order and would produce an all-zero shared secret.
    #[error("X25519 peer key is non-contributory")]
    NonContributoryDhKey,
    /// The supplied full fingerprint does not match the exact public bundle.
    #[error("public identity bundle fingerprint mismatch")]
    FingerprintMismatch,
    /// The signature does not verify for the provided key and message.
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}

impl From<getrandom::Error> for IdentityError {
    fn from(_: getrandom::Error) -> Self {
        Self::RandomSource
    }
}

/// Public, fixed-width version-1 identity bundle.
///
/// Its exact encoding is `version (1 byte) || Ed25519 public key (32 bytes) ||
/// X25519 public key (32 bytes)`. This is a candidate local profile until the
/// protocol identity specification is cross-checked and frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityPublicBundle {
    ed25519_public_key: [u8; 32],
    x25519_public_key: [u8; 32],
}

impl IdentityPublicBundle {
    /// Parses the exact version-1 public identity encoding.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid length, unsupported version, invalid
    /// Ed25519 key, or non-contributory X25519 key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let encoded: &[u8; PUBLIC_BUNDLE_LEN] =
            bytes.try_into().map_err(|_| IdentityError::InvalidLength {
                kind: "public identity bundle",
                expected: PUBLIC_BUNDLE_LEN,
                actual: bytes.len(),
            })?;
        if encoded[0] != PUBLIC_BUNDLE_VERSION {
            return Err(IdentityError::UnsupportedBundleVersion(encoded[0]));
        }
        let mut ed25519_public_key = [0_u8; 32];
        ed25519_public_key.copy_from_slice(&encoded[1..33]);
        VerifyingKey::from_bytes(&ed25519_public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let mut x25519_public_key = [0_u8; 32];
        x25519_public_key.copy_from_slice(&encoded[33..65]);
        let probe_secret = StaticSecret::from([0xA5; 32]);
        let peer_public_key = X25519PublicKey::from(x25519_public_key);
        if !probe_secret
            .diffie_hellman(&peer_public_key)
            .was_contributory()
        {
            return Err(IdentityError::NonContributoryDhKey);
        }
        Ok(Self {
            ed25519_public_key,
            x25519_public_key,
        })
    }

    /// Serializes the public bundle to its exact fixed-width version-1 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; PUBLIC_BUNDLE_LEN] {
        let mut bytes = [0_u8; PUBLIC_BUNDLE_LEN];
        bytes[0] = PUBLIC_BUNDLE_VERSION;
        bytes[1..33].copy_from_slice(&self.ed25519_public_key);
        bytes[33..65].copy_from_slice(&self.x25519_public_key);
        bytes
    }

    /// Returns the Ed25519 public verification key.
    #[must_use]
    pub const fn ed25519_public_key(&self) -> [u8; 32] {
        self.ed25519_public_key
    }

    /// Returns the X25519 public key.
    #[must_use]
    pub const fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519_public_key
    }

    /// Returns SHA-256 of the domain tag followed by the exact encoded bundle.
    #[must_use]
    pub fn fingerprint(self) -> [u8; 32] {
        fingerprint_for_bundle(&self.to_bytes())
    }
}

/// A local identity with non-exportable-by-API Ed25519 and X25519 private keys.
///
/// The type intentionally does not implement `Debug`, `Clone`, or serialization.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    dh_secret: StaticSecret,
}

impl DeviceIdentity {
    /// Creates signing and X25519 keys from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating-system random source fails.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut signing_seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *signing_seed)?;
        let mut dh_seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *dh_seed)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&signing_seed),
            dh_secret: StaticSecret::from(*dh_seed),
        })
    }

    /// Creates an identity and returns its opaque protector-produced ciphertext.
    ///
    /// The raw versioned material is constructed and zeroized inside this crate.
    /// The ciphertext is suitable for persistence only when `protector` is a
    /// reviewed OS-backed implementation. No production keystore provider is
    /// included here.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation, protection, or the output-size
    /// bound fails.
    pub fn generate_protected<P: PrivateKeyProtector>(
        protector: &P,
    ) -> Result<(Self, Vec<u8>), IdentityError> {
        let identity = Self::generate()?;
        let private_material = identity.protected_material();
        let ciphertext = protector.wrap(&private_material[..])?;
        if ciphertext.len() > MAX_PROTECTED_CIPHERTEXT_LEN {
            return Err(IdentityError::ProtectedCiphertextTooLarge {
                kind: "protected ciphertext output",
                maximum: MAX_PROTECTED_CIPHERTEXT_LEN,
                actual: ciphertext.len(),
            });
        }
        Ok((identity, ciphertext))
    }

    /// Reopens an identity from protector ciphertext without returning raw keys.
    ///
    /// The ciphertext length is bounded before calling the protector. The
    /// unwrapped version, length, and public-key consistency are then validated.
    ///
    /// # Errors
    ///
    /// Returns an error if ciphertext is oversized, protection fails, or the
    /// unwrapped material is invalid.
    pub fn load_protected<P: PrivateKeyProtector>(
        protector: &P,
        ciphertext: &[u8],
    ) -> Result<Self, IdentityError> {
        if ciphertext.len() > MAX_PROTECTED_CIPHERTEXT_LEN {
            return Err(IdentityError::ProtectedCiphertextTooLarge {
                kind: "protected ciphertext input",
                maximum: MAX_PROTECTED_CIPHERTEXT_LEN,
                actual: ciphertext.len(),
            });
        }
        let private_material = Zeroizing::new(protector.unwrap(ciphertext)?);
        if private_material.len() != PROTECTED_MATERIAL_LEN
            || private_material[0] != PROTECTED_MATERIAL_VERSION
        {
            return Err(IdentityError::InvalidProtectedMaterial);
        }

        let mut signing_seed = Zeroizing::new([0_u8; 32]);
        signing_seed.copy_from_slice(&private_material[1..33]);
        let mut dh_seed = Zeroizing::new([0_u8; 32]);
        dh_seed.copy_from_slice(&private_material[33..65]);
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let dh_secret = StaticSecret::from(*dh_seed);

        let signing_public_key = signing_key.verifying_key().to_bytes();
        let dh_public_key = X25519PublicKey::from(&dh_secret).to_bytes();
        if private_material[65..97] != signing_public_key
            || private_material[97..129] != dh_public_key
        {
            return Err(IdentityError::InvalidProtectedMaterial);
        }
        Ok(Self {
            signing_key,
            dh_secret,
        })
    }

    fn protected_material(&self) -> Zeroizing<[u8; PROTECTED_MATERIAL_LEN]> {
        let mut private_material = Zeroizing::new([0_u8; PROTECTED_MATERIAL_LEN]);
        private_material[0] = PROTECTED_MATERIAL_VERSION;
        let signing_seed = Zeroizing::new(self.signing_key.to_bytes());
        private_material[1..33].copy_from_slice(&*signing_seed);
        let dh_seed = Zeroizing::new(self.dh_secret.to_bytes());
        private_material[33..65].copy_from_slice(&*dh_seed);
        private_material[65..97].copy_from_slice(&self.public_key());
        private_material[97..129].copy_from_slice(&self.dh_public_key());
        private_material
    }

    /// Returns this device's 32-byte Ed25519 public verification key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns this device's 32-byte X25519 public key.
    #[must_use]
    pub fn dh_public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.dh_secret).to_bytes()
    }

    /// Returns the public identity bundle in the candidate version-1 encoding.
    #[must_use]
    pub fn public_bundle(&self) -> IdentityPublicBundle {
        IdentityPublicBundle {
            ed25519_public_key: self.public_key(),
            x25519_public_key: self.dh_public_key(),
        }
    }

    /// Returns the full SHA-256 fingerprint of the exact public bundle bytes.
    ///
    /// The hash is `SHA-256(UTF-8("lattice:identity-bundle:v1") || 0x00 ||
    /// versioned_public_bundle_bytes)`. This encoding is a candidate profile
    /// until cross-checked against the versioned protocol identity specification.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public_bundle().fingerprint()
    }

    /// Signs arbitrary bytes, returning a 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Derives a contributory X25519 secret held in zeroizing memory.
    ///
    /// The peer key must be authenticated by an application protocol. A KDF
    /// bound to the authenticated transcript is required before using this
    /// secret as key material. This API does not expose it through FFI.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or non-contributory peer key.
    pub fn derive_shared_secret(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let peer_public_key: &[u8; 32] =
            peer_public_key
                .try_into()
                .map_err(|_| IdentityError::InvalidLength {
                    kind: "X25519 public key",
                    expected: 32,
                    actual: peer_public_key.len(),
                })?;
        let peer_public_key = X25519PublicKey::from(*peer_public_key);
        let shared_secret = self.dh_secret.diffie_hellman(&peer_public_key);
        if !shared_secret.was_contributory() {
            return Err(IdentityError::NonContributoryDhKey);
        }
        Ok(Zeroizing::new(shared_secret.to_bytes()))
    }
}

/// Verifies an Ed25519 signature against exact-length public inputs.
///
/// A valid signature demonstrates key possession; it does not establish
/// authorization or a trusted real-world identity.
///
/// # Errors
///
/// Returns an error for invalid public-key or signature lengths, an invalid
/// public key, or a signature that does not verify.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
    let public_key: &[u8; 32] =
        public_key
            .try_into()
            .map_err(|_| IdentityError::InvalidLength {
                kind: "Ed25519 public key",
                expected: 32,
                actual: public_key.len(),
            })?;
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| IdentityError::InvalidLength {
            kind: "signature",
            expected: 64,
            actual: signature.len(),
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| IdentityError::VerificationFailed)
}

fn fingerprint_for_bundle(bundle_bytes: &[u8; PUBLIC_BUNDLE_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(bundle_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        DeviceIdentity, IdentityError, IdentityPublicBundle, PinnedIdentity,
        PrivateKeyProtectionError, PrivateKeyProtector, verify,
    };
    use ed25519_dalek::SigningKey;
    /// Test-only passthrough; it deliberately provides no confidentiality.
    struct TestProtector {
        fail_wrap: bool,
        fail_unwrap: bool,
    }

    impl PrivateKeyProtector for TestProtector {
        fn wrap(&self, private_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            if self.fail_wrap {
                return Err(PrivateKeyProtectionError);
            }
            Ok(private_material.to_vec())
        }

        fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            if self.fail_unwrap {
                return Err(PrivateKeyProtectionError);
            }
            Ok(ciphertext.to_vec())
        }
    }

    struct OversizedProtector;

    impl PrivateKeyProtector for OversizedProtector {
        fn wrap(&self, _: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(vec![0; 4097])
        }

        fn unwrap(&self, _: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Err(PrivateKeyProtectionError)
        }
    }

    #[test]
    fn signs_and_verifies_and_rejects_tampering() {
        let identity = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let message = b"device identity proof";
        let signature = identity.sign(message);
        assert_eq!(verify(&identity.public_key(), message, &signature), Ok(()));
        assert_eq!(
            verify(&identity.public_key(), b"changed message", &signature),
            Err(IdentityError::VerificationFailed)
        );
        let mut changed_signature = signature;
        changed_signature[0] ^= 1;
        assert_eq!(
            verify(&identity.public_key(), message, &changed_signature),
            Err(IdentityError::VerificationFailed)
        );
    }

    #[test]
    fn pinned_identity_requires_exact_full_bundle_fingerprint() {
        let identity = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let bundle = identity.public_bundle();
        let fingerprint = bundle.fingerprint();
        let pinned = PinnedIdentity::from_verified_fingerprint(bundle, fingerprint)
            .expect("matching fingerprint");
        assert_eq!(pinned.bundle(), bundle);
        assert_eq!(pinned.fingerprint(), fingerprint);

        let mut wrong_fingerprint = fingerprint;
        wrong_fingerprint[0] ^= 1;
        assert_eq!(
            PinnedIdentity::from_verified_fingerprint(bundle, wrong_fingerprint),
            Err(IdentityError::FingerprintMismatch)
        );

        let mut changed_bundle_bytes = bundle.to_bytes();
        changed_bundle_bytes[33] ^= 1;
        let changed_x25519 = IdentityPublicBundle::from_bytes(&changed_bundle_bytes)
            .expect("changed X25519 bytes remain a valid public bundle");
        assert_eq!(
            changed_bundle_bytes[1..33],
            bundle.to_bytes()[1..33],
            "Ed25519 key is unchanged"
        );
        assert_eq!(
            PinnedIdentity::from_verified_fingerprint(changed_x25519, fingerprint),
            Err(IdentityError::FingerprintMismatch)
        );
    }

    #[test]
    fn identity_bundle_rejects_non_contributory_x25519_key() {
        let identity = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let mut bytes = identity.public_bundle().to_bytes();
        bytes[33..].fill(0);

        assert_eq!(
            IdentityPublicBundle::from_bytes(&bytes),
            Err(IdentityError::NonContributoryDhKey)
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex value has complete byte pairs");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex input is ASCII"), 16)
                    .expect("valid hexadecimal byte")
            })
            .collect()
    }

    #[test]
    fn fingerprint_binds_versioned_bundle_with_stable_vector() {
        let ed25519_public_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ])
        .verifying_key()
        .to_bytes();
        let x25519_public_key = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let mut bytes = [0_u8; 65];
        bytes[0] = 1;
        bytes[1..33].copy_from_slice(&ed25519_public_key);
        bytes[33..].copy_from_slice(&x25519_public_key);
        let bundle = IdentityPublicBundle::from_bytes(&bytes).expect("valid public bundle");
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/identity-bundle.json"
        ))
        .expect("parse published identity vector");
        assert_eq!(
            bundle.to_bytes().as_slice(),
            decode_hex(
                vector["bundle_hex"]
                    .as_str()
                    .expect("vector includes encoded bundle")
            )
        );
        let expected_fingerprint: [u8; 32] = decode_hex(
            vector["fingerprint_hex"]
                .as_str()
                .expect("vector includes fingerprint"),
        )
        .try_into()
        .expect("fingerprint is 32 bytes");
        assert_eq!(bundle.fingerprint(), expected_fingerprint);

        let other_ed = SigningKey::from_bytes(&[0x42; 32])
            .verifying_key()
            .to_bytes();
        let mut changed_ed = bytes;
        changed_ed[1..33].copy_from_slice(&other_ed);
        let changed_ed = IdentityPublicBundle::from_bytes(&changed_ed).expect("valid changed key");
        assert_ne!(bundle.fingerprint(), changed_ed.fingerprint());

        let mut changed_dh = bytes;
        changed_dh[33] ^= 1;
        let changed_dh = IdentityPublicBundle::from_bytes(&changed_dh).expect("valid bundle");
        assert_ne!(bundle.fingerprint(), changed_dh.fingerprint());
    }

    #[test]
    fn generated_identities_derive_matching_pairwise_secrets() {
        let first = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let second = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let third = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let shared = first
            .derive_shared_secret(&second.dh_public_key())
            .expect("contributory peer key");
        let peer_shared = second
            .derive_shared_secret(&first.dh_public_key())
            .expect("contributory peer key");
        assert_eq!(&*shared, &*peer_shared);
        let unrelated_shared = first
            .derive_shared_secret(&third.dh_public_key())
            .expect("contributory peer key");
        assert_ne!(&*shared, &*unrelated_shared);
    }

    #[test]
    fn invalid_bundle_and_dh_inputs_are_rejected() {
        let identity = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        assert!(matches!(
            identity.derive_shared_secret(&[0; 31]),
            Err(IdentityError::InvalidLength {
                kind: "X25519 public key",
                ..
            })
        ));
        assert_eq!(
            identity.derive_shared_secret(&[0; 32]).unwrap_err(),
            IdentityError::NonContributoryDhKey
        );
        assert!(matches!(
            IdentityPublicBundle::from_bytes(&[0; 64]),
            Err(IdentityError::InvalidLength {
                kind: "public identity bundle",
                ..
            })
        ));
        let mut unsupported_version = identity.public_bundle().to_bytes();
        unsupported_version[0] = 2;
        assert_eq!(
            IdentityPublicBundle::from_bytes(&unsupported_version),
            Err(IdentityError::UnsupportedBundleVersion(2))
        );
        assert!(matches!(
            verify(&[0; 31], b"message", &[0; 64]),
            Err(IdentityError::InvalidLength {
                kind: "Ed25519 public key",
                ..
            })
        ));
        assert!(matches!(
            verify(&identity.public_key(), b"message", &[0; 63]),
            Err(IdentityError::InvalidLength {
                kind: "signature",
                ..
            })
        ));
    }

    #[test]
    fn protected_identity_round_trips_without_changing_public_identity() {
        let protector = TestProtector {
            fail_wrap: false,
            fail_unwrap: false,
        };
        let (identity, ciphertext) =
            DeviceIdentity::generate_protected(&protector).expect("protection should succeed");
        let loaded =
            DeviceIdentity::load_protected(&protector, &ciphertext).expect("load should succeed");
        assert_eq!(identity.public_bundle(), loaded.public_bundle());
        assert_eq!(identity.fingerprint(), loaded.fingerprint());
        let message = b"restored identity";
        assert_eq!(
            verify(&loaded.public_key(), message, &identity.sign(message)),
            Ok(())
        );
    }

    #[test]
    fn protected_identity_rejects_invalid_version_and_corruption() {
        let protector = TestProtector {
            fail_wrap: false,
            fail_unwrap: false,
        };
        let (_, mut ciphertext) =
            DeviceIdentity::generate_protected(&protector).expect("protection should succeed");
        ciphertext[0] ^= 1;
        assert_eq!(
            DeviceIdentity::load_protected(&protector, &ciphertext).err(),
            Some(IdentityError::InvalidProtectedMaterial)
        );

        let (_, mut ciphertext) =
            DeviceIdentity::generate_protected(&protector).expect("protection should succeed");
        ciphertext[66] ^= 1;
        assert_eq!(
            DeviceIdentity::load_protected(&protector, &ciphertext).err(),
            Some(IdentityError::InvalidProtectedMaterial)
        );

        let (_, mut ciphertext) =
            DeviceIdentity::generate_protected(&protector).expect("protection should succeed");
        ciphertext.truncate(12);
        assert_eq!(
            DeviceIdentity::load_protected(&protector, &ciphertext).err(),
            Some(IdentityError::InvalidProtectedMaterial)
        );
    }

    #[test]
    fn protected_identity_propagates_wrapper_failures() {
        let wrap_failure = TestProtector {
            fail_wrap: true,
            fail_unwrap: false,
        };
        assert_eq!(
            DeviceIdentity::generate_protected(&wrap_failure).err(),
            Some(IdentityError::Protection(PrivateKeyProtectionError))
        );

        let unwrap_failure = TestProtector {
            fail_wrap: false,
            fail_unwrap: true,
        };
        assert_eq!(
            DeviceIdentity::load_protected(&unwrap_failure, b"ciphertext").err(),
            Some(IdentityError::Protection(PrivateKeyProtectionError))
        );
    }

    #[test]
    fn protected_ciphertexts_are_bounded_before_unwrap_and_after_wrap() {
        assert_eq!(
            DeviceIdentity::generate_protected(&OversizedProtector).err(),
            Some(IdentityError::ProtectedCiphertextTooLarge {
                kind: "protected ciphertext output",
                maximum: 4096,
                actual: 4097,
            })
        );
        assert_eq!(
            DeviceIdentity::load_protected(&OversizedProtector, &[0; 4097]).err(),
            Some(IdentityError::ProtectedCiphertextTooLarge {
                kind: "protected ciphertext input",
                maximum: 4096,
                actual: 4097,
            })
        );
    }

    #[test]
    fn generated_public_identities_are_distinct() {
        let first = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let second = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        assert_ne!(first.public_bundle(), second.public_bundle());
        assert_ne!(first.fingerprint(), second.fingerprint());
    }
}
