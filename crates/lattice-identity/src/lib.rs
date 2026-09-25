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
    /// The bounded PKCS#10 request could not be encoded.
    #[error("certificate signing request encoding failed")]
    CsrEncoding,
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

    /// Creates a DER-encoded PKCS#10 request for this identity.
    ///
    /// The subject common name is `lattice:` followed by the lowercase
    /// hexadecimal full identity fingerprint. The request also includes one
    /// subjectAltName URI, `urn:lattice:identity:v1:<fingerprint>`. Its Ed25519
    /// `SubjectPublicKeyInfo` contains this identity's public signing key.
    ///
    /// # Errors
    ///
    /// Returns an error only if bounded DER encoding cannot be completed.
    pub fn certificate_signing_request(&self) -> Result<Vec<u8>, IdentityError> {
        const ED25519_ALGORITHM: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let fingerprint = self.fingerprint();
        let mut fingerprint_text = [0_u8; 72];
        fingerprint_text[..8].copy_from_slice(b"lattice:");
        let mut fingerprint_uri = [0_u8; 88];
        fingerprint_uri[..24].copy_from_slice(b"urn:lattice:identity:v1:");
        for (index, byte) in fingerprint.into_iter().enumerate() {
            fingerprint_text[8 + index * 2] = LOWERCASE_HEX[usize::from(byte >> 4)];
            fingerprint_text[9 + index * 2] = LOWERCASE_HEX[usize::from(byte & 0x0f)];
            fingerprint_uri[24 + index * 2] = LOWERCASE_HEX[usize::from(byte >> 4)];
            fingerprint_uri[25 + index * 2] = LOWERCASE_HEX[usize::from(byte & 0x0f)];
        }

        let common_name_oid = [0x06, 0x03, 0x55, 0x04, 0x03];
        let common_name = der_wrap(0x0c, &fingerprint_text)?;
        let mut attribute_content = Vec::new();
        der_append(&mut attribute_content, &common_name_oid)?;
        der_append(&mut attribute_content, &common_name)?;
        let attribute = der_wrap(0x30, &attribute_content)?;
        let relative_distinguished_name = der_wrap(0x31, &attribute)?;
        let subject = der_wrap(0x30, &relative_distinguished_name)?;

        let mut public_key_bits = [0_u8; 33];
        public_key_bits[1..].copy_from_slice(&self.public_key());
        let subject_public_key = der_wrap(0x03, &public_key_bits)?;
        let mut spki_content = Vec::new();
        der_append(&mut spki_content, ED25519_ALGORITHM)?;
        der_append(&mut spki_content, &subject_public_key)?;
        let subject_public_key_info = der_wrap(0x30, &spki_content)?;
        let uri_name = der_wrap(0x86, &fingerprint_uri)?;
        let general_names = der_wrap(0x30, &uri_name)?;
        let subject_alt_name_oid = [0x06, 0x03, 0x55, 0x1d, 0x11];
        let encoded_general_names = der_wrap(0x04, &general_names)?;
        let mut extension_content = Vec::new();
        der_append(&mut extension_content, &subject_alt_name_oid)?;
        der_append(&mut extension_content, &encoded_general_names)?;
        let extension = der_wrap(0x30, &extension_content)?;
        let extensions = der_wrap(0x30, &extension)?;
        let extension_values = der_wrap(0x31, &extensions)?;
        let extension_request_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
        ];
        let mut extension_request_content = Vec::new();
        der_append(&mut extension_request_content, &extension_request_oid)?;
        der_append(&mut extension_request_content, &extension_values)?;
        let extension_request = der_wrap(0x30, &extension_request_content)?;
        let requested_attributes = der_wrap(0xa0, &extension_request)?;

        let mut request_info_content = Vec::new();
        der_append(&mut request_info_content, &[0x02, 0x01, 0x00])?;
        der_append(&mut request_info_content, &subject)?;
        der_append(&mut request_info_content, &subject_public_key_info)?;
        der_append(&mut request_info_content, &requested_attributes)?;
        let request_info = der_wrap(0x30, &request_info_content)?;
        let signature = self.sign(&request_info);
        let mut signature_bits = [0_u8; 65];
        signature_bits[1..].copy_from_slice(&signature);
        let signature = der_wrap(0x03, &signature_bits)?;

        let mut request_content = Vec::new();
        der_append(&mut request_content, &request_info)?;
        der_append(&mut request_content, ED25519_ALGORITHM)?;
        der_append(&mut request_content, &signature)?;
        der_wrap(0x30, &request_content)
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

/// Maximum DER byte count for an identity certificate request.
const MAX_CSR_DER_LEN: usize = 1024;
const LOWERCASE_HEX: &[u8; 16] = b"0123456789abcdef";

fn der_length_bytes(length: usize) -> Result<([u8; 9], usize), IdentityError> {
    let mut encoded = [0_u8; 9];
    if length < 128 {
        encoded[0] = u8::try_from(length).map_err(|_| IdentityError::CsrEncoding)?;
        return Ok((encoded, 1));
    }
    let significant_bytes = (usize::BITS as usize - length.leading_zeros() as usize).div_ceil(8);
    if significant_bytes > 8 {
        return Err(IdentityError::CsrEncoding);
    }
    encoded[0] = 0x80 | u8::try_from(significant_bytes).map_err(|_| IdentityError::CsrEncoding)?;
    for index in 0..significant_bytes {
        encoded[1 + index] = u8::try_from((length >> ((significant_bytes - index - 1) * 8)) & 0xff)
            .map_err(|_| IdentityError::CsrEncoding)?;
    }
    Ok((encoded, significant_bytes + 1))
}

fn der_wrap(tag: u8, content: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let (length, length_size) = der_length_bytes(content.len())?;
    let total_len = 1_usize
        .checked_add(length_size)
        .and_then(|prefix| prefix.checked_add(content.len()))
        .filter(|&total| total <= MAX_CSR_DER_LEN)
        .ok_or(IdentityError::CsrEncoding)?;
    let mut der = Vec::new();
    der.try_reserve(total_len)
        .map_err(|_| IdentityError::CsrEncoding)?;
    der.push(tag);
    der.extend_from_slice(&length[..length_size]);
    der.extend_from_slice(content);
    Ok(der)
}

fn der_append(destination: &mut Vec<u8>, value: &[u8]) -> Result<(), IdentityError> {
    let total_len = destination
        .len()
        .checked_add(value.len())
        .filter(|&total| total <= MAX_CSR_DER_LEN)
        .ok_or(IdentityError::CsrEncoding)?;
    destination
        .try_reserve(total_len - destination.len())
        .map_err(|_| IdentityError::CsrEncoding)?;
    destination.extend_from_slice(value);
    Ok(())
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
    use ed25519_dalek::{Signature, VerifyingKey};

    fn take_tlv_encoded<'a>(input: &mut &'a [u8], expected_tag: u8) -> (&'a [u8], &'a [u8]) {
        assert!(input.len() >= 2);
        assert_eq!(input[0], expected_tag);
        let first_length = input[1];
        let (length, header_len) = if first_length & 0x80 == 0 {
            (usize::from(first_length), 2)
        } else {
            let length_bytes = usize::from(first_length & 0x7f);
            assert!(length_bytes > 0 && length_bytes <= 8);
            assert!(input.len() >= 2 + length_bytes);
            let mut length = 0_usize;
            for byte in &input[2..2 + length_bytes] {
                length = (length << 8) | usize::from(*byte);
            }
            assert!(length >= 128);
            (length, 2 + length_bytes)
        };
        let end = header_len.checked_add(length).expect("DER length fits");
        assert!(input.len() >= end);
        let encoded = &input[..end];
        let value = &input[header_len..end];
        *input = &input[end..];
        (encoded, value)
    }

    fn take_tlv<'a>(input: &mut &'a [u8], expected_tag: u8) -> &'a [u8] {
        take_tlv_encoded(input, expected_tag).1
    }

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
    fn csr_contains_identity_key_fingerprint_and_valid_signature() {
        let identity = DeviceIdentity::generate().expect("OS CSPRNG should be available");
        let request = identity
            .certificate_signing_request()
            .expect("bounded CSR DER encoding should succeed");
        assert!(request.len() <= super::MAX_CSR_DER_LEN);

        let mut document = request.as_slice();
        let mut request_content = take_tlv(&mut document, 0x30);
        assert!(document.is_empty());
        let (request_info_der, request_info) = take_tlv_encoded(&mut request_content, 0x30);
        assert_eq!(
            take_tlv(&mut request_content, 0x30),
            &[0x06, 0x03, 0x2b, 0x65, 0x70]
        );
        let signature_bits = take_tlv(&mut request_content, 0x03);
        assert!(request_content.is_empty());
        assert_eq!(signature_bits.len(), 65);
        assert_eq!(
            signature_bits[0], 0,
            "signature BIT STRING has no unused bits"
        );

        let mut info = request_info;
        assert_eq!(take_tlv(&mut info, 0x02), &[0x00]);
        let mut subject = take_tlv(&mut info, 0x30);
        let mut rdn = take_tlv(&mut subject, 0x31);
        assert!(subject.is_empty());
        let mut attribute = take_tlv(&mut rdn, 0x30);
        assert!(rdn.is_empty());
        assert_eq!(take_tlv(&mut attribute, 0x06), &[0x55, 0x04, 0x03]);
        let common_name = take_tlv(&mut attribute, 0x0c);
        assert!(attribute.is_empty());
        let fingerprint_hex = lowercase_hex(&identity.fingerprint());
        let expected_common_name = format!("lattice:{fingerprint_hex}");
        assert_eq!(common_name, expected_common_name.as_bytes());

        let mut spki = take_tlv(&mut info, 0x30);
        assert_eq!(take_tlv(&mut spki, 0x30), &[0x06, 0x03, 0x2b, 0x65, 0x70]);
        let public_key_bits = take_tlv(&mut spki, 0x03);
        assert!(spki.is_empty());
        assert_eq!(public_key_bits.len(), 33);
        assert_eq!(public_key_bits[0], 0);
        assert_eq!(&public_key_bits[1..], &identity.public_key());
        let mut requested_attributes = take_tlv(&mut info, 0xa0);
        let mut extension_request = take_tlv(&mut requested_attributes, 0x30);
        assert!(requested_attributes.is_empty());
        assert_eq!(
            take_tlv(&mut extension_request, 0x06),
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]
        );
        let mut extension_values = take_tlv(&mut extension_request, 0x31);
        assert!(extension_request.is_empty());
        let mut extensions = take_tlv(&mut extension_values, 0x30);
        assert!(extension_values.is_empty());
        let mut extension = take_tlv(&mut extensions, 0x30);
        assert!(extensions.is_empty());
        assert_eq!(take_tlv(&mut extension, 0x06), &[0x55, 0x1d, 0x11]);
        let mut general_names = take_tlv(&mut extension, 0x04);
        assert!(extension.is_empty());
        let mut general_names_content = take_tlv(&mut general_names, 0x30);
        assert!(general_names.is_empty());
        let uri = take_tlv(&mut general_names_content, 0x86);
        assert!(general_names_content.is_empty());
        let expected_uri = format!("urn:lattice:identity:v1:{fingerprint_hex}");
        assert_eq!(uri, expected_uri.as_bytes());
        assert!(info.is_empty());

        let public_key_bytes: [u8; 32] = public_key_bits[1..]
            .try_into()
            .expect("Ed25519 SPKI key is 32 bytes");
        let signature_bytes: [u8; 64] = signature_bits[1..]
            .try_into()
            .expect("Ed25519 CSR signature is 64 bytes");
        VerifyingKey::from_bytes(&public_key_bytes)
            .expect("CSR SPKI encodes an Ed25519 public key")
            .verify_strict(request_info_der, &Signature::from_bytes(&signature_bytes))
            .expect("CSR signature verifies over CertificationRequestInfo");
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

    fn lowercase_hex(bytes: &[u8]) -> String {
        let mut encoded = Vec::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(super::LOWERCASE_HEX[usize::from(byte >> 4)]);
            encoded.push(super::LOWERCASE_HEX[usize::from(byte & 0x0f)]);
        }
        String::from_utf8(encoded).expect("lowercase hex is ASCII")
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
    fn hostile_public_bundle_corpus_is_bounded_and_round_trips() {
        let valid = DeviceIdentity::generate()
            .expect("generate identity fixture")
            .public_bundle()
            .to_bytes();
        for index in 0..valid.len() {
            for mask in [0x01, 0x80] {
                let mut mutated = valid;
                mutated[index] ^= mask;
                if let Ok(bundle) = IdentityPublicBundle::from_bytes(&mutated) {
                    assert_eq!(bundle.to_bytes(), mutated);
                }
            }
        }

        let mut state = 0xc0ac_29b7_c97c_50dd_u64;
        for _ in 0..1_024 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = usize::try_from(state % 96).expect("bounded corpus length");
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                input.push(u8::try_from((state >> 32) & 0xff).expect("masked to one byte"));
            }
            if let Ok(bundle) = IdentityPublicBundle::from_bytes(&input) {
                assert_eq!(bundle.to_bytes().as_slice(), input.as_slice());
            }
        }
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
