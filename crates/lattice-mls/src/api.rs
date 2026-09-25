//! Production `OpenMLS` operations over a caller-owned provider.
//!
//! This API signs with [`DeviceIdentity`] and accepts X.509 credentials only
//! when the RFC 9420 certificate vector is well-formed, its leaf Ed25519 SPKI
//! matches the MLS signature key, its chain verifies to operating-system trust
//! roots, and its canonical Lattice fingerprint URI SAN matches the full device
//! identity fingerprint. Hostname matching is intentionally not used: the
//! credential is bound to the cryptographic device identity, not a DNS name.
//! MLS membership still does not confer Space authorization.
//!
//! The signing key comes from the identity crate's in-process
//! `DeviceIdentity`; no OS-keystore implementation is provided here.
//!
//! Per-call bounds are 1 MiB for `MLS` wire objects, 512 KiB for application
//! plaintext, 16 KiB for `Credential::serialized_content()`, 256 bytes for a
//! loaded group ID and 4096 members per managed group.
//! Conflict evidence retains at most two bounded wire objects. These limits
//! do not bound aggregate provider storage, provider record size, or storage
//! growth; those are controlled by the caller's provider.
//!
//! The caller supplies an [`OpenMlsProvider`] for every operation. `OpenMLS`
//! persists secrets through that provider; this crate neither chooses a
//! storage backend nor encrypts/authenticates provider data. The incoming
//! staged-`Commit`/conflict boundary is process-local and is not included in
//! `OpenMLS` storage. Callers must protect/persist their own authenticated
//! conflict metadata and must not reload a group as operational after losing
//! that metadata. Incoming `Commits` are refused without validation while a
//! local `Commit` is pending, so that case is not classified as a conflict.
//! Distinct incoming successors are quarantined only in process memory. This
//! API does not implement ADR-001 recovery or event-log atomicity.

use std::{collections::HashMap, error::Error, fmt};

#[cfg(target_os = "android")]
use std::{fs, io::Read, path::Path};

use lattice_identity::DeviceIdentity;
use openmls::prelude::tls_codec::{
    Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes,
};
use openmls::{
    credentials::{Credential, CredentialType, CredentialWithKey},
    group::{MlsGroup, StagedCommit},
    key_packages::KeyPackage,
    prelude::{
        Capabilities, Ciphersuite, ContentType, Extension, GroupEpoch, GroupId, KeyPackageIn,
        LeafNode, LeafNodeIndex, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageIn,
        MlsMessageOut, ProcessedMessageContent, Proposal, ProtocolVersion,
    },
};
use openmls_traits::{
    OpenMlsProvider,
    signatures::{Signer, SignerError},
    storage::StorageProvider,
    types::SignatureScheme,
};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};

/// `OpenMLS` ciphersuite used by the current executable MLS candidate.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Maximum TLS-encoded MLS object accepted or emitted by this boundary.
pub const MAX_MLS_WIRE_BYTES: usize = 1024 * 1024;
/// Maximum opaque X.509 credential content accepted by this boundary.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
/// Maximum number of DER certificates accepted in one X.509 credential chain.
pub const MAX_X509_CHAIN_CERTIFICATES: usize = 8;
/// Maximum MLS group identifier accepted by this boundary.
pub const MAX_GROUP_ID_BYTES: usize = 256;
/// Maximum group membership count managed by this boundary.
pub const MAX_GROUP_MEMBERS: usize = 4096;
/// Maximum application plaintext accepted or returned by this boundary.
pub const MAX_APPLICATION_BYTES: usize = 512 * 1024;

/// Errors reported by the production MLS boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsError {
    /// An input or `OpenMLS` output exceeded the documented bound.
    InputTooLarge {
        /// Input category.
        kind: &'static str,
        /// Maximum permitted byte count.
        maximum: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// The input is empty or has invalid framing for the requested operation.
    InvalidInput,
    /// The input is not a well-formed, exact TLS-encoded MLS message.
    MalformedMessage,
    /// The object is a valid MLS object but not one supported by this method.
    UnsupportedMessage,
    /// `BasicCredential` is intentionally restricted to the test harness.
    BasicCredentialForbidden,
    /// This boundary accepts only opaque `OpenMLS` X.509 credentials.
    UnsupportedCredentialType,
    /// The leaf certificate key differs from its MLS `signature_key`.
    CredentialKeyMismatch,
    /// The certificate vector, chain, trust, or fingerprint validation failed.
    CredentialValidationFailed,
    /// A group identifier does not identify the requested local group.
    WrongGroup,
    /// No matching persisted `OpenMLS` group was found.
    GroupNotFound,
    /// No member has the requested validated identity fingerprint.
    GroupMemberNotFound,
    /// An MLS object depends on a future epoch not yet present locally.
    MissingDependency {
        /// Current locally available epoch.
        current_epoch: u64,
        /// Epoch required by the input object.
        received_epoch: u64,
    },
    /// A message belongs to an epoch older than the current group epoch.
    StaleEpoch {
        /// Current locally available epoch.
        current_epoch: u64,
        /// Epoch carried by the input object.
        received_epoch: u64,
    },
    /// This group has an unmerged local Commit.
    OwnCommitPending,
    /// An incoming Commit is staged and must be explicitly accepted first.
    IncomingCommitPending,
    /// This group has been quarantined after detecting competing Commit branches.
    Conflicted,
    /// A second distinct valid Commit extended the same locally current epoch.
    ConflictDetected {
        /// Parent epoch shared by both observed Commit branches.
        parent_epoch: u64,
    },
    /// The exact incoming Commit bytes have already been staged.
    DuplicateStagedCommit,
    /// No incoming Commit is available to merge.
    NoStagedCommit,
    /// Caller acceptance did not name the exact prepared/staged Commit bytes.
    AcceptanceMismatch,
    /// The staged Commit no longer has the current group epoch as its parent.
    ParentEpochChanged,
    /// The operation requires a local Commit that is not pending.
    NoOwnCommitPending,
    /// The group is inactive and cannot process further messages.
    GroupInactive,
    /// The requested operation would exceed the group-state bound.
    GroupStateLimit,
    /// `OpenMLS` rejected an MLS operation or the caller's provider failed.
    OpenMlsFailure,
    /// The authenticated MLS member key could not be retrieved from the group.
    SenderKeyUnavailable,
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge {
                kind,
                maximum,
                actual,
            } => {
                write!(f, "{kind} exceeds {maximum} bytes: got {actual}")
            }
            Self::InvalidInput => f.write_str("invalid MLS API input"),
            Self::MalformedMessage => f.write_str("malformed TLS-encoded MLS message"),
            Self::UnsupportedMessage => f.write_str("unsupported MLS message type"),
            Self::BasicCredentialForbidden => {
                f.write_str("BasicCredential is restricted to the test interop API")
            }
            Self::UnsupportedCredentialType => f.write_str("unsupported MLS credential type"),
            Self::CredentialKeyMismatch => {
                f.write_str("MLS credential key does not match the device signer")
            }
            Self::CredentialValidationFailed => {
                f.write_str("X.509 credential failed chain or identity validation")
            }
            Self::WrongGroup => f.write_str("MLS object belongs to a different group"),
            Self::GroupNotFound => f.write_str("persisted OpenMLS group was not found"),
            Self::GroupMemberNotFound => f.write_str("MLS member identity was not found"),
            Self::MissingDependency {
                current_epoch,
                received_epoch,
            } => write!(
                f,
                "MLS epoch dependency is missing: current {current_epoch}, received {received_epoch}"
            ),
            Self::StaleEpoch {
                current_epoch,
                received_epoch,
            } => write!(
                f,
                "MLS message is stale: current {current_epoch}, received {received_epoch}"
            ),
            Self::OwnCommitPending => f.write_str("an own MLS Commit is pending"),
            Self::IncomingCommitPending => f.write_str("an incoming MLS Commit is staged"),
            Self::Conflicted => f.write_str("MLS group is quarantined as conflicted"),
            Self::ConflictDetected { parent_epoch } => write!(
                f,
                "competing valid MLS Commits extend parent epoch {parent_epoch}"
            ),
            Self::DuplicateStagedCommit => f.write_str("MLS Commit is already staged"),
            Self::NoStagedCommit => f.write_str("there is no staged MLS Commit"),
            Self::AcceptanceMismatch => {
                f.write_str("acceptance must name the exact MLS Commit bytes")
            }
            Self::ParentEpochChanged => f.write_str("MLS Commit parent epoch changed"),
            Self::NoOwnCommitPending => f.write_str("there is no pending local MLS Commit"),
            Self::GroupInactive => f.write_str("MLS group is inactive"),
            Self::GroupStateLimit => f.write_str("MLS group state limit exceeded"),
            Self::SenderKeyUnavailable => {
                f.write_str("MLS sender key is unavailable in the current group")
            }
            Self::OpenMlsFailure => {
                f.write_str("OpenMLS or the caller provider rejected the operation")
            }
        }
    }
}

impl Error for MlsError {}

/// Result type for production MLS operations.
pub type MlsResult<T> = Result<T, MlsError>;

/// Caller-supplied X.509 credential paired with a local device key.
///
/// The production constructor validates the exact RFC 9420 certificate vector,
/// device Ed25519 SPKI, full-fingerprint SAN, validity period, and OS-rooted
/// certificate path before constructing a value.
#[derive(Clone, Debug)]
pub struct DeviceCredentialInput {
    credential_with_key: CredentialWithKey,
    identity_fingerprint: [u8; 32],
}

impl DeviceCredentialInput {
    /// Validates and pairs X.509 credential content with `identity`.
    ///
    /// The content is the RFC 9420 TLS variable-length certificate vector,
    /// ordered leaf-first. The leaf SPKI must be the device's Ed25519 signing
    /// key, and exactly one canonical `urn:lattice:identity:v1:<fingerprint>`
    /// URI SAN must match the full Lattice identity fingerprint. The chain is
    /// verified against the operating system trust store at the current time;
    /// no hostname or caller-provided root semantics are applied. EKU presence
    /// is validated structurally but no TLS client/server EKU is imposed because
    /// RFC 9420 does not select one for MLS credentials.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::InputTooLarge`] when the serialized credential
    /// exceeds [`MAX_CREDENTIAL_BYTES`], [`MlsError::BasicCredentialForbidden`]
    /// for a basic credential, [`MlsError::UnsupportedCredentialType`] for
    /// another credential type, [`MlsError::CredentialKeyMismatch`] when the
    /// leaf Ed25519 SPKI differs from the device signing key, or
    /// [`MlsError::CredentialValidationFailed`] for malformed, mismatched,
    /// expired, untrusted, or otherwise invalid X.509 data.
    pub fn from_x509_credential(
        identity: &DeviceIdentity,
        credential: Credential,
    ) -> MlsResult<Self> {
        check_x509_credential_type(&credential)?;
        check_credential_size(&credential)?;
        let identity_public_key = identity.public_key();
        let identity_fingerprint = identity.fingerprint();
        let identity_fingerprint = validate_x509_credential(
            &credential,
            &identity_public_key,
            Some(&identity_fingerprint),
            true,
            false,
        )?;
        Ok(Self {
            credential_with_key: CredentialWithKey {
                credential,
                signature_key: identity.public_key().to_vec().into(),
            },
            identity_fingerprint,
        })
    }

    /// Makes an explicitly untrusted X.509 fixture for integration tests.
    ///
    /// This API is compiled only with the non-default `test-utils` feature.
    /// It inserts an unmistakable test marker and must never be used for real
    /// credentials. Normal production construction remains strict even when
    /// this feature is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is not X.509 or exceeds the
    /// credential size limit.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_untrusted_x509_credential_for_tests(
        identity: &DeviceIdentity,
        credential: &Credential,
    ) -> MlsResult<Self> {
        check_x509_credential_type(credential)?;
        check_credential_size(credential)?;
        let identity_fingerprint = identity.fingerprint();
        let mut test_content = Vec::with_capacity(
            TEST_UNTRUSTED_CREDENTIAL_MAGIC.len()
                + identity_fingerprint.len()
                + credential.serialized_content().len(),
        );
        test_content.extend_from_slice(TEST_UNTRUSTED_CREDENTIAL_MAGIC);
        test_content.extend_from_slice(&identity_fingerprint);
        test_content.extend_from_slice(credential.serialized_content());
        let credential = Credential::new(CredentialType::X509, test_content);
        check_credential_size(&credential)?;
        Ok(Self {
            credential_with_key: CredentialWithKey {
                credential,
                signature_key: identity.public_key().to_vec().into(),
            },
            identity_fingerprint,
        })
    }

    /// Returns the opaque MLS credential value.
    #[must_use]
    pub fn credential(&self) -> &Credential {
        &self.credential_with_key.credential
    }

    /// Returns the validated full Lattice identity fingerprint.
    #[must_use]
    pub const fn identity_fingerprint(&self) -> &[u8; 32] {
        &self.identity_fingerprint
    }

    fn check_signer(&self, identity: &DeviceIdentity) -> MlsResult<()> {
        if self.credential_with_key.signature_key.as_slice() != identity.public_key() {
            return Err(MlsError::CredentialKeyMismatch);
        }
        if self.identity_fingerprint != identity.fingerprint() {
            return Err(MlsError::CredentialValidationFailed);
        }
        Ok(())
    }
}

const LATTICE_IDENTITY_SAN_NAMESPACE: &[u8] = b"urn:lattice:identity:";
const LATTICE_IDENTITY_SAN_PREFIX: &[u8] = b"urn:lattice:identity:v1:";
#[cfg(any(test, feature = "test-utils"))]
const TEST_UNTRUSTED_CREDENTIAL_MAGIC: &[u8] = b"\0LATTICE-MLS-TEST-UNTRUSTED-X509-V1\0";

fn check_x509_credential_type(credential: &Credential) -> MlsResult<()> {
    match credential.credential_type() {
        CredentialType::X509 => Ok(()),
        CredentialType::Basic => Err(MlsError::BasicCredentialForbidden),
        _ => Err(MlsError::UnsupportedCredentialType),
    }
}

fn check_credential_size(credential: &Credential) -> MlsResult<()> {
    if credential.serialized_content().len() > MAX_CREDENTIAL_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "X.509 credential content",
            maximum: MAX_CREDENTIAL_BYTES,
            actual: credential.serialized_content().len(),
        });
    }
    Ok(())
}

fn validate_x509_credential(
    credential: &Credential,
    signature_key: &[u8],
    expected_identity_fingerprint: Option<&[u8; 32]>,
    verify_chain: bool,
    allow_test_marker: bool,
) -> MlsResult<[u8; 32]> {
    check_x509_credential_type(credential)?;
    check_credential_size(credential)?;
    if signature_key.len() != 32 {
        return Err(MlsError::CredentialKeyMismatch);
    }
    let content = credential.serialized_content();

    #[cfg(any(test, feature = "test-utils"))]
    if allow_test_marker && let Some(fingerprint) = test_marker_fingerprint(content) {
        return Ok(fingerprint);
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    let _ = allow_test_marker;

    let certificates = Vec::<VLBytes>::tls_deserialize_exact(content)
        .map_err(|_| MlsError::CredentialValidationFailed)?;
    if certificates.is_empty()
        || certificates.len() > MAX_X509_CHAIN_CERTIFICATES
        || certificates
            .iter()
            .any(|certificate| certificate.as_slice().is_empty())
    {
        return Err(MlsError::CredentialValidationFailed);
    }
    for certificate in &certificates[1..] {
        let der = CertificateDer::from(certificate.as_slice());
        EndEntityCert::try_from(&der).map_err(|_| MlsError::CredentialValidationFailed)?;
    }
    let mut child_issuer = certificate_issuer_subject(certificates[0].as_slice())?.0;
    for certificate in &certificates[1..] {
        let (issuer, subject) = certificate_issuer_subject(certificate.as_slice())?;
        if child_issuer != subject {
            return Err(MlsError::CredentialValidationFailed);
        }
        child_issuer = issuer;
    }

    let leaf_der = CertificateDer::from(certificates[0].as_slice());
    let leaf =
        EndEntityCert::try_from(&leaf_der).map_err(|_| MlsError::CredentialValidationFailed)?;
    if leaf.subject_public_key_info().as_ref() != ed25519_spki(signature_key) {
        return Err(MlsError::CredentialKeyMismatch);
    }
    let identity_fingerprint =
        validate_identity_san(certificates[0].as_slice(), expected_identity_fingerprint)?;

    if verify_chain {
        let intermediates: Vec<_> = certificates[1..]
            .iter()
            .map(|certificate| CertificateDer::from(certificate.as_slice()))
            .collect();
        verify_x509_path(&leaf, &intermediates)?;
    }

    Ok(identity_fingerprint)
}

#[cfg(any(test, feature = "test-utils"))]
fn test_marker_fingerprint(content: &[u8]) -> Option<[u8; 32]> {
    let content = content.strip_prefix(TEST_UNTRUSTED_CREDENTIAL_MAGIC)?;
    content.get(..32)?.try_into().ok()
}

fn ed25519_spki(public_key: &[u8]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, // SubjectPublicKeyInfo SEQUENCE
        0x30, 0x05, // AlgorithmIdentifier SEQUENCE
        0x06, 0x03, 0x2b, 0x65, 0x70, // id-Ed25519
        0x03, 0x21, 0x00, // BIT STRING, 32 key bytes, no unused bits
    ]);
    spki.extend_from_slice(public_key);
    spki
}

fn validate_identity_san(
    leaf_der: &[u8],
    expected_identity_fingerprint: Option<&[u8; 32]>,
) -> MlsResult<[u8; 32]> {
    let mut outer = leaf_der;
    let certificate = der_read_expected(&mut outer, 0x30)?;
    if !outer.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }
    let mut certificate_fields = certificate;
    let tbs = der_read_expected(&mut certificate_fields, 0x30)?;
    let _ = der_read_expected(&mut certificate_fields, 0x30)?;
    let _ = der_read_expected(&mut certificate_fields, 0x03)?;
    if !certificate_fields.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }

    let mut tbs_fields = tbs;
    if tbs_fields.first() == Some(&0xa0) {
        let _ = der_read_expected(&mut tbs_fields, 0xa0)?;
    }
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] {
        let _ = der_read_expected(&mut tbs_fields, tag)?;
    }

    let mut san_extension = None;
    while !tbs_fields.is_empty() {
        match tbs_fields[0] {
            0xa3 => {
                let extensions = der_read_expected(&mut tbs_fields, 0xa3)?;
                if !tbs_fields.is_empty() {
                    return Err(MlsError::CredentialValidationFailed);
                }
                san_extension = Some(extensions);
            }
            0x81 | 0x82 => {
                let tag = tbs_fields[0];
                let _ = der_read_expected(&mut tbs_fields, tag)?;
            }
            _ => return Err(MlsError::CredentialValidationFailed),
        }
    }

    let extensions = san_extension.ok_or(MlsError::CredentialValidationFailed)?;
    let mut extension_sequence = extensions;
    let extension_bytes = der_read_expected(&mut extension_sequence, 0x30)?;
    if !extension_sequence.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }

    let mut extension_bytes = extension_bytes;
    let mut san = None;
    while !extension_bytes.is_empty() {
        let extension = der_read_expected(&mut extension_bytes, 0x30)?;
        let mut extension_fields = extension;
        let oid = der_read_expected(&mut extension_fields, 0x06)?;
        if extension_fields.first() == Some(&0x01) {
            let critical = der_read_expected(&mut extension_fields, 0x01)?;
            if critical.len() != 1 || !matches!(critical[0], 0 | 0xff) {
                return Err(MlsError::CredentialValidationFailed);
            }
        }
        let value = der_read_expected(&mut extension_fields, 0x04)?;
        if !extension_fields.is_empty() {
            return Err(MlsError::CredentialValidationFailed);
        }
        if oid == [0x55, 0x1d, 0x11] && san.replace(value).is_some() {
            return Err(MlsError::CredentialValidationFailed);
        }
    }

    let san = san.ok_or(MlsError::CredentialValidationFailed)?;
    let mut san_sequence = san;
    let names = der_read_expected(&mut san_sequence, 0x30)?;
    if !san_sequence.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }
    let mut names = names;
    let mut matched_fingerprint = None;
    let mut identity_name_count = 0;
    while !names.is_empty() {
        let (tag, value) = der_read_any(&mut names)?;
        if tag == 0x86
            && value
                .get(..LATTICE_IDENTITY_SAN_NAMESPACE.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(LATTICE_IDENTITY_SAN_NAMESPACE))
        {
            identity_name_count += 1;
            if !value.starts_with(LATTICE_IDENTITY_SAN_PREFIX) {
                return Err(MlsError::CredentialValidationFailed);
            }
            let fingerprint_hex = value
                .get(LATTICE_IDENTITY_SAN_PREFIX.len()..)
                .ok_or(MlsError::CredentialValidationFailed)?;
            let fingerprint = parse_fingerprint_hex(fingerprint_hex)?;
            if value != identity_uri(&fingerprint).as_bytes()
                || expected_identity_fingerprint.is_some_and(|expected| expected != &fingerprint)
            {
                return Err(MlsError::CredentialValidationFailed);
            }
            matched_fingerprint = Some(fingerprint);
        }
    }
    if identity_name_count != 1 {
        return Err(MlsError::CredentialValidationFailed);
    }
    matched_fingerprint.ok_or(MlsError::CredentialValidationFailed)
}

fn identity_uri(fingerprint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut uri = String::with_capacity(LATTICE_IDENTITY_SAN_PREFIX.len() + 64);
    uri.push_str(std::str::from_utf8(LATTICE_IDENTITY_SAN_PREFIX).expect("constant is UTF-8"));
    for byte in fingerprint {
        uri.push(char::from(HEX[usize::from(byte >> 4)]));
        uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    uri
}

fn parse_fingerprint_hex(value: &[u8]) -> MlsResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(MlsError::CredentialValidationFailed);
    }
    let mut fingerprint = [0; 32];
    for (index, pair) in value.chunks_exact(2).enumerate() {
        let high = parse_lower_hex(pair[0]).ok_or(MlsError::CredentialValidationFailed)?;
        let low = parse_lower_hex(pair[1]).ok_or(MlsError::CredentialValidationFailed)?;
        fingerprint[index] = (high << 4) | low;
    }
    Ok(fingerprint)
}

fn parse_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn der_read_expected<'a>(input: &mut &'a [u8], tag: u8) -> MlsResult<&'a [u8]> {
    let (actual_tag, value) = der_read_any(input)?;
    if actual_tag != tag {
        return Err(MlsError::CredentialValidationFailed);
    }
    Ok(value)
}

fn der_read_any<'a>(input: &mut &'a [u8]) -> MlsResult<(u8, &'a [u8])> {
    let (&tag, remaining) = input
        .split_first()
        .ok_or(MlsError::CredentialValidationFailed)?;
    if tag & 0x1f == 0x1f {
        return Err(MlsError::CredentialValidationFailed);
    }
    let (&first_length, remaining) = remaining
        .split_first()
        .ok_or(MlsError::CredentialValidationFailed)?;
    let (length, remaining) = if first_length & 0x80 == 0 {
        (usize::from(first_length), remaining)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > 4 || remaining.len() < length_bytes {
            return Err(MlsError::CredentialValidationFailed);
        }
        let (encoded_length, remaining) = remaining.split_at(length_bytes);
        if encoded_length[0] == 0 {
            return Err(MlsError::CredentialValidationFailed);
        }
        let mut length = 0usize;
        for byte in encoded_length {
            length = length
                .checked_mul(256)
                .and_then(|length| length.checked_add(usize::from(*byte)))
                .ok_or(MlsError::CredentialValidationFailed)?;
        }
        if length < 128 {
            return Err(MlsError::CredentialValidationFailed);
        }
        (length, remaining)
    };
    if remaining.len() < length {
        return Err(MlsError::CredentialValidationFailed);
    }
    let (value, rest) = remaining.split_at(length);
    *input = rest;
    Ok((tag, value))
}
fn certificate_issuer_subject(certificate: &[u8]) -> MlsResult<(&[u8], &[u8])> {
    let mut outer = certificate;
    let mut certificate_fields = der_read_expected(&mut outer, 0x30)?;
    if !outer.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }
    let mut tbs = der_read_expected(&mut certificate_fields, 0x30)?;
    if tbs.first() == Some(&0xa0) {
        let _ = der_read_expected(&mut tbs, 0xa0)?;
    }
    let _ = der_read_expected(&mut tbs, 0x02)?;
    let _ = der_read_expected(&mut tbs, 0x30)?;
    let issuer = der_read_expected(&mut tbs, 0x30)?;
    let _ = der_read_expected(&mut tbs, 0x30)?;
    let subject = der_read_expected(&mut tbs, 0x30)?;
    Ok((issuer, subject))
}

fn verify_x509_path(
    leaf: &EndEntityCert<'_>,
    intermediates: &[CertificateDer<'_>],
) -> MlsResult<()> {
    let root_certificates = load_platform_roots()?;
    let trust_anchors: Vec<TrustAnchor<'_>> = root_certificates
        .iter()
        .filter_map(|certificate| webpki::anchor_from_trusted_cert(certificate).ok())
        .collect();
    if trust_anchors.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &trust_anchors,
        intermediates,
        UnixTime::now(),
        AnyExtendedKeyUsage,
        None,
        None,
    )
    .map_err(|_| MlsError::CredentialValidationFailed)?;
    Ok(())
}

struct AnyExtendedKeyUsage;

impl ExtendedKeyUsageValidator for AnyExtendedKeyUsage {
    fn validate(&self, eku: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in eku {
            purpose?;
        }
        Ok(())
    }
}

#[cfg(target_os = "android")]
fn load_platform_roots() -> MlsResult<Vec<CertificateDer<'static>>> {
    const MAX_ROOTS: usize = 4096;
    const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;
    const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
    let apex_store = Path::new("/apex/com.android.conscrypt/cacerts");
    let legacy_store = Path::new("/system/etc/security/cacerts");
    let system_store = if android_store_has_certificates(apex_store)? {
        apex_store
    } else {
        legacy_store
    };
    let entries = fs::read_dir(system_store).map_err(|_| MlsError::CredentialValidationFailed)?;
    let mut certificates = Vec::new();
    let mut total_bytes = 0usize;
    for entry in entries {
        let entry = entry.map_err(|_| MlsError::CredentialValidationFailed)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((_, suffix)) = name.rsplit_once('.') else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|_| MlsError::CredentialValidationFailed)?
            .is_file()
        {
            continue;
        }
        let mut file =
            fs::File::open(entry.path()).map_err(|_| MlsError::CredentialValidationFailed)?;
        let mut encoded = Vec::new();
        file.by_ref()
            .take(MAX_CERTIFICATE_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(|_| MlsError::CredentialValidationFailed)?;
        if encoded.is_empty() || encoded.len() as u64 > MAX_CERTIFICATE_BYTES {
            return Err(MlsError::CredentialValidationFailed);
        }
        total_bytes = total_bytes
            .checked_add(encoded.len())
            .filter(|total| *total <= MAX_TOTAL_BYTES)
            .ok_or(MlsError::CredentialValidationFailed)?;
        certificates.push(decode_android_ca_certificate(encoded)?);
        if certificates.len() > MAX_ROOTS {
            return Err(MlsError::CredentialValidationFailed);
        }
    }
    if certificates.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }
    Ok(certificates)
}

#[cfg(target_os = "android")]
fn android_store_has_certificates(store: &Path) -> MlsResult<bool> {
    let entries = match fs::read_dir(store) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(MlsError::CredentialValidationFailed),
    };
    for entry in entries {
        let entry = entry.map_err(|_| MlsError::CredentialValidationFailed)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((_, suffix)) = name.rsplit_once('.') else {
            continue;
        };
        if !suffix.is_empty()
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
            && entry
                .file_type()
                .map_err(|_| MlsError::CredentialValidationFailed)?
                .is_file()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "android")]
fn decode_android_ca_certificate(encoded: Vec<u8>) -> MlsResult<CertificateDer<'static>> {
    use rustls_pki_types::pem::{PemObject, SectionKind};

    let pem_start = encoded
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(encoded.len());
    let (preamble, body) = encoded.split_at(pem_start);
    if preamble.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(MlsError::CredentialValidationFailed);
    }
    if body.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let mut sections = <(SectionKind, Vec<u8>)>::pem_slice_iter(body);
        let (kind, der) = sections
            .next()
            .transpose()
            .map_err(|_| MlsError::CredentialValidationFailed)?
            .ok_or(MlsError::CredentialValidationFailed)?;
        if kind != SectionKind::Certificate
            || sections
                .remainder()
                .iter()
                .any(|byte| !byte.is_ascii_whitespace())
        {
            return Err(MlsError::CredentialValidationFailed);
        }
        return Ok(CertificateDer::from(der));
    }
    if body.first() != Some(&0x30) {
        return Err(MlsError::CredentialValidationFailed);
    }
    Ok(CertificateDer::from(encoded))
}

#[cfg(not(target_os = "android"))]
fn load_platform_roots() -> MlsResult<Vec<CertificateDer<'static>>> {
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        return Err(MlsError::CredentialValidationFailed);
    }
    Ok(result.certs)
}
struct DeviceSigner<'a>(&'a DeviceIdentity);

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Type of the serialized MLS object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsWireKind {
    /// A signed MLS `KeyPackage`.
    KeyPackage,
    /// An MLS proposal.
    Proposal,
    /// An MLS Commit.
    Commit,
    /// An MLS Welcome.
    Welcome,
    /// MLS application data.
    Application,
}

/// Bounded TLS-encoded MLS output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsMessage {
    bytes: Vec<u8>,
    kind: MlsWireKind,
}

impl MlsMessage {
    /// Returns the TLS-encoded MLS object.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the type of the encoded MLS object.
    #[must_use]
    pub const fn kind(&self) -> MlsWireKind {
        self.kind
    }
}

/// Space authorization is not evaluated by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceAuthorization {
    /// No verified Lattice identity or Space policy input was evaluated.
    NotEvaluated,
}

/// Domain prefix used to derive the event-visible MLS group reference.
pub const MLS_GROUP_REFERENCE_DOMAIN: &[u8] = b"lattice:mls-group-reference:v1\0";

/// Decrypted data bound to the exact input ciphertext, authenticated MLS member
/// key, and the validated full-fingerprint URI SAN from that member's credential.
///
/// This proves MLS membership-key possession and its certificate-bound Lattice
/// identity. The caller must compare both values with the signed event author
/// and still apply Space authorization and policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsApplication {
    plaintext: Vec<u8>,
    member_signature_key: Option<[u8; 32]>,
    member_identity_fingerprint: Option<[u8; 32]>,
    ciphertext_sha256: [u8; 32],
    epoch: u64,
    group_reference: [u8; 32],
}

impl MlsApplication {
    /// Returns the exact decrypted application plaintext.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Consumes this result and transfers ownership of its plaintext.
    #[must_use]
    pub fn into_plaintext(self) -> Vec<u8> {
        self.plaintext
    }

    /// Returns the MLS member's Ed25519 key, if the message came from a group member.
    #[must_use]
    pub const fn member_signature_key(&self) -> Option<&[u8; 32]> {
        self.member_signature_key.as_ref()
    }
    /// Returns the authenticated sender's validated full Lattice fingerprint.
    ///
    /// The application must compare this with the signed event author's full
    /// identity fingerprint before binding this plaintext to that event.
    #[must_use]
    pub const fn member_identity_fingerprint(&self) -> Option<&[u8; 32]> {
        self.member_identity_fingerprint.as_ref()
    }
    /// Replaces only the member fingerprint for negative admission tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_test_member_identity_fingerprint(mut self, fingerprint: [u8; 32]) -> Self {
        self.member_identity_fingerprint = Some(fingerprint);
        self
    }

    /// Returns the SHA-256 digest of the exact TLS-encoded ciphertext processed.
    #[must_use]
    pub const fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }

    /// Returns the MLS epoch under which the ciphertext was accepted.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the candidate event-visible reference for this MLS group.
    #[must_use]
    pub const fn group_reference(&self) -> &[u8; 32] {
        &self.group_reference
    }

    /// Whether `ciphertext` is the exact bounded object that produced this plaintext.
    #[must_use]
    pub fn matches_ciphertext(&self, ciphertext: &[u8]) -> bool {
        if ciphertext.len() > MAX_MLS_WIRE_BYTES {
            return false;
        }
        let digest: [u8; 32] = Sha256::digest(ciphertext).into();
        digest == self.ciphertext_sha256
    }
}

/// A successful result from processing an incoming MLS object.
#[derive(Debug, PartialEq, Eq)]
pub enum IncomingResult {
    /// Decrypted MLS application data with full identity, member-key, and ciphertext binding.
    Application(MlsApplication),
    /// A validated MLS proposal, not yet admitted by application policy.
    Proposal {
        /// Whether the proposal used the external sender path.
        external: bool,
        /// Space authorization has not been evaluated.
        space_authorization: SpaceAuthorization,
    },
    /// A valid Commit staged against the current locally held epoch.
    StagedCommit {
        /// The Commit's parent epoch, which must remain current until merge.
        parent_epoch: u64,
        /// Space authorization has not been evaluated.
        space_authorization: SpaceAuthorization,
    },
}

/// Current state exposed by the production MLS boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupStatus {
    /// No pending transition, conflict, or inactive state is known locally.
    Operational,
    /// This member has an unmerged local Commit.
    OwnCommitPending,
    /// One authenticated incoming Commit is staged in this process.
    IncomingCommitStaged,
    /// Distinct valid Commits were observed from the same local parent epoch.
    Conflicted,
    /// `OpenMLS` reports that the local member is no longer active.
    Inactive,
}

struct IncomingCommit {
    staged: StagedCommit,
    encoded: Vec<u8>,
    parent_epoch: GroupEpoch,
    identity_keys_to_remove: Vec<[u8; 32]>,
    identity_fingerprints_to_add: Vec<([u8; 32], [u8; 32])>,
    membership_change: Option<ValidatedMlsMembershipChange>,
}
struct StagedCredentialCandidate {
    credential: Credential,
    signature_key: [u8; 32],
    is_member: bool,
}
struct StagedCredentialChanges {
    identity_keys_to_remove: Vec<[u8; 32]>,
    identity_fingerprints_to_add: Vec<([u8; 32], [u8; 32])>,
}

/// One membership delta extracted from an authenticated, staged MLS Commit.
///
/// This proof is available only while the exact Commit remains staged. It
/// binds the group, parent epoch, authenticated author, exact wire digest,
/// target identity and, for an Add, the exact TLS `KeyPackage` hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMlsMembershipChange {
    group_reference: [u8; 32],
    parent_epoch: u64,
    author: [u8; 32],
    commit_sha256: [u8; 32],
    action: MlsMembershipAction,
    target: [u8; 32],
    key_package_hash: Option<[u8; 32]>,
}
/// A membership binding extracted only after an opaque staged proof is checked.
#[derive(Debug, Eq, PartialEq)]
pub struct MlsMembershipControlBinding {
    action: MlsMembershipAction,
    target: [u8; 32],
    key_package_hash: Option<[u8; 32]>,
}

impl MlsMembershipControlBinding {
    /// Returns whether the Commit adds or removes one member.
    #[must_use]
    pub const fn action(&self) -> MlsMembershipAction {
        self.action
    }

    /// Returns the full identity fingerprint of the changed member.
    #[must_use]
    pub const fn target(&self) -> &[u8; 32] {
        &self.target
    }

    /// Returns the exact TLS `KeyPackage` hash for Add; `None` for Remove.
    #[must_use]
    pub const fn key_package_hash(&self) -> Option<&[u8; 32]> {
        self.key_package_hash.as_ref()
    }
}

/// The single membership action validated in an MLS Commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsMembershipAction {
    /// Commit adds the named identity with the named `KeyPackage`.
    Add,
    /// Commit removes the named identity.
    Remove,
}

impl ValidatedMlsMembershipChange {
    /// Consumes the proof and returns its membership values only when the
    /// signed control-event context and exact Commit bytes match.
    #[must_use]
    pub fn into_control_binding(
        self,
        group_reference: &[u8; 32],
        parent_epoch: u64,
        author: &[u8; 32],
        commit_wire: &[u8],
    ) -> Option<MlsMembershipControlBinding> {
        if &self.group_reference != group_reference
            || self.parent_epoch != parent_epoch
            || &self.author != author
            || !self.matches_commit_wire(commit_wire)
        {
            return None;
        }
        Some(MlsMembershipControlBinding {
            action: self.action,
            target: self.target,
            key_package_hash: self.key_package_hash,
        })
    }

    /// Returns the group reference from the Commit's parent generation.
    #[must_use]
    pub const fn group_reference(&self) -> &[u8; 32] {
        &self.group_reference
    }

    /// Returns the parent epoch against which the Commit was authenticated.
    #[must_use]
    pub const fn parent_epoch(&self) -> u64 {
        self.parent_epoch
    }

    /// Returns the authenticated identity fingerprint of the Commit author.
    #[must_use]
    pub const fn author(&self) -> &[u8; 32] {
        &self.author
    }

    /// Returns SHA-256 of the exact TLS-encoded Commit bytes.
    #[must_use]
    pub const fn commit_sha256(&self) -> &[u8; 32] {
        &self.commit_sha256
    }

    /// Checks that bytes are the exact Commit processed by `OpenMLS`.
    #[must_use]
    pub fn matches_commit_wire(&self, wire: &[u8]) -> bool {
        <[u8; 32]>::from(Sha256::digest(wire)) == self.commit_sha256
    }

    /// Returns whether the Commit adds or removes one member.
    #[must_use]
    pub const fn action(&self) -> MlsMembershipAction {
        self.action
    }

    /// Returns the full identity fingerprint of the changed member.
    #[must_use]
    pub const fn target(&self) -> &[u8; 32] {
        &self.target
    }

    /// Returns the exact TLS `KeyPackage` hash for Add; `None` for Remove.
    #[must_use]
    pub const fn key_package_hash(&self) -> Option<&[u8; 32]> {
        self.key_package_hash.as_ref()
    }
}
/// Bounded evidence for two distinct valid successor Commits.
///
/// The value is available to the caller for authenticated persistence or
/// diagnostics. This crate retains it only in memory and does not authenticate
/// or persist it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictEvidence {
    parent_epoch: u64,
    first_commit: Vec<u8>,
    second_commit: Vec<u8>,
    first_membership_change: Option<ValidatedMlsMembershipChange>,
    second_membership_change: Option<ValidatedMlsMembershipChange>,
}

impl ConflictEvidence {
    /// Returns the epoch from which both Commit branches were validated.
    #[must_use]
    pub const fn parent_epoch(&self) -> u64 {
        self.parent_epoch
    }

    /// Returns the first locally observed branch's exact TLS bytes.
    #[must_use]
    pub fn first_commit(&self) -> &[u8] {
        &self.first_commit
    }

    /// Returns the competing branch's exact TLS bytes.
    #[must_use]
    pub fn second_commit(&self) -> &[u8] {
        &self.second_commit
    }

    /// Returns the authenticated first-branch membership proof, if present.
    #[must_use]
    pub const fn first_membership_change(&self) -> Option<&ValidatedMlsMembershipChange> {
        self.first_membership_change.as_ref()
    }

    /// Returns the authenticated competing-branch membership proof, if present.
    #[must_use]
    pub const fn second_membership_change(&self) -> Option<&ValidatedMlsMembershipChange> {
        self.second_membership_change.as_ref()
    }
}

/// `OpenMLS` group state with explicit local commit and conflict gates.
///
/// The `OpenMLS` secret state is stored through the provider passed to each
/// operation. `incoming_commit` and `conflict` are process-local only and must
/// be protected/persisted separately by the caller before relying on them
/// across restarts.
pub struct GroupState {
    inner: MlsGroup,
    incoming_commit: Option<IncomingCommit>,
    conflict: Option<ConflictEvidence>,
    member_identity_fingerprints: HashMap<[u8; 32], [u8; 32]>,
}

/// Prepared add transition; its Welcome is withheld until exact Commit acceptance.
pub struct PreparedAdd {
    group_id: Vec<u8>,
    parent_epoch: GroupEpoch,
    commit: MlsMessage,
    welcome: MlsMessage,
    added_member_signature_key: [u8; 32],
    added_member_identity_fingerprint: [u8; 32],
    key_package_sha256: [u8; 32],
}

impl PreparedAdd {
    /// Returns the exact Commit that must be accepted before the Welcome is released.
    #[must_use]
    pub fn commit(&self) -> &MlsMessage {
        &self.commit
    }

    /// Returns the parent epoch of this transition.
    #[must_use]
    pub fn parent_epoch(&self) -> u64 {
        self.parent_epoch.as_u64()
    }
    /// Returns the validated full identity fingerprint carried by the added
    /// member's certificate. Callers must compare it to the invited target
    /// before accepting the prepared Commit.
    #[must_use]
    pub const fn added_member_identity_fingerprint(&self) -> &[u8; 32] {
        &self.added_member_identity_fingerprint
    }
    /// Returns SHA-256 of the exact TLS `KeyPackage` bytes validated by this add.
    #[must_use]
    pub const fn key_package_sha256(&self) -> &[u8; 32] {
        &self.key_package_sha256
    }
}

/// Prepared removal transition; the Commit remains pending until exact
/// acceptance.
pub struct PreparedRemoval {
    group_id: Vec<u8>,
    parent_epoch: GroupEpoch,
    commit: MlsMessage,
    removed_member_signature_key: [u8; 32],
    removed_member_identity_fingerprint: [u8; 32],
}

impl PreparedRemoval {
    /// Returns the exact Commit that must be accepted.
    #[must_use]
    pub fn commit(&self) -> &MlsMessage {
        &self.commit
    }

    /// Returns the Commit's parent epoch.
    #[must_use]
    pub fn parent_epoch(&self) -> u64 {
        self.parent_epoch.as_u64()
    }

    /// Returns the identity fingerprint removed by this Commit.
    #[must_use]
    pub const fn removed_member_identity_fingerprint(&self) -> &[u8; 32] {
        &self.removed_member_identity_fingerprint
    }
}

impl GroupState {
    /// Creates an `OpenMLS` group with the current candidate ciphersuite.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::CredentialKeyMismatch`] when the credential is not
    /// paired with this identity's signing key, or [`MlsError::OpenMlsFailure`]
    /// when `OpenMLS` or the provider rejects group creation.
    pub fn create<P: OpenMlsProvider>(
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
    ) -> MlsResult<Self> {
        credential.check_signer(identity)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(x509_capabilities())
            .use_ratchet_tree_extension(true)
            .build();
        let inner = MlsGroup::new(
            provider,
            &DeviceSigner(identity),
            &config,
            credential.credential_with_key.clone(),
        )
        .map_err(|_| MlsError::OpenMlsFailure)?;
        let mut member_identity_fingerprints = HashMap::new();
        member_identity_fingerprints
            .insert(identity.public_key(), *credential.identity_fingerprint());
        Ok(Self {
            inner,
            incoming_commit: None,
            conflict: None,
            member_identity_fingerprints,
        })
    }

    /// Loads `OpenMLS` secret state from the caller's provider.
    ///
    /// Persisted members are checked for supported credential framing, the
    /// canonical identity SAN, and SPKI/signature-key equality. Certificate
    /// path and validity are not rechecked here: each credential was admitted
    /// at a trusted group transition, and time passing must not erase that
    /// persisted membership. This restores only `OpenMLS` state; it cannot
    /// recover process-local incoming-`Commit` or conflict quarantine. Callers
    /// must authenticate and restore their own boundary metadata or must not
    /// resume the group as operational.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::InputTooLarge`] for an oversized group ID,
    /// [`MlsError::InvalidInput`] for an empty ID,
    /// [`MlsError::OpenMlsFailure`] when the provider fails,
    /// [`MlsError::GroupNotFound`] when no persisted group matches,
    /// [`MlsError::GroupStateLimit`] when the group exceeds the member bound, or
    /// [`MlsError::CredentialValidationFailed`] for malformed persisted member
    /// credential content.
    pub fn load<P: OpenMlsProvider>(provider: &P, group_id: &[u8]) -> MlsResult<Self> {
        check_group_id(group_id)?;
        let id = GroupId::from_slice(group_id);
        let inner = MlsGroup::load(provider.storage(), &id)
            .map_err(|_| MlsError::OpenMlsFailure)?
            .ok_or(MlsError::GroupNotFound)?;
        if inner.members().count() > MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        let mut member_identity_fingerprints = HashMap::new();
        for member in inner.members() {
            let signature_key: [u8; 32] = member
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::CredentialKeyMismatch)?;
            let fingerprint = validate_x509_credential(
                &member.credential,
                &signature_key,
                None,
                false,
                cfg!(any(test, feature = "test-utils")),
            )?;
            if member_identity_fingerprints
                .insert(signature_key, fingerprint)
                .is_some_and(|existing| existing != fingerprint)
            {
                return Err(MlsError::CredentialValidationFailed);
            }
        }
        Ok(Self {
            inner,
            incoming_commit: None,
            conflict: None,
            member_identity_fingerprints,
        })
    }

    /// Creates a TLS-encoded `MLS` `KeyPackage` for this device and credential.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::CredentialKeyMismatch`] when the credential is not
    /// paired with this identity's signing key, or [`MlsError::OpenMlsFailure`]
    /// when key-package creation or encoding fails.
    pub fn publish_key_package<P: OpenMlsProvider>(
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
    ) -> MlsResult<MlsMessage> {
        credential.check_signer(identity)?;
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(x509_capabilities())
            .build(
                CIPHERSUITE,
                provider,
                &DeviceSigner(identity),
                credential.credential_with_key.clone(),
            )
            .map_err(|_| MlsError::OpenMlsFailure)?;
        encode_message(
            &MlsMessageOut::from(bundle.into_key_package()),
            MlsWireKind::KeyPackage,
        )
    }

    /// Joins from a `Welcome` only when the expected credential and signer key
    /// match and every staged member's certificate validates to OS trust.
    ///
    /// This does not establish Space authorization.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::InputTooLarge`] or [`MlsError::InvalidInput`] for
    /// invalid bounds, [`MlsError::UnsupportedMessage`] for a non-`Welcome`,
    /// [`MlsError::WrongGroup`] for a different group,
    /// [`MlsError::CredentialKeyMismatch`] for a different sender credential,
    /// [`MlsError::GroupStateLimit`] for excessive membership,
    /// [`MlsError::CredentialValidationFailed`] for any member whose
    /// certificate is malformed, untrusted, expired, or identity-mismatched, or
    /// [`MlsError::OpenMlsFailure`] when `OpenMLS` rejects the message/provider.
    #[allow(clippy::manual_let_else)] // Keep the explicit security-critical Welcome classification.
    pub fn from_welcome<P: OpenMlsProvider>(
        provider: &P,
        expected_group_id: &[u8],
        expected_credential: &DeviceCredentialInput,
        welcome_wire: &[u8],
    ) -> MlsResult<Self> {
        check_group_id(expected_group_id)?;
        check_wire_size(welcome_wire)?;
        let parsed = parse_message(welcome_wire)?;
        let welcome = match parsed.extract() {
            openmls::prelude::MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(MlsError::UnsupportedMessage),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged =
            openmls::group::StagedWelcome::new_from_welcome(provider, &join_config, welcome, None)
                .map_err(|_| MlsError::OpenMlsFailure)?;

        if staged.group_context().group_id().as_slice() != expected_group_id {
            return Err(MlsError::WrongGroup);
        }
        if staged.members().count() > MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        let expected = &expected_credential.credential_with_key;
        let mut member_identity_fingerprints = HashMap::new();
        for member in staged.members() {
            let signature_key: [u8; 32] = member
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::CredentialKeyMismatch)?;
            let expected_fingerprint = (member.credential.serialized_content()
                == expected.credential.serialized_content())
            .then_some(expected_credential.identity_fingerprint());
            let fingerprint = validate_x509_credential(
                &member.credential,
                &signature_key,
                expected_fingerprint,
                true,
                cfg!(any(test, feature = "test-utils")),
            )?;
            if member_identity_fingerprints
                .insert(signature_key, fingerprint)
                .is_some_and(|existing| existing != fingerprint)
            {
                return Err(MlsError::CredentialValidationFailed);
            }
        }
        let expected_signature_key: [u8; 32] = expected
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| MlsError::CredentialKeyMismatch)?;
        if member_identity_fingerprints.get(&expected_signature_key)
            != Some(expected_credential.identity_fingerprint())
        {
            return Err(MlsError::CredentialKeyMismatch);
        }

        let inner = staged
            .into_group(provider)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        Ok(Self {
            inner,
            incoming_commit: None,
            conflict: None,
            member_identity_fingerprints,
        })
    }

    /// Returns the MLS group identifier bytes.
    #[must_use]
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id().to_vec()
    }

    /// Returns the candidate event-visible reference for this MLS group.
    #[must_use]
    pub fn group_reference(&self) -> [u8; 32] {
        derive_group_reference(self.inner.group_id().as_slice())
    }

    /// Returns the current MLS epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    /// Returns the current MLS member count.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Reports whether a validated current group member has this full identity fingerprint.
    #[must_use]
    pub fn contains_member_identity(&self, fingerprint: &[u8; 32]) -> bool {
        self.member_identity_fingerprints
            .values()
            .any(|member_fingerprint| member_fingerprint == fingerprint)
    }

    /// Returns current state relevant to MLS transitions.
    #[must_use]
    pub fn status(&self) -> GroupStatus {
        if self.conflict.is_some() {
            GroupStatus::Conflicted
        } else if !self.inner.is_active() {
            GroupStatus::Inactive
        } else if self.inner.pending_commit().is_some() {
            GroupStatus::OwnCommitPending
        } else if self.incoming_commit.is_some() {
            GroupStatus::IncomingCommitStaged
        } else {
            GroupStatus::Operational
        }
    }

    /// Returns the locally retained conflict evidence, if competing branches were observed.
    #[must_use]
    pub fn conflict_evidence(&self) -> Option<&ConflictEvidence> {
        self.conflict.as_ref()
    }

    /// Takes the proof for one authenticated membership delta in the staged
    /// incoming Commit.
    ///
    /// The proof is one-shot: once consumed, this group cannot issue another
    /// proof for the staged Commit. It is unavailable after merge or discard.
    #[must_use]
    pub fn take_staged_membership_change(&mut self) -> Option<ValidatedMlsMembershipChange> {
        self.incoming_commit
            .as_mut()
            .and_then(|commit| commit.membership_change.take())
    }

    /// Prepares an add transition from one bounded `KeyPackage` after validating
    /// its leaf certificate chain, Ed25519 SPKI binding, and canonical full
    /// identity fingerprint SAN. Compare
    /// [`PreparedAdd::added_member_identity_fingerprint`] with the invited
    /// target before accepting the prepared Commit.
    ///
    /// # Errors
    ///
    /// Returns state-transition, size, or `OpenMLS` errors, or
    /// [`MlsError::CredentialValidationFailed`] when the incoming package
    /// contains an untrusted, expired, malformed, mismatched, or duplicate
    /// device credential.
    pub fn prepare_add<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        key_package_wire: &[u8],
    ) -> MlsResult<PreparedAdd> {
        self.ensure_operational()?;
        credential.check_signer(identity)?;
        if self.member_count() >= MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        let DecodedKeyPackage {
            key_package,
            signature_key,
            identity_fingerprint,
        } = decode_key_package(provider, key_package_wire)?;
        let key_package_sha256 = Sha256::digest(
            key_package
                .tls_serialize_detached()
                .map_err(|_| MlsError::MalformedMessage)?,
        )
        .into();
        if self
            .member_identity_fingerprints
            .contains_key(&signature_key)
            || self
                .member_identity_fingerprints
                .values()
                .any(|existing| existing == &identity_fingerprint)
        {
            return Err(MlsError::CredentialValidationFailed);
        }
        let (commit, welcome, _) = self
            .inner
            .add_members(provider, &DeviceSigner(identity), &[key_package])
            .map_err(|_| MlsError::OpenMlsFailure)?;
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::OpenMlsFailure);
        }
        Ok(PreparedAdd {
            group_id: self.group_id(),
            parent_epoch: self.inner.epoch(),
            commit: encode_message(&commit, MlsWireKind::Commit)?,
            welcome: encode_message(&welcome, MlsWireKind::Welcome)?,
            added_member_signature_key: signature_key,
            added_member_identity_fingerprint: identity_fingerprint,
            key_package_sha256,
        })
    }

    /// Prepares an MLS Remove for one currently validated member identity.
    ///
    /// The exact Commit remains pending until the caller binds it to an
    /// authorized policy transition and accepts it. A group containing more
    /// than one leaf for the requested fingerprint is rejected rather than
    /// partially removing that identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is not uniquely present, is the local
    /// signer, or the MLS group/provider rejects the operation.
    pub fn prepare_remove<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        target_fingerprint: &[u8; 32],
    ) -> MlsResult<PreparedRemoval> {
        self.ensure_operational()?;
        credential.check_signer(identity)?;
        if target_fingerprint == credential.identity_fingerprint() {
            return Err(MlsError::InvalidInput);
        }
        let mut target = None;
        for member in self.inner.members() {
            let signature_key: [u8; 32] = member
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::CredentialKeyMismatch)?;
            if self.member_identity_fingerprints.get(&signature_key) == Some(target_fingerprint) {
                if target.is_some() {
                    return Err(MlsError::CredentialValidationFailed);
                }
                target = Some((signature_key, member.index));
            }
        }
        let (removed_member_signature_key, leaf_index) =
            target.ok_or(MlsError::GroupMemberNotFound)?;
        let (commit, _, _) = self
            .inner
            .remove_members(provider, &DeviceSigner(identity), &[leaf_index])
            .map_err(|_| MlsError::OpenMlsFailure)?;
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::OpenMlsFailure);
        }
        Ok(PreparedRemoval {
            group_id: self.group_id(),
            parent_epoch: self.inner.epoch(),
            commit: encode_message(&commit, MlsWireKind::Commit)?,
            removed_member_signature_key,
            removed_member_identity_fingerprint: *target_fingerprint,
        })
    }

    /// Merges the exact prepared Commit and releases its Welcome.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Conflicted`], [`MlsError::GroupInactive`],
    /// [`MlsError::InputTooLarge`], [`MlsError::WrongGroup`],
    /// [`MlsError::ParentEpochChanged`], [`MlsError::AcceptanceMismatch`],
    /// [`MlsError::NoOwnCommitPending`], or [`MlsError::OpenMlsFailure`].
    ///
    /// This is the caller's explicit acceptance signal only; it does not perform
    /// Space authorization or coordinate atomically with an application log.
    pub fn accept_prepared_add<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        prepared: &PreparedAdd,
        accepted_commit_wire: &[u8],
    ) -> MlsResult<MlsMessage> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        check_wire_size(accepted_commit_wire)?;
        if prepared.group_id != self.group_id() {
            return Err(MlsError::WrongGroup);
        }
        if prepared.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if prepared.commit.as_bytes() != accepted_commit_wire {
            return Err(MlsError::AcceptanceMismatch);
        }
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::NoOwnCommitPending);
        }
        self.inner
            .merge_pending_commit(provider)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        self.member_identity_fingerprints.insert(
            prepared.added_member_signature_key,
            prepared.added_member_identity_fingerprint,
        );
        Ok(prepared.welcome.clone())
    }

    /// Merges the exact prepared Remove Commit.
    ///
    /// This merges MLS state only; it does not authorize, persist, or replay a
    /// Space removal/ban transition. The caller must bind the exact Commit to
    /// the authorized parent-epoch policy event and persist both atomically
    /// before exposing the resulting state.
    ///
    /// # Errors
    ///
    /// Returns the same exact-Commit and group-state errors as
    /// [`GroupState::accept_prepared_add`].
    pub fn accept_prepared_remove<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        prepared: &PreparedRemoval,
        accepted_commit_wire: &[u8],
    ) -> MlsResult<()> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        check_wire_size(accepted_commit_wire)?;
        if prepared.group_id != self.group_id() {
            return Err(MlsError::WrongGroup);
        }
        if prepared.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if prepared.commit.as_bytes() != accepted_commit_wire {
            return Err(MlsError::AcceptanceMismatch);
        }
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::NoOwnCommitPending);
        }
        self.inner
            .merge_pending_commit(provider)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        self.member_identity_fingerprints
            .remove(&prepared.removed_member_signature_key);
        Ok(())
    }

    /// Encrypts one application payload in the parent epoch while this exact
    /// prepared Add Commit remains pending.
    ///
    /// This supports protocols that require an MLS-authenticated application
    /// transition before the matching membership Commit is merged. The caller
    /// must authorize the resulting plaintext before accepting the Commit.
    ///
    /// # Errors
    ///
    /// Returns an error if the group/epoch differs from `prepared`, no local
    /// Commit is pending, the credential does not match the signer, the payload
    /// exceeds its bound, or `OpenMLS` rejects the message.
    pub fn encrypt_application_for_pending_membership<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        prepared: &PreparedAdd,
        plaintext: &[u8],
    ) -> MlsResult<MlsMessage> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        credential.check_signer(identity)?;
        if prepared.group_id != self.group_id() {
            return Err(MlsError::WrongGroup);
        }
        if prepared.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::NoOwnCommitPending);
        }
        check_application_size(plaintext)?;
        let message = self
            .inner
            .create_message(provider, &DeviceSigner(identity), plaintext)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        encode_message(&message, MlsWireKind::Application)
    }

    /// Encrypts a parent-epoch policy transition while this prepared Remove
    /// Commit remains pending.
    ///
    /// # Errors
    ///
    /// Returns an error when the prepared removal is stale, no local Commit is
    /// pending, credential signing fails, or the payload is rejected.
    pub fn encrypt_application_for_pending_removal<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        prepared: &PreparedRemoval,
        plaintext: &[u8],
    ) -> MlsResult<MlsMessage> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        credential.check_signer(identity)?;
        if prepared.group_id != self.group_id() {
            return Err(MlsError::WrongGroup);
        }
        if prepared.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::NoOwnCommitPending);
        }
        check_application_size(plaintext)?;
        let message = self
            .inner
            .create_message(provider, &DeviceSigner(identity), plaintext)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        encode_message(&message, MlsWireKind::Application)
    }

    /// Encrypts a bounded application payload with the actual `OpenMLS` group state.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Conflicted`], pending/inactive-state errors,
    /// [`MlsError::CredentialKeyMismatch`], [`MlsError::InputTooLarge`], or
    /// [`MlsError::OpenMlsFailure`].
    pub fn encrypt_application<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        plaintext: &[u8],
    ) -> MlsResult<MlsMessage> {
        self.ensure_operational()?;
        credential.check_signer(identity)?;
        check_application_size(plaintext)?;
        let message = self
            .inner
            .create_message(provider, &DeviceSigner(identity), plaintext)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        encode_message(&message, MlsWireKind::Application)
    }

    /// Parses and authenticates one bounded incoming MLS protocol message.
    ///
    /// Commits are staged and never merged implicitly. A future-epoch message is
    /// returned as a typed missing-dependency error; this API has no pending queue.
    ///
    /// # Errors
    ///
    /// Returns an error when the wire is malformed/unsupported, belongs to a
    /// different or unavailable epoch/group, violates a group transition gate,
    /// or is rejected by `OpenMLS` or the provider.
    pub fn process_incoming<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        wire: &[u8],
    ) -> MlsResult<IncomingResult> {
        check_wire_size(wire)?;
        let ciphertext_sha256 = Sha256::digest(wire).into();
        let parsed = parse_message(wire)?;
        let protocol = parsed
            .try_into_protocol_message()
            .map_err(|_| MlsError::UnsupportedMessage)?;
        if protocol.group_id() != self.inner.group_id() {
            return Err(MlsError::WrongGroup);
        }
        let group_reference = self.group_reference();
        let kind = wire_kind(protocol.content_type());
        let current_epoch = self.inner.epoch();
        let received_epoch = protocol.epoch();
        if received_epoch > current_epoch {
            return Err(MlsError::MissingDependency {
                current_epoch: current_epoch.as_u64(),
                received_epoch: received_epoch.as_u64(),
            });
        }
        if received_epoch < current_epoch {
            return Err(MlsError::StaleEpoch {
                current_epoch: current_epoch.as_u64(),
                received_epoch: received_epoch.as_u64(),
            });
        }
        self.ensure_not_conflicted()?;
        self.ensure_active()?;

        if kind == MlsWireKind::Commit {
            if self
                .incoming_commit
                .as_ref()
                .is_some_and(|staged| staged.encoded == wire)
            {
                return Err(MlsError::DuplicateStagedCommit);
            }
            if self.inner.pending_commit().is_some() {
                return Err(MlsError::OwnCommitPending);
            }
        }

        let processed = self
            .inner
            .process_message(provider, protocol)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        let sender = processed.sender().clone();
        let member_signature_key = self.member_signature_key(&sender)?;
        let member_identity_fingerprint = self.member_identity_fingerprint(&sender)?;
        let content = processed.into_content();
        if kind == MlsWireKind::Commit {
            return match content {
                ProcessedMessageContent::StagedCommitMessage(staged) => self.stage_incoming_commit(
                    staged,
                    &sender,
                    member_identity_fingerprint,
                    wire,
                    ciphertext_sha256,
                ),
                other => classify_non_commit(
                    other,
                    member_identity_fingerprint,
                    member_signature_key,
                    ciphertext_sha256,
                    received_epoch.as_u64(),
                    group_reference,
                ),
            };
        }

        classify_non_commit(
            content,
            member_identity_fingerprint,
            member_signature_key,
            ciphertext_sha256,
            received_epoch.as_u64(),
            group_reference,
        )
    }

    fn stage_incoming_commit(
        &mut self,
        staged: Box<StagedCommit>,
        sender: &openmls::prelude::Sender,
        member_identity_fingerprint: Option<[u8; 32]>,
        wire: &[u8],
        ciphertext_sha256: [u8; 32],
    ) -> MlsResult<IncomingResult> {
        let changes = self.validate_staged_credentials(&staged, sender)?;
        let membership_change = self.validated_membership_change(
            &staged,
            member_identity_fingerprint,
            &changes.identity_fingerprints_to_add,
            ciphertext_sha256,
        )?;
        if let Some(existing) = self.incoming_commit.take() {
            let parent_epoch = existing.parent_epoch.as_u64();
            self.conflict = Some(ConflictEvidence {
                parent_epoch,
                first_commit: existing.encoded,
                second_commit: bounded_copy(wire)?,
                first_membership_change: existing.membership_change,
                second_membership_change: membership_change,
            });
            return Err(MlsError::ConflictDetected { parent_epoch });
        }

        let resulting_members = self
            .member_count()
            .saturating_add(staged.add_proposals().count())
            .saturating_sub(staged.remove_proposals().count());
        if resulting_members > MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        let parent_epoch = self.inner.epoch();
        self.incoming_commit = Some(IncomingCommit {
            staged: *staged,
            encoded: bounded_copy(wire)?,
            parent_epoch,
            identity_keys_to_remove: changes.identity_keys_to_remove,
            identity_fingerprints_to_add: changes.identity_fingerprints_to_add,
            membership_change,
        });
        Ok(IncomingResult::StagedCommit {
            parent_epoch: parent_epoch.as_u64(),
            space_authorization: SpaceAuthorization::NotEvaluated,
        })
    }

    /// Merges the exact staged incoming Commit after explicit caller acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Conflicted`], [`MlsError::GroupInactive`],
    /// [`MlsError::InputTooLarge`], [`MlsError::NoStagedCommit`],
    /// [`MlsError::ParentEpochChanged`], [`MlsError::AcceptanceMismatch`], or
    /// [`MlsError::OpenMlsFailure`].
    pub fn accept_incoming_commit<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        accepted_commit_wire: &[u8],
    ) -> MlsResult<()> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        check_wire_size(accepted_commit_wire)?;
        let staged = self
            .incoming_commit
            .as_ref()
            .ok_or(MlsError::NoStagedCommit)?;
        if staged.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if staged.encoded != accepted_commit_wire {
            return Err(MlsError::AcceptanceMismatch);
        }
        let staged = self
            .incoming_commit
            .take()
            .ok_or(MlsError::NoStagedCommit)?;
        self.inner
            .merge_staged_commit(provider, staged.staged)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        for signature_key in staged.identity_keys_to_remove {
            self.member_identity_fingerprints.remove(&signature_key);
        }
        self.member_identity_fingerprints
            .extend(staged.identity_fingerprints_to_add);
        Ok(())
    }

    fn ensure_operational(&self) -> MlsResult<()> {
        match self.status() {
            GroupStatus::Operational => Ok(()),
            GroupStatus::OwnCommitPending => Err(MlsError::OwnCommitPending),
            GroupStatus::IncomingCommitStaged => Err(MlsError::IncomingCommitPending),
            GroupStatus::Conflicted => Err(MlsError::Conflicted),
            GroupStatus::Inactive => Err(MlsError::GroupInactive),
        }
    }

    fn ensure_active(&self) -> MlsResult<()> {
        if self.inner.is_active() {
            Ok(())
        } else {
            Err(MlsError::GroupInactive)
        }
    }

    fn ensure_not_conflicted(&self) -> MlsResult<()> {
        if self.conflict.is_some() {
            Err(MlsError::Conflicted)
        } else {
            Ok(())
        }
    }
    fn member_signature_key_by_index(&self, index: LeafNodeIndex) -> MlsResult<[u8; 32]> {
        let member = self
            .inner
            .members()
            .find(|member| member.index == index)
            .ok_or(MlsError::SenderKeyUnavailable)?;
        member
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| MlsError::SenderKeyUnavailable)
    }

    fn changed_leaf_candidate(leaf: &LeafNode) -> MlsResult<StagedCredentialCandidate> {
        let signature_key = leaf
            .signature_key()
            .as_slice()
            .try_into()
            .map_err(|_| MlsError::CredentialKeyMismatch)?;
        Ok(StagedCredentialCandidate {
            credential: leaf.credential().clone(),
            signature_key,
            is_member: true,
        })
    }

    fn validate_staged_credentials(
        &self,
        staged: &StagedCommit,
        commit_sender: &openmls::prelude::Sender,
    ) -> MlsResult<StagedCredentialChanges> {
        let mut keys_to_remove = Vec::new();
        let mut candidates = Vec::new();
        if let Some(leaf) = staged.update_path_leaf_node() {
            if let Some(old_key) = self.member_signature_key(commit_sender)? {
                keys_to_remove.push(old_key);
            }
            candidates.push(Self::changed_leaf_candidate(leaf)?);
        }
        for update in staged.update_proposals() {
            let old_key = self
                .member_signature_key(update.sender())?
                .ok_or(MlsError::SenderKeyUnavailable)?;
            keys_to_remove.push(old_key);
            candidates.push(Self::changed_leaf_candidate(
                update.update_proposal().leaf_node(),
            )?);
        }
        for add in staged.add_proposals() {
            candidates.push(Self::changed_leaf_candidate(
                add.add_proposal().key_package().leaf_node(),
            )?);
        }
        for remove in staged.remove_proposals() {
            keys_to_remove
                .push(self.member_signature_key_by_index(remove.remove_proposal().removed())?);
        }
        for queued in staged.queued_proposals() {
            let Proposal::GroupContextExtensions(proposal) = queued.proposal() else {
                continue;
            };
            for extension in proposal.extensions().iter() {
                let Extension::ExternalSenders(external_senders) = extension else {
                    continue;
                };
                for external_sender in external_senders {
                    let encoded = external_sender
                        .tls_serialize_detached()
                        .map_err(|_| MlsError::MalformedMessage)?;
                    let mut bytes = encoded.as_slice();
                    let signature_key = VLBytes::tls_deserialize(&mut bytes)
                        .map_err(|_| MlsError::MalformedMessage)?;
                    let credential = Credential::tls_deserialize(&mut bytes)
                        .map_err(|_| MlsError::MalformedMessage)?;
                    if !bytes.is_empty() {
                        return Err(MlsError::MalformedMessage);
                    }
                    let signature_key = signature_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| MlsError::CredentialKeyMismatch)?;
                    candidates.push(StagedCredentialCandidate {
                        credential,
                        signature_key,
                        is_member: false,
                    });
                }
            }
        }

        let mut seen_credentials = vec![false; candidates.len()];
        let mut fingerprints_to_add = Vec::new();
        for credential in staged.credentials_to_verify() {
            let candidate_index = candidates
                .iter()
                .enumerate()
                .position(|(index, candidate)| {
                    !seen_credentials[index] && candidate.credential == *credential
                })
                .ok_or(MlsError::CredentialValidationFailed)?;
            seen_credentials[candidate_index] = true;
            let candidate = &candidates[candidate_index];
            let identity_fingerprint = validate_x509_credential(
                credential,
                &candidate.signature_key,
                None,
                true,
                cfg!(any(test, feature = "test-utils")),
            )?;
            if candidate.is_member {
                fingerprints_to_add.push((candidate.signature_key, identity_fingerprint));
            }
        }
        if seen_credentials.iter().any(|seen| !seen) {
            return Err(MlsError::CredentialValidationFailed);
        }

        let mut seen = HashMap::with_capacity(fingerprints_to_add.len());
        for (signature_key, fingerprint) in &fingerprints_to_add {
            if seen.insert(*signature_key, *fingerprint).is_some()
                || (self
                    .member_identity_fingerprints
                    .contains_key(signature_key)
                    && !keys_to_remove.contains(signature_key))
            {
                return Err(MlsError::CredentialValidationFailed);
            }
        }
        Ok(StagedCredentialChanges {
            identity_keys_to_remove: keys_to_remove,
            identity_fingerprints_to_add: fingerprints_to_add,
        })
    }

    fn member_identity_fingerprint(
        &self,
        sender: &openmls::prelude::Sender,
    ) -> MlsResult<Option<[u8; 32]>> {
        self.member_signature_key(sender)?
            .map(|signature_key| {
                self.member_identity_fingerprints
                    .get(&signature_key)
                    .copied()
                    .ok_or(MlsError::SenderKeyUnavailable)
            })
            .transpose()
    }

    fn member_signature_key(
        &self,
        sender: &openmls::prelude::Sender,
    ) -> MlsResult<Option<[u8; 32]>> {
        match sender {
            openmls::prelude::Sender::Member(index) => {
                self.member_signature_key_by_index(*index).map(Some)
            }
            _ => Ok(None),
        }
    }
    fn validated_membership_change(
        &self,
        staged: &StagedCommit,
        author: Option<[u8; 32]>,
        identity_fingerprints_to_add: &[([u8; 32], [u8; 32])],
        commit_sha256: [u8; 32],
    ) -> MlsResult<Option<ValidatedMlsMembershipChange>> {
        let adds = staged.add_proposals().count();
        let removes = staged.remove_proposals().count();
        let (action, target, key_package_hash) = match (adds, removes) {
            (1, 0) => {
                let add = staged
                    .add_proposals()
                    .next()
                    .ok_or(MlsError::OpenMlsFailure)?;
                let key_package = add.add_proposal().key_package();
                let signature_key: [u8; 32] = key_package
                    .leaf_node()
                    .signature_key()
                    .as_slice()
                    .try_into()
                    .map_err(|_| MlsError::CredentialKeyMismatch)?;
                let target = identity_fingerprints_to_add
                    .iter()
                    .find(|(key, _)| key == &signature_key)
                    .map(|(_, fingerprint)| *fingerprint)
                    .ok_or(MlsError::CredentialValidationFailed)?;
                let key_package_bytes = key_package
                    .tls_serialize_detached()
                    .map_err(|_| MlsError::MalformedMessage)?;
                (
                    MlsMembershipAction::Add,
                    target,
                    Some(Sha256::digest(key_package_bytes).into()),
                )
            }
            (0, 1) => {
                let remove = staged
                    .remove_proposals()
                    .next()
                    .ok_or(MlsError::OpenMlsFailure)?;
                let signature_key =
                    self.member_signature_key_by_index(remove.remove_proposal().removed())?;
                let target = *self
                    .member_identity_fingerprints
                    .get(&signature_key)
                    .ok_or(MlsError::SenderKeyUnavailable)?;
                (MlsMembershipAction::Remove, target, None)
            }
            _ => return Ok(None),
        };
        let Some(author) = author else {
            return Ok(None);
        };
        Ok(Some(ValidatedMlsMembershipChange {
            group_reference: self.group_reference(),
            parent_epoch: self.inner.epoch().as_u64(),
            author,
            commit_sha256,
            action,
            target,
            key_package_hash,
        }))
    }
}

fn check_wire_size(wire: &[u8]) -> MlsResult<()> {
    if wire.is_empty() {
        return Err(MlsError::InvalidInput);
    }
    if wire.len() > MAX_MLS_WIRE_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "MLS wire message",
            maximum: MAX_MLS_WIRE_BYTES,
            actual: wire.len(),
        });
    }
    Ok(())
}

fn check_group_id(group_id: &[u8]) -> MlsResult<()> {
    if group_id.is_empty() {
        return Err(MlsError::InvalidInput);
    }
    if group_id.len() > MAX_GROUP_ID_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "MLS group identifier",
            maximum: MAX_GROUP_ID_BYTES,
            actual: group_id.len(),
        });
    }
    Ok(())
}

fn check_application_size(plaintext: &[u8]) -> MlsResult<()> {
    if plaintext.len() > MAX_APPLICATION_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "MLS application plaintext",
            maximum: MAX_APPLICATION_BYTES,
            actual: plaintext.len(),
        });
    }
    Ok(())
}

fn bounded_copy(bytes: &[u8]) -> MlsResult<Vec<u8>> {
    check_wire_size(bytes)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| MlsError::OpenMlsFailure)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn parse_message(wire: &[u8]) -> MlsResult<MlsMessageIn> {
    check_wire_size(wire)?;
    MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| MlsError::MalformedMessage)
}

/// Hashes the exact TLS serialization of one bounded MLS `KeyPackage`.
///
/// The digest excludes the enclosing `MlsMessage` framing. It does not validate
/// the package's credential trust or membership target. Callers must still use
/// [`GroupState::prepare_add`] before accepting the package.
///
/// # Errors
///
/// Returns an error when the input is oversized, malformed, or is not a
/// `KeyPackage` MLS message.
pub fn key_package_wire_sha256(wire: &[u8]) -> MlsResult<[u8; 32]> {
    let parsed = parse_message(wire)?;
    let openmls::prelude::MlsMessageBodyIn::KeyPackage(key_package) = parsed.extract() else {
        return Err(MlsError::UnsupportedMessage);
    };
    let encoded = key_package
        .tls_serialize_detached()
        .map_err(|_| MlsError::MalformedMessage)?;
    Ok(Sha256::digest(encoded).into())
}
/// Returns the native MLS `KeyPackage` reference and expiry from a
/// `KeyPackage` message.
///
/// The reference is the suite-defined MLS hash reference, not a digest of the
/// outer message or TLS bytes.
///
/// # Errors
///
/// Returns an error for an oversized, malformed, unsupported, or invalid
/// `KeyPackage`.
pub fn key_package_lifecycle_metadata<P: OpenMlsProvider>(
    provider: &P,
    wire: &[u8],
) -> MlsResult<([u8; 32], u64)> {
    let parsed = parse_message(wire)?;
    let key_package: KeyPackageIn = match parsed.extract() {
        openmls::prelude::MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => return Err(MlsError::UnsupportedMessage),
    };
    let key_package = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| MlsError::OpenMlsFailure)?;
    let reference = key_package
        .hash_ref(provider.crypto())
        .map_err(|_| MlsError::OpenMlsFailure)?;
    let reference = reference
        .as_slice()
        .try_into()
        .map_err(|_| MlsError::OpenMlsFailure)?;
    Ok((reference, key_package.life_time().not_after()))
}

/// Deletes the local private bundle for a published `KeyPackage`.
///
/// Returns its suite-defined reference so the caller can update the app
/// inventory in the same provider transaction.
///
/// # Errors
///
/// Returns an error for invalid package data or provider storage failures.
pub fn delete_key_package_bundle<P: OpenMlsProvider>(
    provider: &P,
    wire: &[u8],
) -> MlsResult<[u8; 32]> {
    let parsed = parse_message(wire)?;
    let key_package: KeyPackageIn = match parsed.extract() {
        openmls::prelude::MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => return Err(MlsError::UnsupportedMessage),
    };
    let key_package = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| MlsError::OpenMlsFailure)?;
    let reference = key_package
        .hash_ref(provider.crypto())
        .map_err(|_| MlsError::OpenMlsFailure)?;
    let reference_bytes = reference
        .as_slice()
        .try_into()
        .map_err(|_| MlsError::OpenMlsFailure)?;
    provider
        .storage()
        .delete_key_package(&reference)
        .map_err(|_| MlsError::OpenMlsFailure)?;
    Ok(reference_bytes)
}

/// Finds the `KeyPackage` reference in a `Welcome` for which this provider holds
/// the corresponding private bundle.
///
/// # Errors
///
/// Returns an error for malformed Welcome data or provider storage failures.
pub fn welcome_key_package_reference<P: OpenMlsProvider>(
    provider: &P,
    wire: &[u8],
) -> MlsResult<Option<[u8; 32]>> {
    let parsed = parse_message(wire)?;
    let openmls::prelude::MlsMessageBodyIn::Welcome(welcome) = parsed.extract() else {
        return Err(MlsError::UnsupportedMessage);
    };
    for encrypted_secrets in welcome.secrets() {
        let reference = encrypted_secrets.new_member();
        if provider
            .storage()
            .key_package::<_, openmls::key_packages::KeyPackageBundle>(&reference)
            .map_err(|_| MlsError::OpenMlsFailure)?
            .is_some()
        {
            let reference = reference
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::OpenMlsFailure)?;
            return Ok(Some(reference));
        }
    }
    Ok(None)
}

struct DecodedKeyPackage {
    key_package: KeyPackage,
    signature_key: [u8; 32],
    identity_fingerprint: [u8; 32],
}

fn decode_key_package<P: OpenMlsProvider>(
    provider: &P,
    wire: &[u8],
) -> MlsResult<DecodedKeyPackage> {
    let parsed = parse_message(wire)?;
    let key_package: KeyPackageIn = match parsed.extract() {
        openmls::prelude::MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => return Err(MlsError::UnsupportedMessage),
    };
    let key_package = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| MlsError::OpenMlsFailure)?;
    let leaf = key_package.leaf_node();
    let signature_key: [u8; 32] = leaf
        .signature_key()
        .as_slice()
        .try_into()
        .map_err(|_| MlsError::CredentialKeyMismatch)?;
    let identity_fingerprint = validate_x509_credential(
        leaf.credential(),
        &signature_key,
        None,
        true,
        cfg!(any(test, feature = "test-utils")),
    )?;
    Ok(DecodedKeyPackage {
        key_package,
        signature_key,
        identity_fingerprint,
    })
}

fn encode_message(message: &MlsMessageOut, kind: MlsWireKind) -> MlsResult<MlsMessage> {
    let bytes = message.to_bytes().map_err(|_| MlsError::OpenMlsFailure)?;
    check_wire_size(&bytes)?;
    Ok(MlsMessage { bytes, kind })
}

fn x509_capabilities() -> Capabilities {
    Capabilities::builder()
        .credentials(vec![CredentialType::X509])
        .build()
}

fn wire_kind(content_type: ContentType) -> MlsWireKind {
    match content_type {
        ContentType::Application => MlsWireKind::Application,
        ContentType::Proposal => MlsWireKind::Proposal,
        ContentType::Commit => MlsWireKind::Commit,
    }
}

fn derive_group_reference(group_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MLS_GROUP_REFERENCE_DOMAIN);
    hasher.update(group_id);
    hasher.finalize().into()
}
fn classify_non_commit(
    content: ProcessedMessageContent,
    member_identity_fingerprint: Option<[u8; 32]>,
    member_signature_key: Option<[u8; 32]>,
    ciphertext_sha256: [u8; 32],
    epoch: u64,
    group_reference: [u8; 32],
) -> MlsResult<IncomingResult> {
    match content {
        ProcessedMessageContent::ApplicationMessage(message) => {
            let plaintext = message.into_bytes();
            check_application_size(&plaintext)?;
            Ok(IncomingResult::Application(MlsApplication {
                plaintext,
                member_signature_key,
                member_identity_fingerprint,
                ciphertext_sha256,
                epoch,
                group_reference,
            }))
        }
        ProcessedMessageContent::ProposalMessage(_) => Ok(IncomingResult::Proposal {
            external: false,
            space_authorization: SpaceAuthorization::NotEvaluated,
        }),
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(IncomingResult::Proposal {
            external: true,
            space_authorization: SpaceAuthorization::NotEvaluated,
        }),
        _ => Err(MlsError::UnsupportedMessage),
    }
}
#[cfg(test)]
mod credential_san_tests {
    use super::{identity_uri, validate_identity_san};

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 128 {
            encoded.push(u8::try_from(content.len()).expect("short DER length fits"));
        } else {
            let length_bytes = content.len().to_be_bytes();
            let first = length_bytes
                .iter()
                .position(|byte| *byte != 0)
                .expect("positive DER length has a nonzero byte");
            let length_bytes = &length_bytes[first..];
            encoded.push(0x80 | u8::try_from(length_bytes.len()).expect("usize width fits"));
            encoded.extend_from_slice(length_bytes);
        }
        encoded.extend_from_slice(content);
        encoded
    }

    fn certificate_with_identity_uris(uris: &[Vec<u8>]) -> Vec<u8> {
        let mut general_names = Vec::new();
        for uri in uris {
            general_names.extend_from_slice(&der(0x86, uri));
        }
        let san = der(0x30, &general_names);
        let mut extension = der(0x06, &[0x55, 0x1d, 0x11]);
        extension.extend_from_slice(&der(0x04, &san));
        let extension = der(0x30, &extension);
        let extensions = der(0x30, &extension);
        let extensions = der(0xa3, &extensions);

        let mut tbs = der(0x02, &[1]);
        for _ in 0..5 {
            tbs.extend_from_slice(&der(0x30, &[]));
        }
        tbs.extend_from_slice(&extensions);
        let tbs = der(0x30, &tbs);
        let mut certificate = tbs;
        certificate.extend_from_slice(&der(0x30, &[]));
        certificate.extend_from_slice(&der(0x03, &[0]));
        der(0x30, &certificate)
    }
    fn certificate_for_identity(identity: &lattice_identity::DeviceIdentity) -> Vec<u8> {
        let algorithm = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));
        let common_name = der(0x30, &{
            let mut attribute = der(0x06, &[0x55, 0x04, 0x03]);
            attribute.extend_from_slice(&der(0x0c, b"lattice-test"));
            attribute
        });
        let issuer = der(0x30, &der(0x31, &common_name));
        let mut validity = der(0x17, b"000101000000Z");
        validity.extend_from_slice(&der(0x17, b"490101000000Z"));
        let validity = der(0x30, &validity);
        let mut subject_public_key = vec![0];
        subject_public_key.extend_from_slice(&identity.public_key());
        let mut subject_public_key_info = algorithm.clone();
        subject_public_key_info.extend_from_slice(&der(0x03, &subject_public_key));
        let subject_public_key_info = der(0x30, &subject_public_key_info);

        let san = der(0x30, &der(0x86, &uri(&identity.fingerprint())));
        let mut san_extension = der(0x06, &[0x55, 0x1d, 0x11]);
        san_extension.extend_from_slice(&der(0x04, &san));
        let san_extension = der(0x30, &san_extension);
        let extensions = der(0xa3, &der(0x30, &san_extension));

        let mut tbs = der(0xa0, &der(0x02, &[2]));
        tbs.extend_from_slice(&der(0x02, &[1]));
        tbs.extend_from_slice(&algorithm);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&subject_public_key_info);
        tbs.extend_from_slice(&extensions);
        let tbs = der(0x30, &tbs);
        let signature = identity.sign(&tbs);
        let mut signature_bits = vec![0];
        signature_bits.extend_from_slice(&signature);
        let mut certificate = tbs;
        certificate.extend_from_slice(&algorithm);
        certificate.extend_from_slice(&der(0x03, &signature_bits));
        der(0x30, &certificate)
    }

    #[test]
    fn rejects_a_parseable_self_signed_but_untrusted_certificate() {
        use openmls::credentials::{Credential, CredentialType};
        use openmls::prelude::tls_codec::{Serialize as TlsSerialize, VLBytes};

        let identity = lattice_identity::DeviceIdentity::generate()
            .expect("test device identity generation succeeds");
        let certificates = vec![VLBytes::new(certificate_for_identity(&identity))];
        let content = certificates
            .tls_serialize_detached()
            .expect("RFC 9420 certificate vector encodes");
        let credential = Credential::new(CredentialType::X509, content);

        assert_eq!(
            super::DeviceCredentialInput::from_x509_credential(&identity, credential).unwrap_err(),
            super::MlsError::CredentialValidationFailed
        );
    }

    fn uri(fingerprint: &[u8; 32]) -> Vec<u8> {
        identity_uri(fingerprint).into_bytes()
    }

    #[test]
    fn accepts_one_canonical_lowercase_fingerprint_uri() {
        let fingerprint = [0xab; 32];
        let certificate = certificate_with_identity_uris(&[uri(&fingerprint)]);
        assert_eq!(
            validate_identity_san(&certificate, Some(&fingerprint)),
            Ok(fingerprint)
        );
        let other_fingerprint = [0xcd; 32];
        assert!(validate_identity_san(&certificate, Some(&other_fingerprint)).is_err());
    }

    #[test]
    fn rejects_uppercase_and_noncanonical_identity_uris() {
        let fingerprint = [0xab; 32];
        let canonical = uri(&fingerprint);
        let uppercase_prefix = canonical
            .iter()
            .map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>();
        let mut uppercase_hex = canonical.clone();
        *uppercase_hex.last_mut().expect("fingerprint has hex bytes") = b'B';
        let mut trailing_data = canonical;
        trailing_data.push(b'/');

        for value in [uppercase_prefix, uppercase_hex, trailing_data] {
            let certificate = certificate_with_identity_uris(&[value]);
            assert!(validate_identity_san(&certificate, None).is_err());
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_conflicting_identity_uris() {
        let fingerprint = [0xab; 32];
        let other_fingerprint = [0xcd; 32];
        let missing = certificate_with_identity_uris(&[]);
        let duplicate = uri(&fingerprint);
        let duplicated = certificate_with_identity_uris(&[duplicate.clone(), duplicate]);
        let conflicting =
            certificate_with_identity_uris(&[uri(&fingerprint), uri(&other_fingerprint)]);

        assert!(validate_identity_san(&missing, Some(&fingerprint)).is_err());
        assert!(validate_identity_san(&duplicated, Some(&fingerprint)).is_err());
        assert!(validate_identity_san(&conflicting, None).is_err());
    }
}

#[cfg(test)]
mod group_reference_tests {
    use super::{MLS_GROUP_REFERENCE_DOMAIN, derive_group_reference};

    const VECTOR: &str = include_str!("../../../protocol/vectors/mls-group-reference.txt");

    fn vector_field(name: &str) -> &str {
        VECTOR
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(" = "))
            .expect("published vector field exists")
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("vector is ASCII");
                u8::from_str_radix(pair, 16).expect("vector field is hexadecimal")
            })
            .collect()
    }

    #[test]
    fn candidate_group_reference_matches_shared_vector() {
        let domain = vector_field("domain").as_bytes();
        assert_eq!(MLS_GROUP_REFERENCE_DOMAIN.strip_suffix(&[0]), Some(domain));
        let group_id = decode_hex(vector_field("group_id_hex"));
        let expected: [u8; 32] = decode_hex(vector_field("group_reference_hex"))
            .try_into()
            .expect("reference is exactly 32 bytes");
        assert_eq!(derive_group_reference(&group_id), expected);
    }
}
#[cfg(test)]
mod membership_change_tests {
    use super::{
        DeviceCredentialInput, GroupState, IncomingResult, MlsMembershipAction,
        ValidatedMlsMembershipChange, key_package_wire_sha256,
    };
    use lattice_identity::DeviceIdentity;
    use openmls::credentials::{Credential, CredentialType};
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use sha2::{Digest, Sha256};

    fn test_credential(identity: &DeviceIdentity) -> DeviceCredentialInput {
        let credential = Credential::new(
            CredentialType::X509,
            b"test-only untrusted X.509 placeholder".to_vec(),
        );
        DeviceCredentialInput::from_untrusted_x509_credential_for_tests(identity, &credential)
            .expect("test credential matches the device signer")
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One scenario covers add, exact removal proof, and rekey exclusion.
    fn staged_add_and_remove_proofs_bind_exact_membership_changes() {
        let provider_alice = OpenMlsRustCrypto::default();
        let provider_charlie = OpenMlsRustCrypto::default();
        let provider_bob = OpenMlsRustCrypto::default();
        let alice_identity = DeviceIdentity::generate().expect("Alice identity");
        let bob_identity = DeviceIdentity::generate().expect("Bob identity");
        let charlie_identity = DeviceIdentity::generate().expect("Charlie identity");
        let alice_credential = test_credential(&alice_identity);
        let bob_credential = test_credential(&bob_identity);
        let charlie_credential = test_credential(&charlie_identity);

        let mut alice = GroupState::create(&provider_alice, &alice_identity, &alice_credential)
            .expect("create Alice group");
        let bob_key_package =
            GroupState::publish_key_package(&provider_bob, &bob_identity, &bob_credential)
                .expect("publish Bob KeyPackage");
        let bob_add = alice
            .prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                bob_key_package.as_bytes(),
            )
            .expect("prepare Bob add");
        let group_id = alice.group_id();
        let bob_welcome = alice
            .accept_prepared_add(&provider_alice, &bob_add, bob_add.commit().as_bytes())
            .expect("accept Bob add");
        let mut bob = GroupState::from_welcome(
            &provider_bob,
            &group_id,
            &bob_credential,
            bob_welcome.as_bytes(),
        )
        .expect("join Alice group");

        let charlie_key_package = GroupState::publish_key_package(
            &provider_charlie,
            &charlie_identity,
            &charlie_credential,
        )
        .expect("publish Charlie KeyPackage");
        let charlie_add = alice
            .prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                charlie_key_package.as_bytes(),
            )
            .expect("prepare Charlie add");
        let charlie_package_hash = key_package_wire_sha256(charlie_key_package.as_bytes())
            .expect("published KeyPackage has a bounded supported encoding");
        assert_eq!(charlie_add.key_package_sha256(), &charlie_package_hash);
        let commit = charlie_add.commit().as_bytes();
        let commit_sha256: [u8; 32] = Sha256::digest(commit).into();
        assert!(matches!(
            bob.process_incoming(&provider_bob, commit),
            Ok(IncomingResult::StagedCommit {
                parent_epoch: 1,
                ..
            })
        ));

        let change: ValidatedMlsMembershipChange = bob
            .take_staged_membership_change()
            .expect("one validated Add produces a typed relation");
        assert_eq!(change.group_reference(), &alice.group_reference());
        assert_eq!(change.parent_epoch(), 1);
        assert_eq!(change.author(), &alice_identity.fingerprint());
        assert_eq!(change.commit_sha256(), &commit_sha256);
        assert_eq!(change.action(), MlsMembershipAction::Add);
        assert_eq!(change.target(), &charlie_identity.fingerprint());
        assert_eq!(change.key_package_hash(), Some(&charlie_package_hash));
        assert!(!change.matches_commit_wire(&[0]));

        bob.accept_incoming_commit(&provider_bob, commit)
            .expect("merge exact staged Commit");
        assert!(bob.take_staged_membership_change().is_none());
        let charlie_welcome = alice
            .accept_prepared_add(
                &provider_alice,
                &charlie_add,
                charlie_add.commit().as_bytes(),
            )
            .expect("accept exact Charlie add on Alice");
        let mut charlie = GroupState::from_welcome(
            &provider_charlie,
            &group_id,
            &charlie_credential,
            charlie_welcome.as_bytes(),
        )
        .expect("Charlie joins before removal");
        let duplicate_charlie_package = GroupState::publish_key_package(
            &provider_alice,
            &charlie_identity,
            &charlie_credential,
        )
        .expect("publish second package for the same identity");
        assert!(matches!(
            alice.prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                duplicate_charlie_package.as_bytes(),
            ),
            Err(super::MlsError::CredentialValidationFailed)
        ));
        let prepared_remove = alice
            .prepare_remove(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                &charlie_identity.fingerprint(),
            )
            .expect("prepare authenticated Charlie removal");
        assert_eq!(prepared_remove.parent_epoch(), 2);
        assert_eq!(
            prepared_remove.removed_member_identity_fingerprint(),
            &charlie_identity.fingerprint()
        );
        let remove_commit = prepared_remove.commit().as_bytes().to_vec();
        let parent_transition = alice
            .encrypt_application_for_pending_removal(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                &prepared_remove,
                b"ban policy transition",
            )
            .expect("authenticate parent-epoch policy transition");
        assert!(matches!(
            bob.process_incoming(&provider_bob, parent_transition.as_bytes()),
            Ok(IncomingResult::Application(application))
                if application.plaintext() == b"ban policy transition"
        ));
        alice
            .accept_prepared_remove(&provider_alice, &prepared_remove, &remove_commit)
            .expect("merge exact removal Commit");
        assert_eq!(alice.epoch(), 3);
        assert!(!alice.contains_member_identity(&charlie_identity.fingerprint()));
        assert!(matches!(
            bob.process_incoming(&provider_bob, &remove_commit),
            Ok(IncomingResult::StagedCommit {
                parent_epoch: 2,
                ..
            })
        ));
        let removal: ValidatedMlsMembershipChange = bob
            .take_staged_membership_change()
            .expect("Remove Commit produces a typed rekey proof");
        assert_eq!(removal.action(), MlsMembershipAction::Remove);
        assert_eq!(removal.parent_epoch(), 2);
        assert_eq!(removal.author(), &alice_identity.fingerprint());
        assert_eq!(removal.target(), &charlie_identity.fingerprint());
        assert_eq!(removal.key_package_hash(), None);
        assert!(removal.matches_commit_wire(&remove_commit));
        bob.accept_incoming_commit(&provider_bob, &remove_commit)
            .expect("merge exact removal Commit on remaining member");
        assert_eq!(bob.epoch(), 3);
        assert!(!bob.contains_member_identity(&charlie_identity.fingerprint()));
        let future_epoch_message = alice
            .encrypt_application(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                b"post-removal epoch data",
            )
            .expect("encrypt with fresh post-removal epoch");
        assert!(matches!(
            bob.process_incoming(&provider_bob, future_epoch_message.as_bytes()),
            Ok(IncomingResult::Application(application))
                if application.plaintext() == b"post-removal epoch data"
        ));
        assert!(
            charlie
                .process_incoming(&provider_charlie, future_epoch_message.as_bytes())
                .is_err()
        );
    }
    #[test]
    fn control_binding_consumes_only_exact_staged_context() {
        let group_reference = [0x11; 32];
        let parent_epoch = 7;
        let author = [0x22; 32];
        let target = [0x33; 32];
        let key_package_hash = [0x44; 32];
        let commit_wire = b"exact authenticated Commit";
        let make_proof = || ValidatedMlsMembershipChange {
            group_reference,
            parent_epoch,
            author,
            commit_sha256: Sha256::digest(commit_wire).into(),
            action: MlsMembershipAction::Add,
            target,
            key_package_hash: Some(key_package_hash),
        };

        assert!(
            make_proof()
                .into_control_binding(&[0x55; 32], parent_epoch, &author, commit_wire)
                .is_none()
        );
        assert!(
            make_proof()
                .into_control_binding(&group_reference, parent_epoch + 1, &author, commit_wire)
                .is_none()
        );
        assert!(
            make_proof()
                .into_control_binding(&group_reference, parent_epoch, &[0x66; 32], commit_wire)
                .is_none()
        );
        assert!(
            make_proof()
                .into_control_binding(&group_reference, parent_epoch, &author, b"different Commit",)
                .is_none()
        );

        let binding = make_proof()
            .into_control_binding(&group_reference, parent_epoch, &author, commit_wire)
            .expect("exact proof context produces one control binding");
        assert_eq!(binding.action(), MlsMembershipAction::Add);
        assert_eq!(binding.target(), &target);
        assert_eq!(binding.key_package_hash(), Some(&key_package_hash));
    }
}
