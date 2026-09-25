//! Candidate, immutable, signature-checked Lattice event encoding.
//!
//! This is an explicitly versioned candidate profile, not a frozen
//! interoperability standard. Event signatures establish device-key
//! possession only: they do not establish Space/channel authorization, MLS
//! validity, content decryption, or acceptance by any policy reducer.
//!
//! The candidate unsigned-preimage map uses these exact ascending integer
//! keys: `0` format version (`1`); `1` 16-byte Space ID; `2` channel ID (null
//! or 16 bytes); `3` 32-byte author device fingerprint; `4` positive author
//! sequence; `5` Lamport value; `6` non-authoritative wall-time hint in
//! milliseconds; `7` up to 64 unique parent event IDs (32 bytes each), sorted
//! in ascending byte order; `8` numeric mandatory event kind; `9` opaque
//! caller-supplied protected-body bytes; `10` 32-byte opaque MLS group
//! reference; and `11` MLS epoch.
//!
//! Event kind `10` is reserved for encrypted ephemeral presence/typing hints;
//! callers must keep those records out of durable history and store-forward.
//!
//! The outer canonical CBOR map uses exact ascending keys: `0` outer format
//! version (`1`); `1` the exact encoded unsigned preimage as a byte string;
//! `2` the exact versioned 65-byte `IdentityPublicBundle`; and `3` the
//! 64-byte Ed25519 signature over
//! `b"lattice:event-signature:v1\0" || preimage`. Event IDs come from
//! `lattice_protocol::EventId::from_preimage` applied to those exact preimage
//! bytes. Verified instances retain both byte strings and return the original
//! outer bytes from `encode`, rather than recoding historical preimages.
//!
//! `protected_body` must already be protected ciphertext supplied by the
//! caller. This crate does not encrypt, decrypt, parse, or expose plaintext.

use core::fmt;

use lattice_identity::{DeviceIdentity, IdentityError, IdentityPublicBundle, verify};
use lattice_protocol::{EventId, Value, decode_canonical, encode_canonical};

/// Candidate event-format version embedded in every unsigned preimage.
pub const EVENT_VERSION: u64 = 1;
/// Candidate outer-event encoding version.
pub const OUTER_EVENT_VERSION: u64 = 1;
/// Maximum number of parent event IDs in a candidate event.
pub const MAX_PARENTS: usize = 64;
/// Maximum caller-supplied protected ciphertext size.
pub const MAX_PROTECTED_BODY_BYTES: usize = 240 * 1024;
/// Domain prefix included in the Ed25519 signed message.
pub const EVENT_SIGNATURE_DOMAIN: &[u8] = b"lattice:event-signature:v1\0";
/// Exact fixed-width identity bundle size used by the outer event.
pub const IDENTITY_BUNDLE_BYTES: usize = 65;
/// Exact Ed25519 signature size used by the outer event.
pub const SIGNATURE_BYTES: usize = 64;

/// Numeric mandatory event kinds recognized by this candidate version.
///
/// Each kind names an opaque protected body class only; recognizing a number
/// does not validate ciphertext, MLS state, event authorization, or policy.
/// Every other numeric value is mandatory-but-unknown to this implementation
/// and is rejected rather than ignored or treated as an extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EventKind {
    /// Encrypted message content.
    Message = 1,
    /// Encrypted edit content referring to an earlier immutable event.
    Edit = 2,
    /// Encrypted tombstone content referring to an earlier immutable event.
    Tombstone = 3,
    /// Encrypted reaction content.
    Reaction = 4,
    /// Encrypted pin content.
    Pin = 5,
    /// Opaque protected membership or Space-state content.
    Membership = 6,
    /// Caller-supplied protected MLS-control ciphertext.
    MlsControl = 7,
    /// Encrypted file-manifest content.
    FileManifest = 8,
    /// Encrypted voice-signaling content.
    VoiceSignal = 9,
    /// Encrypted, non-persistent presence or typing state.
    Ephemeral = 10,
}

impl TryFrom<u64> for EventKind {
    type Error = EventError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Message),
            2 => Ok(Self::Edit),
            3 => Ok(Self::Tombstone),
            4 => Ok(Self::Reaction),
            5 => Ok(Self::Pin),
            6 => Ok(Self::Membership),
            7 => Ok(Self::MlsControl),
            8 => Ok(Self::FileManifest),
            9 => Ok(Self::VoiceSignal),
            10 => Ok(Self::Ephemeral),
            unknown => Err(EventError::UnknownMandatoryEventKind(unknown)),
        }
    }
}

/// Status returned after event signature verification.
///
/// The only candidate status is `SignatureOnly`: it means the Ed25519
/// signature matches the supplied identity bundle and exact preimage. It never
/// means that the event is authorized, decrypted, or policy accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    /// The exact event preimage has a valid device signature; no policy or
    /// decryption conclusion is implied.
    SignatureOnly,
}

/// Errors while creating, parsing, or verifying a candidate event.
///
/// Every parse or verification failure is closed: no partial event is
/// returned, and unknown mandatory kinds are never silently accepted.
#[derive(Debug, Eq, PartialEq)]
pub enum EventError {
    /// The canonical CBOR profile rejected an input or output value.
    CanonicalEncoding(lattice_protocol::Error),
    /// The versioned public identity bundle was malformed or unsupported.
    Identity(IdentityError),
    /// The outer canonical map does not have exactly its four defined fields.
    InvalidOuterShape,
    /// The preimage canonical map does not have exactly its twelve defined fields.
    InvalidPreimageShape,
    /// The outer event uses a version unsupported by this candidate parser.
    UnsupportedOuterVersion(u64),
    /// The unsigned preimage uses a version unsupported by this candidate parser.
    UnsupportedEventVersion(u64),
    /// A mandatory numeric event kind is not recognized by this version.
    UnknownMandatoryEventKind(u64),
    /// A field has the wrong CBOR type or fixed byte width.
    InvalidField(&'static str),
    /// The author fingerprint does not match the supplied public bundle.
    AuthorFingerprintMismatch,
    /// The protected-body byte string is empty.
    EmptyProtectedBody,
    /// Parents are not strictly sorted by their 32-byte event ID.
    ParentsNotSorted,
    /// The parent list contains a duplicate event ID.
    DuplicateParent,
    /// The author sequence is zero; candidate sequences are one-based.
    InvalidAuthorSequence,
    /// The event contains more than the candidate maximum parent count.
    TooManyParents(usize),
    /// The caller-supplied protected body exceeds the candidate size limit.
    ProtectedBodyTooLarge(usize),
    /// The Ed25519 signature does not verify over the exact preimage.
    SignatureVerificationFailed,
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => {
                write!(formatter, "canonical event encoding: {error}")
            }
            Self::Identity(error) => write!(formatter, "event identity bundle: {error}"),
            Self::InvalidOuterShape => formatter.write_str("outer event map has an invalid shape"),
            Self::InvalidPreimageShape => {
                formatter.write_str("event preimage map has an invalid shape")
            }
            Self::UnsupportedOuterVersion(version) => {
                write!(formatter, "unsupported outer event version: {version}")
            }
            Self::UnsupportedEventVersion(version) => {
                write!(formatter, "unsupported event version: {version}")
            }
            Self::UnknownMandatoryEventKind(kind) => {
                write!(formatter, "unknown mandatory event kind: {kind}")
            }
            Self::InvalidField(field) => write!(formatter, "invalid event field: {field}"),
            Self::AuthorFingerprintMismatch => {
                formatter.write_str("author fingerprint does not match identity bundle")
            }
            Self::ParentsNotSorted => {
                formatter.write_str("parent IDs are not sorted by ascending bytes")
            }
            Self::DuplicateParent => formatter.write_str("parent list contains a duplicate ID"),
            Self::InvalidAuthorSequence => formatter.write_str("author sequence must be positive"),
            Self::TooManyParents(actual) => {
                write!(
                    formatter,
                    "event has {actual} parents; maximum is {MAX_PARENTS}"
                )
            }
            Self::ProtectedBodyTooLarge(actual) => write!(
                formatter,
                "protected body is {actual} bytes; maximum is {MAX_PROTECTED_BODY_BYTES}"
            ),
            Self::EmptyProtectedBody => {
                formatter.write_str("protected body ciphertext must not be empty")
            }
            Self::SignatureVerificationFailed => {
                formatter.write_str("event signature verification failed")
            }
        }
    }
}

impl std::error::Error for EventError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<lattice_protocol::Error> for EventError {
    fn from(error: lattice_protocol::Error) -> Self {
        Self::CanonicalEncoding(error)
    }
}

impl From<IdentityError> for EventError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

/// Caller-authored values used to create one immutable candidate event.
///
/// `protected_body` is an opaque, already-protected ciphertext byte string.
/// It is not checked for encryption or decrypted by this crate. Parent IDs
/// must already be unique and sorted in ascending byte order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraft {
    /// Random 16-byte Space identifier.
    pub space_id: [u8; 16],
    /// Optional 16-byte channel identifier; `None` is encoded as CBOR null.
    pub channel_id: Option<[u8; 16]>,
    /// Positive one-based sequence number for this author device.
    pub author_sequence: u64,
    /// Logical Lamport value; presentation order is not authority.
    pub lamport: u64,
    /// Non-authoritative wall-clock hint in milliseconds.
    pub wall_time_hint: u64,
    /// Unique parent event IDs, sorted by ascending 32-byte representation.
    pub parents: Vec<EventId>,
    /// Numeric mandatory event kind from this candidate profile.
    pub kind: EventKind,
    /// Opaque caller-supplied protected ciphertext; never plaintext.
    pub protected_body: Vec<u8>,
    /// Fixed-width opaque reference to the caller's MLS group.
    pub mls_group_reference: [u8; 32],
    /// Caller-provided MLS epoch associated with the protected ciphertext.
    pub mls_epoch: u64,
}

/// An immutable event whose exact bytes have a valid device signature only.
///
/// The type name and [`Self::status`] deliberately distinguish signature
/// verification from authorization, decryption, MLS-context validation, and
/// policy acceptance. This crate performs none of those additional checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignatureOnlyEvent {
    event_id: EventId,
    fields: EventFields,
    author_fingerprint: [u8; 32],
    identity_bundle: IdentityPublicBundle,
    signature: [u8; SIGNATURE_BYTES],
    preimage_bytes: Vec<u8>,
    encoded_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventFields {
    space_id: [u8; 16],
    channel_id: Option<[u8; 16]>,
    author_sequence: u64,
    lamport: u64,
    wall_time_hint: u64,
    parents: Vec<EventId>,
    kind: EventKind,
    protected_body: Vec<u8>,
    mls_group_reference: [u8; 32],
    mls_epoch: u64,
}

impl EventFields {
    fn from_draft(draft: EventDraft) -> Result<Self, EventError> {
        if draft.author_sequence == 0 {
            return Err(EventError::InvalidAuthorSequence);
        }
        if draft.parents.len() > MAX_PARENTS {
            return Err(EventError::TooManyParents(draft.parents.len()));
        }
        validate_parents(&draft.parents)?;
        if draft.protected_body.is_empty() {
            return Err(EventError::EmptyProtectedBody);
        }
        if draft.protected_body.len() > MAX_PROTECTED_BODY_BYTES {
            return Err(EventError::ProtectedBodyTooLarge(
                draft.protected_body.len(),
            ));
        }
        Ok(Self {
            space_id: draft.space_id,
            channel_id: draft.channel_id,
            author_sequence: draft.author_sequence,
            lamport: draft.lamport,
            wall_time_hint: draft.wall_time_hint,
            parents: draft.parents,
            kind: draft.kind,
            protected_body: draft.protected_body,
            mls_group_reference: draft.mls_group_reference,
            mls_epoch: draft.mls_epoch,
        })
    }

    fn to_preimage_value(&self, author_fingerprint: [u8; 32]) -> Value {
        Value::Map(vec![
            (0, Value::Unsigned(EVENT_VERSION)),
            (1, Value::Bytes(self.space_id.to_vec())),
            (
                2,
                self.channel_id
                    .map_or(Value::Null, |channel| Value::Bytes(channel.to_vec())),
            ),
            (3, Value::Bytes(author_fingerprint.to_vec())),
            (4, Value::Unsigned(self.author_sequence)),
            (5, Value::Unsigned(self.lamport)),
            (6, Value::Unsigned(self.wall_time_hint)),
            (
                7,
                Value::Array(
                    self.parents
                        .iter()
                        .map(|parent| Value::Bytes(parent.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (8, Value::Unsigned(self.kind as u64)),
            (9, Value::Bytes(self.protected_body.clone())),
            (10, Value::Bytes(self.mls_group_reference.to_vec())),
            (11, Value::Unsigned(self.mls_epoch)),
        ])
    }
}

impl VerifiedSignatureOnlyEvent {
    /// Creates and signs an immutable event using the supplied local identity.
    ///
    /// The caller must provide opaque protected ciphertext in `draft`; no
    /// encryption or authorization is performed. Parent IDs must already be
    /// unique and sorted by bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the draft fields are malformed or the canonical
    /// preimage cannot be encoded.
    pub fn create(identity: &DeviceIdentity, draft: EventDraft) -> Result<Self, EventError> {
        let fields = EventFields::from_draft(draft)?;
        let identity_bundle = identity.public_bundle();
        let author_fingerprint = identity_bundle.fingerprint();
        let preimage_bytes = encode_canonical(&fields.to_preimage_value(author_fingerprint))?;
        let event_id = EventId::from_preimage(&preimage_bytes)?;

        let mut signed_message =
            Vec::with_capacity(EVENT_SIGNATURE_DOMAIN.len() + preimage_bytes.len());
        signed_message.extend_from_slice(EVENT_SIGNATURE_DOMAIN);
        signed_message.extend_from_slice(&preimage_bytes);
        let signature = identity.sign(&signed_message);
        let identity_bytes = identity_bundle.to_bytes();
        let encoded_bytes =
            encode_canonical(&outer_value(&preimage_bytes, &identity_bytes, &signature))?;

        Ok(Self {
            event_id,
            fields,
            author_fingerprint,
            identity_bundle,
            signature,
            preimage_bytes,
            encoded_bytes,
        })
    }

    /// Parses an exact canonical outer event, checks its full shape and bounds,
    /// binds the author fingerprint to the versioned identity bundle, and
    /// verifies the signature over the exact nested preimage bytes.
    ///
    /// This returns `SignatureOnly` status; it does not authorize, decrypt,
    /// validate the caller's MLS context, or accept the event under policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the outer event, canonical preimage, identity bundle,
    /// or signature is invalid.
    pub fn decode_verify(input: &[u8]) -> Result<Self, EventError> {
        let outer = decode_canonical(input)?;
        let outer = expect_map(&outer, &[0, 1, 2, 3], EventError::InvalidOuterShape)?;

        let outer_version = expect_unsigned(&outer[0].1, "outer version")?;
        if outer_version != OUTER_EVENT_VERSION {
            return Err(EventError::UnsupportedOuterVersion(outer_version));
        }
        let preimage_bytes = expect_bytes(&outer[1].1, "preimage")?;
        let identity_bytes =
            expect_fixed_bytes::<IDENTITY_BUNDLE_BYTES>(&outer[2].1, "identity bundle")?;
        let signature = expect_fixed_bytes::<SIGNATURE_BYTES>(&outer[3].1, "signature")?;

        let event_id = EventId::from_preimage(preimage_bytes)?;
        let preimage = decode_canonical(preimage_bytes)?;
        let (author_fingerprint, fields) = parse_preimage(&preimage)?;
        let identity_bundle = IdentityPublicBundle::from_bytes(&identity_bytes)?;
        if identity_bundle.fingerprint() != author_fingerprint {
            return Err(EventError::AuthorFingerprintMismatch);
        }

        let mut signed_message =
            Vec::with_capacity(EVENT_SIGNATURE_DOMAIN.len() + preimage_bytes.len());
        signed_message.extend_from_slice(EVENT_SIGNATURE_DOMAIN);
        signed_message.extend_from_slice(preimage_bytes);
        verify(
            &identity_bundle.ed25519_public_key(),
            &signed_message,
            &signature,
        )
        .map_err(|_| EventError::SignatureVerificationFailed)?;

        Ok(Self {
            event_id,
            fields,
            author_fingerprint,
            identity_bundle,
            signature,
            preimage_bytes: preimage_bytes.to_vec(),
            encoded_bytes: input.to_vec(),
        })
    }

    /// Returns the candidate status; it conveys key possession only.
    #[must_use]
    pub const fn status(&self) -> VerificationStatus {
        VerificationStatus::SignatureOnly
    }

    /// Returns the event ID derived from the exact canonical unsigned preimage.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Returns the 16-byte Space identifier.
    #[must_use]
    pub const fn space_id(&self) -> &[u8; 16] {
        &self.fields.space_id
    }

    /// Returns the optional 16-byte channel identifier.
    #[must_use]
    pub const fn channel_id(&self) -> Option<&[u8; 16]> {
        self.fields.channel_id.as_ref()
    }

    /// Returns the author device's versioned-bundle fingerprint.
    #[must_use]
    pub const fn author_fingerprint(&self) -> &[u8; 32] {
        &self.author_fingerprint
    }

    /// Returns the positive one-based author sequence.
    #[must_use]
    pub const fn author_sequence(&self) -> u64 {
        self.fields.author_sequence
    }

    /// Returns the Lamport value; it grants no authority.
    #[must_use]
    pub const fn lamport(&self) -> u64 {
        self.fields.lamport
    }

    /// Returns the non-authoritative wall-time hint in milliseconds.
    #[must_use]
    pub const fn wall_time_hint(&self) -> u64 {
        self.fields.wall_time_hint
    }

    /// Returns the unique parent IDs in their authenticated byte-sorted order.
    #[must_use]
    pub fn parents(&self) -> &[EventId] {
        &self.fields.parents
    }

    /// Returns the recognized numeric event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.fields.kind
    }

    /// Returns the opaque caller-supplied protected ciphertext bytes.
    #[must_use]
    pub fn protected_body(&self) -> &[u8] {
        &self.fields.protected_body
    }

    /// Returns the opaque 32-byte MLS group reference.
    #[must_use]
    pub const fn mls_group_reference(&self) -> &[u8; 32] {
        &self.fields.mls_group_reference
    }

    /// Returns the caller-provided MLS epoch.
    #[must_use]
    pub const fn mls_epoch(&self) -> u64 {
        self.fields.mls_epoch
    }

    /// Returns the verified public identity bundle.
    #[must_use]
    pub const fn identity_bundle(&self) -> IdentityPublicBundle {
        self.identity_bundle
    }

    /// Returns the verified 64-byte Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Returns the exact authenticated unsigned preimage bytes.
    #[must_use]
    pub fn preimage_bytes(&self) -> &[u8] {
        &self.preimage_bytes
    }

    /// Returns the exact original outer encoding.
    ///
    /// The encoding is retained from creation or successful parsing, so
    /// historical preimage bytes are never reconstructed or recoded.
    #[must_use]
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded_bytes
    }

    /// Returns the exact original outer encoding without recoding any field.
    #[must_use]
    pub fn encode(&self) -> &[u8] {
        &self.encoded_bytes
    }
}

fn outer_value(preimage: &[u8], identity_bundle: &[u8], signature: &[u8]) -> Value {
    Value::Map(vec![
        (0, Value::Unsigned(OUTER_EVENT_VERSION)),
        (1, Value::Bytes(preimage.to_vec())),
        (2, Value::Bytes(identity_bundle.to_vec())),
        (3, Value::Bytes(signature.to_vec())),
    ])
}

fn expect_map<'a>(
    value: &'a Value,
    expected_keys: &[u64],
    shape_error: EventError,
) -> Result<&'a [(u64, Value)], EventError> {
    let Value::Map(entries) = value else {
        return Err(shape_error);
    };
    if entries.len() != expected_keys.len()
        || entries
            .iter()
            .zip(expected_keys)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(shape_error);
    }
    Ok(entries)
}

fn expect_unsigned(value: &Value, field: &'static str) -> Result<u64, EventError> {
    match value {
        Value::Unsigned(number) => Ok(*number),
        _ => Err(EventError::InvalidField(field)),
    }
}

fn expect_bytes<'a>(value: &'a Value, field: &'static str) -> Result<&'a [u8], EventError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(EventError::InvalidField(field)),
    }
}

fn expect_fixed_bytes<const N: usize>(
    value: &Value,
    field: &'static str,
) -> Result<[u8; N], EventError> {
    expect_bytes(value, field)?
        .try_into()
        .map_err(|_| EventError::InvalidField(field))
}

fn parse_preimage(value: &Value) -> Result<([u8; 32], EventFields), EventError> {
    let entries = expect_map(
        value,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        EventError::InvalidPreimageShape,
    )?;
    let version = expect_unsigned(&entries[0].1, "event version")?;
    if version != EVENT_VERSION {
        return Err(EventError::UnsupportedEventVersion(version));
    }

    let space_id = expect_fixed_bytes::<16>(&entries[1].1, "Space ID")?;
    let channel_id = match &entries[2].1 {
        Value::Null => None,
        Value::Bytes(bytes) => Some(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| EventError::InvalidField("channel ID"))?,
        ),
        _ => return Err(EventError::InvalidField("channel ID")),
    };
    let author_fingerprint = expect_fixed_bytes::<32>(&entries[3].1, "author fingerprint")?;
    let author_sequence = expect_unsigned(&entries[4].1, "author sequence")?;
    if author_sequence == 0 {
        return Err(EventError::InvalidAuthorSequence);
    }
    let lamport = expect_unsigned(&entries[5].1, "Lamport value")?;
    let wall_time_hint = expect_unsigned(&entries[6].1, "wall-time hint")?;

    let Value::Array(parent_values) = &entries[7].1 else {
        return Err(EventError::InvalidField("parents"));
    };
    if parent_values.len() > MAX_PARENTS {
        return Err(EventError::TooManyParents(parent_values.len()));
    }
    let mut parents = Vec::with_capacity(parent_values.len());
    for parent in parent_values {
        parents.push(EventId::from_bytes(expect_fixed_bytes::<32>(
            parent,
            "parent event ID",
        )?));
    }
    validate_parents(&parents)?;

    let kind_number = expect_unsigned(&entries[8].1, "event kind")?;
    let kind = EventKind::try_from(kind_number)?;
    let protected_body = expect_bytes(&entries[9].1, "protected body")?.to_vec();
    if protected_body.is_empty() {
        return Err(EventError::EmptyProtectedBody);
    }
    if protected_body.len() > MAX_PROTECTED_BODY_BYTES {
        return Err(EventError::ProtectedBodyTooLarge(protected_body.len()));
    }
    let mls_group_reference = expect_fixed_bytes::<32>(&entries[10].1, "MLS group reference")?;
    let mls_epoch = expect_unsigned(&entries[11].1, "MLS epoch")?;

    Ok((
        author_fingerprint,
        EventFields {
            space_id,
            channel_id,
            author_sequence,
            lamport,
            wall_time_hint,
            parents,
            kind,
            protected_body,
            mls_group_reference,
            mls_epoch,
        },
    ))
}

fn validate_parents(parents: &[EventId]) -> Result<(), EventError> {
    for pair in parents.windows(2) {
        match pair[0].as_bytes().cmp(pair[1].as_bytes()) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => return Err(EventError::DuplicateParent),
            core::cmp::Ordering::Greater => return Err(EventError::ParentsNotSorted),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(body: Vec<u8>) -> EventDraft {
        EventDraft {
            space_id: [0x11; 16],
            channel_id: Some([0x22; 16]),
            author_sequence: 7,
            lamport: 19,
            wall_time_hint: 1_750_000_000_123,
            parents: vec![EventId::from_bytes([0x33; 32])],
            kind: EventKind::Message,
            protected_body: body,
            mls_group_reference: [0x44; 32],
            mls_epoch: 3,
        }
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity::generate().expect("OS CSPRNG should be available")
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid lowercase hex vector"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn ephemeral_event_kind_is_recognized_as_mandatory() {
        assert_eq!(EventKind::try_from(10), Ok(EventKind::Ephemeral));
        assert_eq!(
            EventKind::try_from(11),
            Err(EventError::UnknownMandatoryEventKind(11))
        );
    }

    #[test]
    fn published_signed_event_vector_verifies_exact_bytes_and_id() {
        let encoded = decode_hex(
            "a40001015878ac00010150000102030405060708090a0b0c0d0e0f02f60358205f7e15d6a462c18997358f8934ac2d0c53556bce94ed7d031b7c9813da55c02a040105182a061b0000018bcfe56800078008010944010203040a5820a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a50b0002584101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a035840deaa1abf700921011df559747f6aacb464bccf5cc5458d107153f6cb1c5dd5de24eb78003c8f25ef81165a099a3798ca6908c4832374f853648f35fa9fa68b0e",
        );
        let Value::Map(outer_fields) =
            decode_canonical(&encoded).expect("canonical outer event vector")
        else {
            panic!("outer event vector is a map");
        };
        let Value::Bytes(preimage) = &outer_fields[1].1 else {
            panic!("outer event vector contains the preimage bytes");
        };
        decode_canonical(preimage).expect("canonical nested event preimage");
        let event =
            VerifiedSignatureOnlyEvent::decode_verify(&encoded).expect("published event vector");
        assert_eq!(event.encode(), encoded);
        assert_eq!(
            event.preimage_bytes(),
            decode_hex(
                "ac00010150000102030405060708090a0b0c0d0e0f02f60358205f7e15d6a462c18997358f8934ac2d0c53556bce94ed7d031b7c9813da55c02a040105182a061b0000018bcfe56800078008010944010203040a5820a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a50b00"
            )
        );
        let expected_id: [u8; 32] =
            decode_hex("dba9789ef714a3b0df9cad7990abc38841d8ab93fe5880d875da7b55632e1d75")
                .try_into()
                .expect("32-byte event ID vector");
        assert_eq!(event.event_id().as_bytes(), &expected_id);
    }
    fn signed_outer(
        identity: &DeviceIdentity,
        author_fingerprint: [u8; 32],
        fields: &EventFields,
    ) -> Vec<u8> {
        let preimage = encode_canonical(&fields.to_preimage_value(author_fingerprint)).unwrap();
        let mut message = EVENT_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&preimage);
        let signature = identity.sign(&message);
        encode_canonical(&outer_value(
            &preimage,
            &identity.public_bundle().to_bytes(),
            &signature,
        ))
        .unwrap()
    }

    #[test]
    fn candidate_v1_preimage_has_exact_integer_key_bytes_and_expected_id() {
        let fields = EventFields::from_draft(draft(vec![0xaa, 0xbb])).unwrap();
        let fingerprint = [0x55; 32];
        let preimage = encode_canonical(&fields.to_preimage_value(fingerprint)).unwrap();
        let expected = vec![
            0xac, 0x00, 0x01, 0x01, 0x50, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x50, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x03, 0x58, 0x20,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x04, 0x07, 0x05, 0x13, 0x06, 0x1b, 0x00, 0x00, 0x01, 0x97,
            0x74, 0x20, 0xdc, 0x7b, 0x07, 0x81, 0x58, 0x20, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x08, 0x01,
            0x09, 0x42, 0xaa, 0xbb, 0x0a, 0x58, 0x20, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x0b, 0x03,
        ];
        assert_eq!(preimage, expected);

        let id = EventId::from_preimage(&preimage).unwrap();
        assert_eq!(
            id.as_bytes(),
            &[
                0x0b, 0x11, 0xe6, 0x45, 0x86, 0x9c, 0x9c, 0x7b, 0x2b, 0x07, 0xd2, 0xef, 0xab, 0xcc,
                0x21, 0x9d, 0x5a, 0x9f, 0x98, 0xea, 0x45, 0xaf, 0x22, 0xaf, 0x39, 0x25, 0x2e, 0x20,
                0xe8, 0x3a, 0x31, 0x6d,
            ]
        );
    }
    #[test]
    fn signature_verification_does_not_claim_authorization_and_reencoding_preserves_bytes() {
        let identity = identity();
        let event =
            VerifiedSignatureOnlyEvent::create(&identity, draft(vec![0x80, 0x81, 0x82])).unwrap();
        let encoded = event.encode();
        let decoded = VerifiedSignatureOnlyEvent::decode_verify(encoded).unwrap();

        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.encoded_bytes(), encoded);
        assert_eq!(decoded.preimage_bytes(), event.preimage_bytes());
        assert_eq!(
            decoded.event_id(),
            EventId::from_preimage(decoded.preimage_bytes()).unwrap()
        );
        assert_eq!(decoded.status(), VerificationStatus::SignatureOnly);
        assert_eq!(decoded.author_fingerprint(), &identity.fingerprint());
        assert_eq!(decoded.protected_body(), &[0x80, 0x81, 0x82]);
    }

    #[test]
    fn modified_body_and_wrong_signing_key_are_rejected() {
        let signer = identity();
        let original = VerifiedSignatureOnlyEvent::create(&signer, draft(vec![0xaa])).unwrap();
        let mut changed = original.fields.clone();
        changed.protected_body[0] ^= 1;
        let changed_preimage =
            encode_canonical(&changed.to_preimage_value(*original.author_fingerprint())).unwrap();
        let tampered_body = encode_canonical(&outer_value(
            &changed_preimage,
            &original.identity_bundle().to_bytes(),
            original.signature(),
        ))
        .unwrap();
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&tampered_body),
            Err(EventError::SignatureVerificationFailed)
        );

        let wrong_signer = identity();
        let mut wrong_key_message = EVENT_SIGNATURE_DOMAIN.to_vec();
        wrong_key_message.extend_from_slice(original.preimage_bytes());
        let wrong_key_signature = wrong_signer.sign(&wrong_key_message);
        let wrong_key_outer = encode_canonical(&outer_value(
            original.preimage_bytes(),
            &original.identity_bundle().to_bytes(),
            &wrong_key_signature,
        ))
        .unwrap();
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&wrong_key_outer),
            Err(EventError::SignatureVerificationFailed)
        );

        let other_identity = identity();
        let other_bundle_outer = encode_canonical(&outer_value(
            original.preimage_bytes(),
            &other_identity.public_bundle().to_bytes(),
            original.signature(),
        ))
        .unwrap();
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&other_bundle_outer),
            Err(EventError::AuthorFingerprintMismatch)
        );
    }

    #[test]
    fn malformed_parent_lists_unknown_kinds_and_bounds_fail_closed() {
        let identity = identity();
        let fingerprint = identity.fingerprint();
        let mut unsorted = EventFields::from_draft(draft(vec![1])).unwrap();
        unsorted.parents = vec![EventId::from_bytes([2; 32]), EventId::from_bytes([1; 32])];
        let unsorted_bytes = signed_outer(&identity, fingerprint, &unsorted);
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&unsorted_bytes),
            Err(EventError::ParentsNotSorted)
        );

        let duplicate = EventId::from_bytes([3; 32]);
        let mut duplicate_parents = EventFields::from_draft(draft(vec![1])).unwrap();
        duplicate_parents.parents = vec![duplicate, duplicate];
        let duplicate_bytes = signed_outer(&identity, fingerprint, &duplicate_parents);
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&duplicate_bytes),
            Err(EventError::DuplicateParent)
        );

        let unknown_kind = EventFields::from_draft(draft(vec![1])).unwrap();
        let unknown_preimage = replace_kind(&unknown_kind, fingerprint, u64::MAX);
        let mut message = EVENT_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&unknown_preimage);
        let signature = identity.sign(&message);
        let unknown_bytes = encode_canonical(&outer_value(
            &unknown_preimage,
            &identity.public_bundle().to_bytes(),
            &signature,
        ))
        .unwrap();
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&unknown_bytes),
            Err(EventError::UnknownMandatoryEventKind(u64::MAX))
        );

        assert_eq!(
            VerifiedSignatureOnlyEvent::create(
                &identity,
                EventDraft {
                    author_sequence: 0,
                    ..draft(vec![1])
                },
            ),
            Err(EventError::InvalidAuthorSequence)
        );
        assert_eq!(
            VerifiedSignatureOnlyEvent::create(
                &identity,
                EventDraft {
                    parents: vec![EventId::from_bytes([0; 32]); MAX_PARENTS + 1],
                    ..draft(vec![1])
                },
            ),
            Err(EventError::TooManyParents(MAX_PARENTS + 1))
        );
        assert_eq!(
            VerifiedSignatureOnlyEvent::create(
                &identity,
                draft(vec![0; MAX_PROTECTED_BODY_BYTES + 1]),
            ),
            Err(EventError::ProtectedBodyTooLarge(
                MAX_PROTECTED_BODY_BYTES + 1
            ))
        );

        let mut boundary_draft = draft(vec![0; MAX_PROTECTED_BODY_BYTES]);
        boundary_draft.parents = (0..MAX_PARENTS)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[0] = u8::try_from(index).unwrap();
                EventId::from_bytes(bytes)
            })
            .collect();
        let boundary_event = VerifiedSignatureOnlyEvent::create(&identity, boundary_draft).unwrap();
        assert!(VerifiedSignatureOnlyEvent::decode_verify(boundary_event.encode()).is_ok());
    }

    #[test]
    fn empty_protected_body_is_rejected_on_create_and_decode() {
        let identity = identity();
        assert_eq!(
            VerifiedSignatureOnlyEvent::create(&identity, draft(Vec::new())),
            Err(EventError::EmptyProtectedBody)
        );

        let fingerprint = identity.fingerprint();
        let mut fields = EventFields::from_draft(draft(vec![1])).expect("valid fixture");
        fields.protected_body.clear();
        let encoded = signed_outer(&identity, fingerprint, &fields);
        assert_eq!(
            VerifiedSignatureOnlyEvent::decode_verify(&encoded),
            Err(EventError::EmptyProtectedBody)
        );
    }

    #[test]
    fn hostile_event_byte_corpus_never_bypasses_signature_validation() {
        let signer = identity();
        let event = VerifiedSignatureOnlyEvent::create(&signer, draft(vec![0x42; 32]))
            .expect("valid signed seed");
        let encoded = event.encode();
        for index in 0..encoded.len() {
            for mask in [0x01, 0x80] {
                let mut mutated = encoded.to_vec();
                mutated[index] ^= mask;
                if let Ok(decoded) = VerifiedSignatureOnlyEvent::decode_verify(&mutated) {
                    assert_eq!(decoded.encode(), mutated);
                    assert_eq!(decoded.event_id(), event.event_id());
                }
            }
        }

        let mut state = 0xa409_3822_299f_31d0_u64;
        for _ in 0..2_048 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = usize::try_from(state % 512).expect("bounded corpus length");
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                input.push(u8::try_from((state >> 32) & 0xff).expect("masked to one byte"));
            }
            let _ = VerifiedSignatureOnlyEvent::decode_verify(&input);
        }
    }
    fn replace_kind(fields: &EventFields, author_fingerprint: [u8; 32], kind: u64) -> Vec<u8> {
        let mut value = fields.to_preimage_value(author_fingerprint);
        let Value::Map(entries) = &mut value else {
            unreachable!();
        };
        entries[8].1 = Value::Unsigned(kind);
        encode_canonical(&value).unwrap()
    }
}
