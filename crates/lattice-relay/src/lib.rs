//! Candidate-only delivery envelope codec.
//!
//! This implements optional candidate envelope accounting plus strict NIP-01
//! signed-event and NIP-11 capability codecs. It does not connect to a relay or
//! claim interoperability. The exact signed Lattice event remains independently
//! verified by `lattice-events`; envelope IDs and inner event IDs are distinct.

pub mod nip01;
pub mod nip11;
pub mod profile;

use core::fmt;

use lattice_events::{EventError, VerifiedSignatureOnlyEvent};
pub use lattice_protocol::EventId;
use sha2::{Digest, Sha256};

/// Candidate delivery-envelope version.
pub const ENVELOPE_VERSION: u64 = 1;
/// Maximum encoded envelope size, including its CBOR map.
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
/// Maximum exact encoded signed event size carried by an envelope.
pub const MAX_SIGNED_EVENT_BYTES: usize = 1_048_576;
/// Maximum allowed hop or copy budget.
pub const MAX_FORWARDING_BUDGET: u64 = 64;
/// Maximum retention period in seconds.
pub const MAX_ENVELOPE_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Domain prefix used to derive envelope identifiers.
pub const ENVELOPE_ID_DOMAIN: &[u8] = b"lattice:envelope:v1\0";

/// Numeric delivery classes in candidate envelope version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum DeliveryClass {
    /// A dependency needed to establish or retain security state.
    SecurityDependency = 0,
    /// Interactive text delivery.
    InteractiveText = 1,
    /// Deferred history synchronization.
    DeferredHistory = 2,
    /// A file chunk on a path that explicitly supports bulk transfer.
    FileChunk = 3,
}

impl TryFrom<u64> for DeliveryClass {
    type Error = EnvelopeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SecurityDependency),
            1 => Ok(Self::InteractiveText),
            2 => Ok(Self::DeferredHistory),
            3 => Ok(Self::FileChunk),
            other => Err(EnvelopeError::UnknownDeliveryClass(other)),
        }
    }
}

/// A SHA-256 envelope identifier, distinct from the inner [`EventId`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EnvelopeId([u8; 32]);

impl EnvelopeId {
    /// Constructs an envelope ID from its fixed-width representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the 32-byte envelope ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Which bounded forwarding budget was exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetKind {
    /// The envelope cannot be forwarded to another hop.
    Hop,
    /// The sender cannot transfer another courier copy.
    Copy,
}

/// Errors while constructing or decoding a candidate delivery envelope.
#[derive(Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// The complete encoded envelope exceeds the 1 MiB profile limit.
    EnvelopeTooLarge(usize),
    /// The exact embedded signed event exceeds its profile limit.
    SignedEventTooLarge(usize),
    /// The byte sequence is malformed or not canonical CBOR.
    InvalidCbor(&'static str),
    /// The map does not have exactly ascending integer keys `0..=8`.
    InvalidShape,
    /// A field has a CBOR type other than the specified one.
    WrongFieldType(&'static str),
    /// A fixed-width byte string has the wrong length.
    InvalidWidth {
        /// Field name.
        field: &'static str,
        /// Required width in bytes.
        expected: usize,
        /// Observed width in bytes.
        actual: usize,
    },
    /// The envelope version is unsupported.
    UnsupportedVersion(u64),
    /// The delivery class is not defined by candidate version 1.
    UnknownDeliveryClass(u64),
    /// Creation time must be a positive Unix second.
    InvalidCreationTime,
    /// Expiry must be strictly later than creation time.
    ExpiryNotAfterCreation,
    /// Expiry exceeds the 30-day retention limit.
    ExpiryTooFar,
    /// Expiry has passed at the supplied local receive time.
    Expired {
        /// Envelope expiry.
        expires_at: u64,
        /// Local receive time.
        now: u64,
    },
    /// Hop or copy budget is outside the inclusive range 0 through 64.
    BudgetOutOfRange {
        /// Which budget was invalid.
        kind: BudgetKind,
        /// Observed value.
        value: u64,
    },
    /// The envelope ID does not match the fields in the map.
    EnvelopeIdMismatch,
    /// The embedded signed event is malformed or its signature is invalid.
    InvalidSignedEvent(EventError),
    /// The event ID field does not identify the verified embedded event.
    EventIdMismatch,
    /// A forwarding operation was attempted with a zero budget.
    BudgetExhausted(BudgetKind),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvelopeTooLarge(size) => {
                write!(formatter, "envelope is {size} bytes; maximum is 1048576")
            }
            Self::SignedEventTooLarge(size) => {
                write!(
                    formatter,
                    "signed event is {size} bytes; maximum is 1048576"
                )
            }
            Self::InvalidCbor(reason) => write!(formatter, "invalid envelope CBOR: {reason}"),
            Self::InvalidShape => formatter
                .write_str("envelope must be a map with exactly ascending keys 0 through 8"),
            Self::WrongFieldType(field) => {
                write!(formatter, "envelope field {field} has the wrong CBOR type")
            }
            Self::InvalidWidth {
                field,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "envelope field {field} is {actual} bytes; expected {expected}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported envelope version {version}")
            }
            Self::UnknownDeliveryClass(class) => {
                write!(formatter, "unknown envelope delivery class {class}")
            }
            Self::InvalidCreationTime => {
                formatter.write_str("envelope creation time must be positive")
            }
            Self::ExpiryNotAfterCreation => {
                formatter.write_str("envelope expiry must be after creation time")
            }
            Self::ExpiryTooFar => {
                formatter.write_str("envelope expiry exceeds the 30-day maximum lifetime")
            }
            Self::Expired { expires_at, now } => {
                write!(
                    formatter,
                    "envelope expired at {expires_at} (local time {now})"
                )
            }
            Self::BudgetOutOfRange { kind, value } => {
                write!(formatter, "{kind:?} budget {value} is outside 0 through 64")
            }
            Self::EnvelopeIdMismatch => {
                formatter.write_str("envelope ID does not match the canonical envelope fields")
            }
            Self::InvalidSignedEvent(error) => {
                write!(formatter, "embedded signed event is invalid: {error}")
            }
            Self::EventIdMismatch => {
                formatter.write_str("envelope event ID does not match the verified embedded event")
            }
            Self::BudgetExhausted(kind) => {
                write!(
                    formatter,
                    "cannot forward or copy with zero {kind:?} budget"
                )
            }
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSignedEvent(error) => Some(error),
            _ => None,
        }
    }
}

/// One canonical candidate-v1 delivery envelope around a verified exact event.
///
/// [`Self::event_id`] is the inner signed-event identity used for event
/// deduplication. [`Self::envelope_id`] identifies this particular routing,
/// expiry, and forwarding-budget instance and changes when any hashed envelope
/// field changes.
#[derive(Debug, Eq, PartialEq)]
pub struct EnvelopeV1 {
    envelope_id: EnvelopeId,
    event_id: EventId,
    delivery_class: DeliveryClass,
    created_at: u64,
    expires_at: u64,
    remaining_hop_budget: u8,
    remaining_copy_budget: u8,
    event: VerifiedSignatureOnlyEvent,
    encoded_bytes: Vec<u8>,
}

impl EnvelopeV1 {
    /// Wraps an already signature-verified event in a new candidate envelope.
    ///
    /// `created_at` must be positive, expiry must be later and no more than 30
    /// days after creation, and both forwarding budgets must be in `0..=64`.
    ///
    /// # Errors
    ///
    /// Returns an error when envelope metadata exceeds a profile bound, the
    /// signed event is too large, or the encoded envelope exceeds its bound.
    pub fn new(
        event: VerifiedSignatureOnlyEvent,
        delivery_class: DeliveryClass,
        created_at: u64,
        expires_at: u64,
        remaining_hop_budget: u64,
        remaining_copy_budget: u64,
    ) -> Result<Self, EnvelopeError> {
        let (remaining_hop_budget, remaining_copy_budget) = validate_bounds(
            created_at,
            expires_at,
            remaining_hop_budget,
            remaining_copy_budget,
        )?;
        let event_bytes = event.encode();
        if event_bytes.len() > MAX_SIGNED_EVENT_BYTES {
            return Err(EnvelopeError::SignedEventTooLarge(event_bytes.len()));
        }
        let event_id = event.event_id();
        let fields = EnvelopeData {
            event_id,
            delivery_class,
            created_at,
            expires_at,
            hop_budget: remaining_hop_budget,
            copy_budget: remaining_copy_budget,
            event_bytes,
        };
        let envelope_id = calculate_envelope_id(&fields);
        let encoded_bytes = encode_envelope(envelope_id, &fields)?;
        Ok(Self {
            envelope_id,
            event_id,
            delivery_class,
            created_at,
            expires_at,
            remaining_hop_budget,
            remaining_copy_budget,
            event,
            encoded_bytes,
        })
    }

    /// Decodes an envelope and independently verifies its embedded signed event.
    ///
    /// Expiry-relative-to-local-time checking is available through
    /// [`Self::decode_at`]. This method validates expiry ordering and the
    /// 30-day maximum, but does not assume a local clock.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/noncanonical envelope bytes, invalid
    /// metadata, an ID mismatch, or an invalid embedded event signature.
    pub fn decode(input: &[u8]) -> Result<Self, EnvelopeError> {
        if input.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::EnvelopeTooLarge(input.len()));
        }
        let fields = parse_envelope(input)?;
        let (remaining_hop_budget, remaining_copy_budget) = validate_bounds(
            fields.created_at,
            fields.expires_at,
            fields.remaining_hop_budget,
            fields.remaining_copy_budget,
        )?;
        let delivery_class = DeliveryClass::try_from(fields.delivery_class)?;
        let event_id_bytes: [u8; 32] =
            fields
                .event_id
                .try_into()
                .map_err(|_| EnvelopeError::InvalidWidth {
                    field: "event ID",
                    expected: 32,
                    actual: fields.event_id.len(),
                })?;
        let event_id = EventId::from_bytes(event_id_bytes);
        let envelope_fields = EnvelopeData {
            event_id,
            delivery_class,
            created_at: fields.created_at,
            expires_at: fields.expires_at,
            hop_budget: remaining_hop_budget,
            copy_budget: remaining_copy_budget,
            event_bytes: fields.event_bytes,
        };
        let expected_id = calculate_envelope_id(&envelope_fields);
        if expected_id.as_bytes() != fields.envelope_id {
            return Err(EnvelopeError::EnvelopeIdMismatch);
        }
        if fields.event_bytes.len() > MAX_SIGNED_EVENT_BYTES {
            return Err(EnvelopeError::SignedEventTooLarge(fields.event_bytes.len()));
        }
        let event = VerifiedSignatureOnlyEvent::decode_verify(fields.event_bytes)
            .map_err(EnvelopeError::InvalidSignedEvent)?;
        if event.event_id().as_bytes() != fields.event_id {
            return Err(EnvelopeError::EventIdMismatch);
        }
        Ok(Self {
            envelope_id: expected_id,
            event_id: event.event_id(),
            delivery_class,
            created_at: fields.created_at,
            expires_at: fields.expires_at,
            remaining_hop_budget,
            remaining_copy_budget,
            event,
            encoded_bytes: input.to_vec(),
        })
    }

    /// Decodes and verifies an envelope, rejecting one expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::decode`] or [`EnvelopeError::Expired`].
    pub fn decode_at(input: &[u8], now: u64) -> Result<Self, EnvelopeError> {
        let envelope = Self::decode(input)?;
        if envelope.expires_at <= now {
            return Err(EnvelopeError::Expired {
                expires_at: envelope.expires_at,
                now,
            });
        }
        Ok(envelope)
    }

    /// Returns the envelope ID for this exact envelope metadata and budget.
    #[must_use]
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.envelope_id
    }

    /// Returns the ID of the independently verified inner signed event.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Returns the numeric delivery class.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }

    /// Returns the positive Unix-second creation time.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the Unix-second expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the remaining hop forwarding budget.
    #[must_use]
    pub const fn remaining_hop_budget(&self) -> u8 {
        self.remaining_hop_budget
    }

    /// Returns the remaining courier-copy budget.
    #[must_use]
    pub const fn remaining_copy_budget(&self) -> u8 {
        self.remaining_copy_budget
    }

    /// Returns the verified inner event.
    #[must_use]
    pub const fn event(&self) -> &VerifiedSignatureOnlyEvent {
        &self.event
    }

    /// Returns the exact signed inner event bytes.
    #[must_use]
    pub fn signed_event_bytes(&self) -> &[u8] {
        self.event.encode()
    }

    /// Returns the exact original envelope bytes without re-encoding.
    #[must_use]
    pub fn encode(&self) -> &[u8] {
        &self.encoded_bytes
    }

    /// Decrements hop budget before forwarding and re-derives envelope ID.
    ///
    /// Returns [`EnvelopeError::BudgetExhausted`] without changing this value
    /// when its current hop budget is zero. A budget of one may be consumed to
    /// zero for exactly one final forwarding operation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::BudgetExhausted`] when the hop budget is zero,
    /// or an encoding error if rebuilding the envelope fails.
    pub fn decrement_hop_budget(&mut self) -> Result<(), EnvelopeError> {
        if self.remaining_hop_budget == 0 {
            return Err(EnvelopeError::BudgetExhausted(BudgetKind::Hop));
        }
        let next = self.remaining_hop_budget - 1;
        self.replace_budgets(next, self.remaining_copy_budget)
    }

    /// Decrements courier-copy budget before transferring a copy and re-derives
    /// envelope ID. This does not provide atomic transfer/disconnect handling.
    ///
    /// Returns [`EnvelopeError::BudgetExhausted`] without changing this value
    /// when its current copy budget is zero.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::BudgetExhausted`] when the copy budget is zero,
    /// or an encoding error if rebuilding the envelope fails.
    pub fn decrement_copy_budget(&mut self) -> Result<(), EnvelopeError> {
        if self.remaining_copy_budget == 0 {
            return Err(EnvelopeError::BudgetExhausted(BudgetKind::Copy));
        }
        let next = self.remaining_copy_budget - 1;
        self.replace_budgets(self.remaining_hop_budget, next)
    }

    fn replace_budgets(&mut self, hop_budget: u8, copy_budget: u8) -> Result<(), EnvelopeError> {
        let fields = EnvelopeData {
            event_id: self.event_id,
            delivery_class: self.delivery_class,
            created_at: self.created_at,
            expires_at: self.expires_at,
            hop_budget,
            copy_budget,
            event_bytes: self.event.encode(),
        };
        let envelope_id = calculate_envelope_id(&fields);
        let encoded_bytes = encode_envelope(envelope_id, &fields)?;
        self.remaining_hop_budget = hop_budget;
        self.remaining_copy_budget = copy_budget;
        self.envelope_id = envelope_id;
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }
}

struct ParsedEnvelope<'a> {
    envelope_id: &'a [u8],
    event_id: &'a [u8],
    delivery_class: u64,
    created_at: u64,
    expires_at: u64,
    remaining_hop_budget: u64,
    remaining_copy_budget: u64,
    event_bytes: &'a [u8],
}

fn validate_bounds(
    created_at: u64,
    expires_at: u64,
    hop_budget: u64,
    copy_budget: u64,
) -> Result<(u8, u8), EnvelopeError> {
    if created_at == 0 {
        return Err(EnvelopeError::InvalidCreationTime);
    }
    if expires_at <= created_at {
        return Err(EnvelopeError::ExpiryNotAfterCreation);
    }
    if expires_at - created_at > MAX_ENVELOPE_LIFETIME_SECONDS {
        return Err(EnvelopeError::ExpiryTooFar);
    }
    if hop_budget > MAX_FORWARDING_BUDGET {
        return Err(EnvelopeError::BudgetOutOfRange {
            kind: BudgetKind::Hop,
            value: hop_budget,
        });
    }
    if copy_budget > MAX_FORWARDING_BUDGET {
        return Err(EnvelopeError::BudgetOutOfRange {
            kind: BudgetKind::Copy,
            value: copy_budget,
        });
    }
    let hop_budget = u8::try_from(hop_budget).map_err(|_| EnvelopeError::BudgetOutOfRange {
        kind: BudgetKind::Hop,
        value: hop_budget,
    })?;
    let copy_budget = u8::try_from(copy_budget).map_err(|_| EnvelopeError::BudgetOutOfRange {
        kind: BudgetKind::Copy,
        value: copy_budget,
    })?;
    Ok((hop_budget, copy_budget))
}
struct EnvelopeData<'a> {
    event_id: EventId,
    delivery_class: DeliveryClass,
    created_at: u64,
    expires_at: u64,
    hop_budget: u8,
    copy_budget: u8,
    event_bytes: &'a [u8],
}

fn calculate_envelope_id(fields: &EnvelopeData<'_>) -> EnvelopeId {
    let mut preimage = Vec::with_capacity(96);
    preimage.push(0xa8); // map(8), omitting key 1
    encode_uint(0, &mut preimage);
    encode_uint(ENVELOPE_VERSION, &mut preimage);
    encode_uint(2, &mut preimage);
    encode_bytes(fields.event_id.as_bytes(), &mut preimage);
    encode_uint(3, &mut preimage);
    encode_uint(fields.delivery_class as u64, &mut preimage);
    encode_uint(4, &mut preimage);
    encode_uint(fields.created_at, &mut preimage);
    encode_uint(5, &mut preimage);
    encode_uint(fields.expires_at, &mut preimage);
    encode_uint(6, &mut preimage);
    encode_uint(u64::from(fields.hop_budget), &mut preimage);
    encode_uint(7, &mut preimage);
    encode_uint(u64::from(fields.copy_budget), &mut preimage);
    encode_uint(8, &mut preimage);
    encode_head(2, fields.event_bytes.len() as u64, &mut preimage);

    let mut hasher = Sha256::new();
    hasher.update(ENVELOPE_ID_DOMAIN);
    hasher.update(preimage);
    hasher.update(fields.event_bytes);
    let digest = hasher.finalize();
    let mut id = [0_u8; 32];
    id.copy_from_slice(&digest);
    EnvelopeId(id)
}

fn encode_envelope(
    envelope_id: EnvelopeId,
    fields: &EnvelopeData<'_>,
) -> Result<Vec<u8>, EnvelopeError> {
    if fields.event_bytes.len() > MAX_SIGNED_EVENT_BYTES {
        return Err(EnvelopeError::SignedEventTooLarge(fields.event_bytes.len()));
    }
    let mut encoded = Vec::with_capacity(fields.event_bytes.len().saturating_add(128));
    encoded.push(0xa9); // map(9)
    encode_uint(0, &mut encoded);
    encode_uint(ENVELOPE_VERSION, &mut encoded);
    encode_uint(1, &mut encoded);
    encode_bytes(envelope_id.as_bytes(), &mut encoded);
    encode_uint(2, &mut encoded);
    encode_bytes(fields.event_id.as_bytes(), &mut encoded);
    encode_uint(3, &mut encoded);
    encode_uint(fields.delivery_class as u64, &mut encoded);
    encode_uint(4, &mut encoded);
    encode_uint(fields.created_at, &mut encoded);
    encode_uint(5, &mut encoded);
    encode_uint(fields.expires_at, &mut encoded);
    encode_uint(6, &mut encoded);
    encode_uint(u64::from(fields.hop_budget), &mut encoded);
    encode_uint(7, &mut encoded);
    encode_uint(u64::from(fields.copy_budget), &mut encoded);
    encode_uint(8, &mut encoded);
    encode_bytes(fields.event_bytes, &mut encoded);
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(EnvelopeError::EnvelopeTooLarge(encoded.len()));
    }
    Ok(encoded)
}

fn encode_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    encode_head(2, bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}

fn encode_uint(value: u64, output: &mut Vec<u8>) {
    encode_head(0, value, output);
}

fn encode_head(major: u8, argument: u64, output: &mut Vec<u8>) {
    let major_bits = major << 5;
    let bytes = argument.to_be_bytes();
    match argument {
        0..=23 => output.push(major_bits | bytes[7]),
        24..=0xff => {
            output.push(major_bits | 0x18);
            output.push(bytes[7]);
        }
        0x100..=0xffff => {
            output.push(major_bits | 0x19);
            output.extend_from_slice(&bytes[6..8]);
        }
        0x1_0000..=0xffff_ffff => {
            output.push(major_bits | 0x1a);
            output.extend_from_slice(&bytes[4..8]);
        }
        _ => {
            output.push(major_bits | 0x1b);
            output.extend_from_slice(&bytes);
        }
    }
}

fn parse_envelope(input: &[u8]) -> Result<ParsedEnvelope<'_>, EnvelopeError> {
    let mut reader = EnvelopeReader {
        input,
        position: 0,
        envelope_id: None,
        event_id: None,
        delivery_class: None,
        created_at: None,
        expires_at: None,
        hop_budget: None,
        copy_budget: None,
        event_bytes: None,
    };
    let map_length = reader.read_argument(5)?;
    if map_length != 9 {
        return Err(EnvelopeError::InvalidShape);
    }
    for expected_key in 0..=8 {
        if reader.read_argument(0)? != expected_key {
            return Err(EnvelopeError::InvalidShape);
        }
        match expected_key {
            0 => {
                let version = reader.read_unsigned("version")?;
                if version != ENVELOPE_VERSION {
                    return Err(EnvelopeError::UnsupportedVersion(version));
                }
            }
            1 => {
                let bytes = reader.read_bytes("envelope ID")?;
                check_width("envelope ID", bytes, 32)?;
                // Stored below after parsing through a small fixed-size table.
                reader.envelope_id = Some(bytes);
            }
            2 => {
                let bytes = reader.read_bytes("event ID")?;
                check_width("event ID", bytes, 32)?;
                reader.event_id = Some(bytes);
            }
            3 => reader.delivery_class = Some(reader.read_unsigned("delivery class")?),
            4 => reader.created_at = Some(reader.read_unsigned("creation time")?),
            5 => reader.expires_at = Some(reader.read_unsigned("expiry time")?),
            6 => reader.hop_budget = Some(reader.read_unsigned("hop budget")?),
            7 => reader.copy_budget = Some(reader.read_unsigned("copy budget")?),
            8 => reader.event_bytes = Some(reader.read_bytes("signed event")?),
            _ => return Err(EnvelopeError::InvalidShape),
        }
    }
    if reader.position != input.len() {
        return Err(EnvelopeError::InvalidCbor("trailing bytes"));
    }
    let event_bytes = reader.event_bytes.ok_or(EnvelopeError::InvalidShape)?;
    if event_bytes.len() > MAX_SIGNED_EVENT_BYTES {
        return Err(EnvelopeError::SignedEventTooLarge(event_bytes.len()));
    }
    Ok(ParsedEnvelope {
        envelope_id: reader.envelope_id.ok_or(EnvelopeError::InvalidShape)?,
        event_id: reader.event_id.ok_or(EnvelopeError::InvalidShape)?,
        delivery_class: reader.delivery_class.ok_or(EnvelopeError::InvalidShape)?,
        created_at: reader.created_at.ok_or(EnvelopeError::InvalidShape)?,
        expires_at: reader.expires_at.ok_or(EnvelopeError::InvalidShape)?,
        remaining_hop_budget: reader.hop_budget.ok_or(EnvelopeError::InvalidShape)?,
        remaining_copy_budget: reader.copy_budget.ok_or(EnvelopeError::InvalidShape)?,
        event_bytes,
    })
}

fn check_width(field: &'static str, bytes: &[u8], expected: usize) -> Result<(), EnvelopeError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(EnvelopeError::InvalidWidth {
            field,
            expected,
            actual: bytes.len(),
        })
    }
}

struct EnvelopeReader<'a> {
    input: &'a [u8],
    position: usize,
    envelope_id: Option<&'a [u8]>,
    event_id: Option<&'a [u8]>,
    delivery_class: Option<u64>,
    created_at: Option<u64>,
    expires_at: Option<u64>,
    hop_budget: Option<u64>,
    copy_budget: Option<u64>,
    event_bytes: Option<&'a [u8]>,
}

impl<'a> EnvelopeReader<'a> {
    fn read_unsigned(&mut self, field: &'static str) -> Result<u64, EnvelopeError> {
        self.read_argument_for_type(0, field)
    }

    fn read_bytes(&mut self, field: &'static str) -> Result<&'a [u8], EnvelopeError> {
        let length = self.read_argument_for_type(2, field)?;
        let length = usize::try_from(length)
            .map_err(|_| EnvelopeError::InvalidCbor("byte-string length out of range"))?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(EnvelopeError::InvalidCbor("byte-string length overflow"))?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(EnvelopeError::InvalidCbor("truncated byte string"))?;
        self.position = end;
        Ok(bytes)
    }

    fn read_argument(&mut self, expected_major: u8) -> Result<u64, EnvelopeError> {
        self.read_argument_for_type(expected_major, "map header or key")
    }

    fn read_argument_for_type(
        &mut self,
        expected_major: u8,
        field: &'static str,
    ) -> Result<u64, EnvelopeError> {
        let initial = *self
            .input
            .get(self.position)
            .ok_or(EnvelopeError::InvalidCbor("truncated CBOR item"))?;
        self.position += 1;
        let major = initial >> 5;
        if major != expected_major {
            return Err(EnvelopeError::WrongFieldType(field));
        }
        let additional = initial & 0x1f;
        let argument = match additional {
            value @ 0..=23 => u64::from(value),
            24 => u64::from(self.read_u8()?),
            25 => u64::from(self.read_u16()?),
            26 => u64::from(self.read_u32()?),
            27 => self.read_u64()?,
            31 => return Err(EnvelopeError::InvalidCbor("indefinite-length item")),
            _ => {
                return Err(EnvelopeError::InvalidCbor(
                    "reserved additional information",
                ));
            }
        };
        let is_minimal = match additional {
            24 => argument >= 24,
            25 => argument > 0xff,
            26 => argument > 0xffff,
            27 => argument > 0xffff_ffff,
            _ => true,
        };
        if !is_minimal {
            return Err(EnvelopeError::InvalidCbor("non-minimal integer or length"));
        }
        Ok(argument)
    }

    fn read_u8(&mut self) -> Result<u8, EnvelopeError> {
        let byte = *self
            .input
            .get(self.position)
            .ok_or(EnvelopeError::InvalidCbor("truncated integer"))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16, EnvelopeError> {
        let bytes = self.read_exact::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, EnvelopeError> {
        let bytes = self.read_exact::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, EnvelopeError> {
        let bytes = self.read_exact::<8>()?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(EnvelopeError::InvalidCbor("integer length overflow"))?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(EnvelopeError::InvalidCbor("truncated integer"))?;
        self.position = end;
        bytes
            .try_into()
            .map_err(|_| EnvelopeError::InvalidCbor("invalid integer width"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_VECTOR_HEX: &str = concat!(
        "a40001015878ac00010150000102030405060708090a0b0c0d0e0f02f603",
        "58205f7e15d6a462c18997358f8934ac2d0c53556bce94ed7d031b7c9813da55c02a",
        "040105182a061b0000018bcfe56800078008010944010203040a5820",
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "0b0002584101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68",
        "f707511a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9",
        "b4e6a035840deaa1abf700921011df559747f6aacb464bccf5cc5458d107153f6cb1",
        "c5dd5de24eb78003c8f25ef81165a099a3798ca6908c4832374f853648f35fa9fa68b0e"
    );

    fn from_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid test hex"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn verified_vector_event() -> VerifiedSignatureOnlyEvent {
        VerifiedSignatureOnlyEvent::decode_verify(&from_hex(EVENT_VECTOR_HEX))
            .expect("embedded published event vector verifies")
    }

    #[test]
    fn canonical_vector_round_trips_exact_bytes_and_separates_ids() {
        let event = verified_vector_event();
        let envelope = EnvelopeV1::new(
            event,
            DeliveryClass::InteractiveText,
            1_700_000_000,
            1_702_592_000,
            2,
            4,
        )
        .expect("valid deterministic envelope");

        assert_eq!(
            envelope.envelope_id().as_bytes().as_slice(),
            from_hex("0acecb2bd7235daa2935bc3b7f5ad30dadbd1f433e552ad0ac109d0231daf70b").as_slice()
        );
        assert_eq!(
            envelope.event_id().as_bytes().as_slice(),
            from_hex("dba9789ef714a3b0df9cad7990abc38841d8ab93fe5880d875da7b55632e1d75").as_slice()
        );
        assert_eq!(
            envelope.encode(),
            from_hex(concat!(
                "a900010158200acecb2bd7235daa2935bc3b7f5ad30dadbd1f433e552ad0ac109d0231daf70b",
                "025820dba9789ef714a3b0df9cad7990abc38841d8ab93fe5880d875da7b55632e1d75",
                "0301041a6553f100051a657b7e000602070408590105a40001015878ac00010150000102030405060708090a0b0c0d0e0f02f60358205f7e15d6a462c18997358f8934ac2d0c53556bce94ed7d031b7c9813da55c02a040105182a061b0000018bcfe56800078008010944010203040a5820",
                "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "0b0002584101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a035840deaa1abf700921011df559747f6aacb464bccf5cc5458d107153f6cb1c5dd5de24eb78003c8f25ef81165a099a3798ca6908c4832374f853648f35fa9fa68b0e"
            ))
            .as_slice()
        );
        let decoded = EnvelopeV1::decode(envelope.encode()).expect("vector decodes");
        assert_eq!(decoded.encode(), envelope.encode());
        assert_eq!(decoded.envelope_id(), envelope.envelope_id());
        assert_eq!(decoded.event_id(), envelope.event_id());
        let expected_event_bytes = from_hex(EVENT_VECTOR_HEX);
        assert_eq!(
            decoded.signed_event_bytes(),
            expected_event_bytes.as_slice()
        );
    }

    #[test]
    fn envelope_id_changes_with_each_routing_or_budget_field() {
        let event = verified_vector_event();
        let baseline = EnvelopeV1::new(
            event.clone(),
            DeliveryClass::InteractiveText,
            1_700_000_000,
            1_702_592_000,
            2,
            4,
        )
        .unwrap();
        let variants = [
            EnvelopeV1::new(
                event.clone(),
                DeliveryClass::DeferredHistory,
                1_700_000_000,
                1_702_592_000,
                2,
                4,
            )
            .unwrap(),
            EnvelopeV1::new(
                event.clone(),
                DeliveryClass::InteractiveText,
                1_700_000_000,
                1_702_591_999,
                2,
                4,
            )
            .unwrap(),
            EnvelopeV1::new(
                event.clone(),
                DeliveryClass::InteractiveText,
                1_700_000_000,
                1_702_592_000,
                3,
                4,
            )
            .unwrap(),
            EnvelopeV1::new(
                event,
                DeliveryClass::InteractiveText,
                1_700_000_000,
                1_702_592_000,
                2,
                5,
            )
            .unwrap(),
        ];
        for variant in variants {
            assert_ne!(variant.envelope_id(), baseline.envelope_id());
            assert_eq!(variant.event_id(), baseline.event_id());
            assert_eq!(variant.signed_event_bytes(), baseline.signed_event_bytes());
        }
    }

    #[test]
    fn expiry_and_budget_boundaries_and_forwarding_limits_are_enforced() {
        let event = verified_vector_event();
        let max_lifetime = EnvelopeV1::new(
            event.clone(),
            DeliveryClass::FileChunk,
            1,
            1 + MAX_ENVELOPE_LIFETIME_SECONDS,
            MAX_FORWARDING_BUDGET,
            MAX_FORWARDING_BUDGET,
        )
        .expect("inclusive maximum lifetime and budgets are valid");
        assert_eq!(max_lifetime.remaining_hop_budget(), 64);
        assert_eq!(max_lifetime.remaining_copy_budget(), 64);
        assert!(matches!(
            EnvelopeV1::new(event.clone(), DeliveryClass::InteractiveText, 0, 1, 0, 0,),
            Err(EnvelopeError::InvalidCreationTime)
        ));
        assert!(matches!(
            EnvelopeV1::new(event.clone(), DeliveryClass::InteractiveText, 10, 10, 0, 0,),
            Err(EnvelopeError::ExpiryNotAfterCreation)
        ));
        assert!(matches!(
            EnvelopeV1::new(
                event.clone(),
                DeliveryClass::InteractiveText,
                1,
                2 + MAX_ENVELOPE_LIFETIME_SECONDS,
                0,
                0,
            ),
            Err(EnvelopeError::ExpiryTooFar)
        ));
        assert!(matches!(
            EnvelopeV1::new(event.clone(), DeliveryClass::InteractiveText, 1, 2, 65, 0,),
            Err(EnvelopeError::BudgetOutOfRange {
                kind: BudgetKind::Hop,
                value: 65,
            })
        ));

        let mut one_hop =
            EnvelopeV1::new(event, DeliveryClass::InteractiveText, 1, 2, 1, 1).unwrap();
        let original_id = one_hop.envelope_id();
        one_hop.decrement_hop_budget().unwrap();
        assert_eq!(one_hop.remaining_hop_budget(), 0);
        assert_ne!(one_hop.envelope_id(), original_id);
        let before_failed_forward = one_hop.encode().to_vec();
        assert_eq!(
            one_hop.decrement_hop_budget(),
            Err(EnvelopeError::BudgetExhausted(BudgetKind::Hop))
        );
        assert_eq!(one_hop.encode(), before_failed_forward.as_slice());
        one_hop.decrement_copy_budget().unwrap();
        assert_eq!(one_hop.remaining_copy_budget(), 0);
        assert_eq!(
            one_hop.decrement_copy_budget(),
            Err(EnvelopeError::BudgetExhausted(BudgetKind::Copy))
        );
        assert!(matches!(
            EnvelopeV1::decode_at(one_hop.encode(), 2),
            Err(EnvelopeError::Expired {
                expires_at: 2,
                now: 2
            })
        ));
    }

    #[test]
    fn event_bytes_are_verified_and_event_id_must_match() {
        let event = verified_vector_event();
        let valid = EnvelopeV1::new(
            event,
            DeliveryClass::InteractiveText,
            1_700_000_000,
            1_700_000_001,
            0,
            0,
        )
        .unwrap();

        let mut corrupted_envelope_id = valid.encode().to_vec();
        corrupted_envelope_id[6] ^= 1;
        assert_eq!(
            EnvelopeV1::decode(&corrupted_envelope_id),
            Err(EnvelopeError::EnvelopeIdMismatch)
        );
        let mut wrong_shape = valid.encode().to_vec();
        wrong_shape[0] = 0xa8;
        assert_eq!(
            EnvelopeV1::decode(&wrong_shape),
            Err(EnvelopeError::InvalidShape)
        );
        let mut noncanonical = valid.encode().to_vec();
        noncanonical[0] = 0xb8;
        noncanonical.insert(1, 0x09);
        assert!(matches!(
            EnvelopeV1::decode(&noncanonical),
            Err(EnvelopeError::InvalidCbor(_))
        ));
        let mut wrong_event_id = [0_u8; 32];
        wrong_event_id.copy_from_slice(valid.event_id().as_bytes());
        wrong_event_id[0] ^= 1;
        let wrong_id_bytes = encode_raw_envelope(
            valid.envelope_id(),
            &EnvelopeData {
                event_id: EventId::from_bytes(wrong_event_id),
                delivery_class: valid.delivery_class(),
                created_at: valid.created_at(),
                expires_at: valid.expires_at(),
                hop_budget: valid.remaining_hop_budget(),
                copy_budget: valid.remaining_copy_budget(),
                event_bytes: valid.signed_event_bytes(),
            },
        );
        let wrong_id = rehash_raw_envelope_with_event_id(&wrong_id_bytes, wrong_event_id);
        assert_eq!(
            EnvelopeV1::decode(&wrong_id),
            Err(EnvelopeError::EventIdMismatch)
        );

        let malformed_event = [0xa0];
        let malformed = encode_raw_envelope(
            EnvelopeId::from_bytes([0; 32]),
            &EnvelopeData {
                event_id: EventId::from_bytes(*valid.event_id().as_bytes()),
                delivery_class: valid.delivery_class(),
                created_at: valid.created_at(),
                expires_at: valid.expires_at(),
                hop_budget: valid.remaining_hop_budget(),
                copy_budget: valid.remaining_copy_budget(),
                event_bytes: &malformed_event,
            },
        );
        let malformed = rehash_raw_envelope(&malformed);
        assert!(matches!(
            EnvelopeV1::decode(&malformed),
            Err(EnvelopeError::InvalidSignedEvent(_))
        ));
    }

    fn encode_raw_envelope(envelope_id: EnvelopeId, fields: &EnvelopeData<'_>) -> Vec<u8> {
        encode_envelope(envelope_id, fields).unwrap()
    }

    fn parsed_envelope_data<'a>(
        parsed: &ParsedEnvelope<'a>,
        event_id: EventId,
    ) -> EnvelopeData<'a> {
        let (hop_budget, copy_budget) = validate_bounds(
            parsed.created_at,
            parsed.expires_at,
            parsed.remaining_hop_budget,
            parsed.remaining_copy_budget,
        )
        .unwrap();
        EnvelopeData {
            event_id,
            delivery_class: DeliveryClass::try_from(parsed.delivery_class).unwrap(),
            created_at: parsed.created_at,
            expires_at: parsed.expires_at,
            hop_budget,
            copy_budget,
            event_bytes: parsed.event_bytes,
        }
    }

    fn rehash_raw_envelope(encoded: &[u8]) -> Vec<u8> {
        let parsed = parse_envelope(encoded).unwrap();
        let event_id: [u8; 32] = parsed.event_id.try_into().unwrap();
        let fields = parsed_envelope_data(&parsed, EventId::from_bytes(event_id));
        let envelope_id = calculate_envelope_id(&fields);
        encode_raw_envelope(envelope_id, &fields)
    }

    fn rehash_raw_envelope_with_event_id(encoded: &[u8], event_id: [u8; 32]) -> Vec<u8> {
        let parsed = parse_envelope(encoded).unwrap();
        let fields = parsed_envelope_data(&parsed, EventId::from_bytes(event_id));
        let envelope_id = calculate_envelope_id(&fields);
        encode_raw_envelope(envelope_id, &fields)
    }
}
