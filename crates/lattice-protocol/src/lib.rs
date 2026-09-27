//! Initial candidate Lattice wire profile and capability handling.
//!
//! The versioned canonical-CBOR profile here is an implementation candidate, not a
//! frozen interoperability contract. Its limits are deliberately conservative:
//! encoded events are at most 1 MiB, each byte/text string at most 256 KiB, each
//! array or map at most 4,096 items, and container nesting at most 32 levels.

use core::fmt;

use sha2::{Digest, Sha256};

pub const CRATE_NAME: &str = "lattice-protocol";

/// Version number for this explicitly versioned, still-candidate encoding profile.
pub const CANDIDATE_ENCODING_VERSION: u8 = 1;

/// Maximum encoded event preimage accepted by the candidate profile.
pub const MAX_EVENT_BYTES: usize = 1_048_576;
/// Maximum payload size of an individual byte or text string.
pub const MAX_STRING_BYTES: usize = 262_144;
/// Maximum number of entries in an individual array or map.
pub const MAX_COLLECTION_ITEMS: usize = 4_096;
/// Maximum number of nested array/map containers.
pub const MAX_NESTING_DEPTH: usize = 32;

mod path_upgrade;

pub use path_upgrade::{
    MAX_PATH_UPGRADE_FRAME_BYTES, NegotiatedPathUpgrades, PATH_UPGRADE_VERSION,
    PathUpgradeCapabilities, PathUpgradeError,
};

const EVENT_ID_DOMAIN: &[u8] = b"lattice:event:v1";

/// Values supported by the candidate integer-key CBOR profile.
///
/// Map keys are unsigned integers and must be strictly increasing. `Signed`
/// represents negative integers only; nonnegative values use `Unsigned`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(u64, Value)>),
    Bool(bool),
    Null,
}

/// A failure to encode or decode the bounded candidate profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    EventTooLarge,
    StringTooLarge,
    CollectionTooLarge,
    NestingTooDeep,
    Truncated,
    TrailingBytes,
    NonCanonicalInteger,
    IndefiniteLength,
    ReservedAdditionalInformation,
    UnsupportedType,
    InvalidUtf8,
    MapKeyNotUnsigned,
    DuplicateMapKey,
    UnsortedMapKeys,
    NegativeIntegerOutOfRange,
    InvalidNegativeInteger,
    LengthOutOfRange,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EventTooLarge => "event exceeds the candidate profile byte limit",
            Self::StringTooLarge => "string exceeds the candidate profile byte limit",
            Self::CollectionTooLarge => "collection exceeds the candidate profile item limit",
            Self::NestingTooDeep => "container nesting exceeds the candidate profile limit",
            Self::Truncated => "truncated CBOR value",
            Self::TrailingBytes => "trailing bytes after the CBOR value",
            Self::NonCanonicalInteger => "non-minimal CBOR integer or length",
            Self::IndefiniteLength => "indefinite-length CBOR item is not supported",
            Self::ReservedAdditionalInformation => "reserved CBOR additional information",
            Self::UnsupportedType => "CBOR type is outside the candidate profile",
            Self::InvalidUtf8 => "text string is not valid UTF-8",
            Self::MapKeyNotUnsigned => "map key is not an unsigned integer",
            Self::DuplicateMapKey => "map contains a duplicate key",
            Self::UnsortedMapKeys => "map keys are not strictly increasing",
            Self::NegativeIntegerOutOfRange => "negative integer is outside the i64 range",
            Self::InvalidNegativeInteger => "signed value must be negative",
            Self::LengthOutOfRange => "CBOR length cannot be represented on this platform",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for Error {}

/// Encode a value using shortest-form, definite-length candidate CBOR.
///
/// # Errors
///
/// Returns [`Error`] for invalid map ordering, unsupported value forms,
/// collection or nesting limits, or an encoded value above the profile limit.
pub fn encode_canonical(value: &Value) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    encode_value(value, 0, &mut output)?;
    Ok(output)
}

/// Decode exactly one canonical value, rejecting trailing bytes and over-limit input.
///
/// # Errors
///
/// Returns [`Error`] when the input is oversized, malformed, non-canonical,
/// truncated, or contains trailing bytes.
pub fn decode_canonical(input: &[u8]) -> Result<Value, Error> {
    if input.len() > MAX_EVENT_BYTES {
        return Err(Error::EventTooLarge);
    }

    let mut decoder = Decoder { input, position: 0 };
    let value = decoder.read_value(0)?;
    if decoder.position != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

fn encode_value(value: &Value, depth: usize, output: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Unsigned(number) => write_head(output, 0, *number),
        Value::Signed(number) => {
            if *number >= 0 {
                return Err(Error::InvalidNegativeInteger);
            }
            let argument = u64::try_from(-1_i128 - i128::from(*number))
                .map_err(|_| Error::LengthOutOfRange)?;
            write_head(output, 1, argument)
        }
        Value::Bytes(bytes) => {
            check_string_len(bytes.len())?;
            write_head(output, 2, bytes.len() as u64)?;
            append(output, bytes)
        }
        Value::Text(text) => {
            check_string_len(text.len())?;
            write_head(output, 3, text.len() as u64)?;
            append(output, text.as_bytes())
        }
        Value::Array(values) => {
            check_container_depth(depth)?;
            check_collection_len(values.len())?;
            write_head(output, 4, values.len() as u64)?;
            for value in values {
                encode_value(value, depth + 1, output)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            check_container_depth(depth)?;
            check_collection_len(entries.len())?;
            for pair in entries.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(Error::DuplicateMapKey);
                }
                if pair[0].0 > pair[1].0 {
                    return Err(Error::UnsortedMapKeys);
                }
            }
            write_head(output, 5, entries.len() as u64)?;
            for (key, value) in entries {
                write_head(output, 0, *key)?;
                encode_value(value, depth + 1, output)?;
            }
            Ok(())
        }
        Value::Bool(false) => append(output, &[0xf4]),
        Value::Bool(true) => append(output, &[0xf5]),
        Value::Null => append(output, &[0xf6]),
    }
}

fn check_string_len(length: usize) -> Result<(), Error> {
    if length > MAX_STRING_BYTES {
        Err(Error::StringTooLarge)
    } else {
        Ok(())
    }
}

fn check_collection_len(length: usize) -> Result<(), Error> {
    if length > MAX_COLLECTION_ITEMS {
        Err(Error::CollectionTooLarge)
    } else {
        Ok(())
    }
}

fn check_container_depth(depth: usize) -> Result<(), Error> {
    if depth >= MAX_NESTING_DEPTH {
        Err(Error::NestingTooDeep)
    } else {
        Ok(())
    }
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let new_length = output
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::EventTooLarge)?;
    if new_length > MAX_EVENT_BYTES {
        return Err(Error::EventTooLarge);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_head(output: &mut Vec<u8>, major: u8, argument: u64) -> Result<(), Error> {
    let prefix = major << 5;
    let bytes = argument.to_be_bytes();
    let mut encoded = [0_u8; 9];
    let length = if argument < 24 {
        encoded[0] = prefix | bytes[7];
        1
    } else if argument <= u8::MAX.into() {
        encoded[0] = prefix | 0x18;
        encoded[1] = bytes[7];
        2
    } else if argument <= u16::MAX.into() {
        encoded[0] = prefix | 0x19;
        encoded[1..3].copy_from_slice(&bytes[6..8]);
        3
    } else if argument <= u32::MAX.into() {
        encoded[0] = prefix | 0x1a;
        encoded[1..5].copy_from_slice(&bytes[4..8]);
        5
    } else {
        encoded[0] = prefix | 0x1b;
        encoded[1..9].copy_from_slice(&bytes);
        9
    };
    append(output, &encoded[..length])
}

#[derive(Clone, Copy)]
struct Head {
    major: u8,
    additional: u8,
    argument: u64,
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn read_value(&mut self, depth: usize) -> Result<Value, Error> {
        let head = self.read_head()?;
        match head.major {
            0 => Ok(Value::Unsigned(head.argument)),
            1 => {
                let argument =
                    i64::try_from(head.argument).map_err(|_| Error::NegativeIntegerOutOfRange)?;
                Ok(Value::Signed(-1 - argument))
            }
            2 => {
                let bytes = self.read_string_bytes(head.argument)?;
                Ok(Value::Bytes(bytes.to_vec()))
            }
            3 => {
                let bytes = self.read_string_bytes(head.argument)?;
                let text = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                check_container_depth(depth)?;
                let length = Self::checked_collection_length(head.argument)?;
                if length > self.remaining() {
                    return Err(Error::Truncated);
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.read_value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => {
                check_container_depth(depth)?;
                let length = Self::checked_collection_length(head.argument)?;
                if length > self.remaining() / 2 {
                    return Err(Error::Truncated);
                }
                let mut entries = Vec::with_capacity(length);
                let mut previous_key = None;
                for _ in 0..length {
                    let key_head = self.read_head()?;
                    if key_head.major != 0 {
                        return Err(Error::MapKeyNotUnsigned);
                    }
                    let key = key_head.argument;
                    if let Some(previous) = previous_key {
                        if key == previous {
                            return Err(Error::DuplicateMapKey);
                        }
                        if key < previous {
                            return Err(Error::UnsortedMapKeys);
                        }
                    }
                    previous_key = Some(key);
                    entries.push((key, self.read_value(depth + 1)?));
                }
                Ok(Value::Map(entries))
            }
            7 => match (head.additional, head.argument) {
                (20, 20) => Ok(Value::Bool(false)),
                (21, 21) => Ok(Value::Bool(true)),
                (22, 22) => Ok(Value::Null),
                _ => Err(Error::UnsupportedType),
            },
            _ => Err(Error::UnsupportedType),
        }
    }

    fn read_head(&mut self) -> Result<Head, Error> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let argument = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let value = self.read_uint(1)?;
                if major != 7 && value < 24 {
                    return Err(Error::NonCanonicalInteger);
                }
                value
            }
            25 => {
                let value = self.read_uint(2)?;
                if major != 7 && value <= u8::MAX.into() {
                    return Err(Error::NonCanonicalInteger);
                }
                value
            }
            26 => {
                let value = self.read_uint(4)?;
                if major != 7 && value <= u16::MAX.into() {
                    return Err(Error::NonCanonicalInteger);
                }
                value
            }
            27 => {
                let value = self.read_uint(8)?;
                if major != 7 && value <= u32::MAX.into() {
                    return Err(Error::NonCanonicalInteger);
                }
                value
            }
            28..=30 => return Err(Error::ReservedAdditionalInformation),
            31 => return Err(Error::IndefiniteLength),
            _ => unreachable!("additional information is five bits"),
        };
        Ok(Head {
            major,
            additional,
            argument,
        })
    }

    fn read_string_bytes(&mut self, length: u64) -> Result<&'a [u8], Error> {
        if length > MAX_STRING_BYTES as u64 {
            return Err(Error::StringTooLarge);
        }
        let length = usize::try_from(length).map_err(|_| Error::LengthOutOfRange)?;
        self.take(length)
    }

    fn checked_collection_length(length: u64) -> Result<usize, Error> {
        if length > MAX_COLLECTION_ITEMS as u64 {
            return Err(Error::CollectionTooLarge);
        }
        usize::try_from(length).map_err(|_| Error::LengthOutOfRange)
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let byte = *self.input.get(self.position).ok_or(Error::Truncated)?;
        self.position += 1;
        Ok(byte)
    }

    fn read_uint(&mut self, length: usize) -> Result<u64, Error> {
        let bytes = self.take(length)?;
        let mut value = 0_u64;
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::LengthOutOfRange)?;
        let bytes = self.input.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.position
    }
}

/// A candidate SHA-256 identifier for an exact canonical event preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Validate and hash a canonical event preimage without rewriting its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the preimage is not a bounded, canonical value.
    pub fn from_preimage(preimage: &[u8]) -> Result<Self, Error> {
        decode_canonical(preimage)?;
        Ok(Self::hash_preimage(preimage))
    }

    /// Encode a supported value and hash those exact encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the value cannot be encoded within the profile.
    pub fn from_value(value: &Value) -> Result<Self, Error> {
        let preimage = encode_canonical(value)?;
        Ok(Self::hash_preimage(&preimage))
    }

    /// Construct an ID from its 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn hash_preimage(preimage: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(EVENT_ID_DOMAIN);
        hasher.update(preimage);
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_candidate_canonical_vectors() {
        let vectors = [
            (Value::Unsigned(0), vec![0x00]),
            (Value::Unsigned(24), vec![0x18, 0x18]),
            (Value::Unsigned(256), vec![0x19, 0x01, 0x00]),
            (Value::Signed(-1), vec![0x20]),
            (Value::Signed(-25), vec![0x38, 0x18]),
            (Value::Bytes(vec![0xaa]), vec![0x41, 0xaa]),
            (Value::Text("a".into()), vec![0x61, b'a']),
            (
                Value::Array(vec![Value::Unsigned(1), Value::Text("a".into())]),
                vec![0x82, 0x01, 0x61, b'a'],
            ),
            (
                Value::Map(vec![(0, Value::Bool(true)), (10, Value::Bytes(vec![0xaa]))]),
                vec![0xa2, 0x00, 0xf5, 0x0a, 0x41, 0xaa],
            ),
            (Value::Null, vec![0xf6]),
        ];

        for (value, expected) in vectors {
            assert_eq!(encode_canonical(&value).unwrap(), expected);
            let decoded = decode_canonical(&expected).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(encode_canonical(&decoded).unwrap(), expected);
        }
    }

    #[test]
    fn event_id_hashes_domain_and_exact_canonical_preimage() {
        let preimage = [0xa1, 0x00, 0x01];
        let expected = [
            0xb0, 0x04, 0xd9, 0x5d, 0xf1, 0x12, 0x3a, 0x2e, 0x00, 0x62, 0xe8, 0x27, 0x91, 0x37,
            0xaa, 0x70, 0x7c, 0xdb, 0x97, 0x78, 0x8a, 0xb3, 0x2c, 0xc6, 0x21, 0x6f, 0x5d, 0x48,
            0x91, 0x62, 0x21, 0x95,
        ];
        let value = Value::Map(vec![(0, Value::Unsigned(1))]);

        assert_eq!(
            EventId::from_preimage(&preimage).unwrap().as_bytes(),
            &expected
        );
        assert_eq!(EventId::from_value(&value).unwrap().as_bytes(), &expected);
    }

    #[test]
    fn rejects_noncanonical_and_malformed_inputs() {
        assert_eq!(
            decode_canonical(&[0x18, 0x00]),
            Err(Error::NonCanonicalInteger)
        );
        assert_eq!(
            decode_canonical(&[0x9f, 0xff]),
            Err(Error::IndefiniteLength)
        );
        assert_eq!(
            decode_canonical(&[0xa2, 0x00, 0x00, 0x00, 0x01]),
            Err(Error::DuplicateMapKey)
        );
        assert_eq!(
            decode_canonical(&[0xa2, 0x01, 0x00, 0x00, 0x00]),
            Err(Error::UnsortedMapKeys)
        );
        assert_eq!(decode_canonical(&[0x61, 0xff]), Err(Error::InvalidUtf8));
        assert_eq!(decode_canonical(&[0x00, 0x00]), Err(Error::TrailingBytes));
        assert_eq!(
            EventId::from_preimage(&[0x18, 0x00]),
            Err(Error::NonCanonicalInteger)
        );
    }

    #[test]
    fn enforces_declared_size_and_nesting_bounds_before_collection_allocation() {
        assert_eq!(
            decode_canonical(&[0x5a, 0x00, 0x04, 0x00, 0x01]),
            Err(Error::StringTooLarge)
        );
        assert_eq!(
            decode_canonical(&[0x99, 0x10, 0x01]),
            Err(Error::CollectionTooLarge)
        );

        let mut nested = vec![0x81; MAX_NESTING_DEPTH + 1];
        nested.push(0xf6);
        assert_eq!(decode_canonical(&nested), Err(Error::NestingTooDeep));

        let oversized_event = vec![0; MAX_EVENT_BYTES + 1];
        assert_eq!(
            decode_canonical(&oversized_event),
            Err(Error::EventTooLarge)
        );
    }

    #[test]
    fn accepts_exact_string_collection_and_nesting_limits() {
        let maximum_string = Value::Bytes(vec![0; MAX_STRING_BYTES]);
        let encoded_string = encode_canonical(&maximum_string).expect("maximum string encodes");
        assert_eq!(decode_canonical(&encoded_string), Ok(maximum_string));

        let maximum_array = Value::Array(vec![Value::Null; MAX_COLLECTION_ITEMS]);
        let encoded_array = encode_canonical(&maximum_array).expect("maximum array encodes");
        assert_eq!(decode_canonical(&encoded_array), Ok(maximum_array));

        let mut maximum_nesting = Value::Null;
        for _ in 0..MAX_NESTING_DEPTH {
            maximum_nesting = Value::Array(vec![maximum_nesting]);
        }
        let encoded_nesting = encode_canonical(&maximum_nesting).expect("maximum nesting encodes");
        assert_eq!(decode_canonical(&encoded_nesting), Ok(maximum_nesting));
    }

    #[test]
    fn hostile_byte_corpus_is_panic_free_and_decodes_only_canonical_values() {
        let canonical_seeds: &[&[u8]] = &[
            &[0xa1, 0x00, 0x01],
            &[0x83, 0x01, 0x21, 0xf6],
            &[0x65, b'h', b'e', b'l', b'l', b'o'],
        ];
        for seed in canonical_seeds {
            let value = decode_canonical(seed).expect("seed is canonical CBOR");
            assert_eq!(
                encode_canonical(&value).expect("seed value re-encodes"),
                *seed
            );
            for index in 0..seed.len() {
                for mask in [0x01, 0x80] {
                    let mut mutated = seed.to_vec();
                    mutated[index] ^= mask;
                    if let Ok(value) = decode_canonical(&mutated) {
                        assert_eq!(
                            encode_canonical(&value).expect("mutated value remains encodable"),
                            mutated
                        );
                    }
                }
            }
        }
        let mut state = 0x1f83_d9ab_fb41_bd6b_u64;
        for _ in 0..4_096 {
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
            if let Ok(value) = decode_canonical(&input) {
                assert_eq!(
                    encode_canonical(&value).expect("decoded values remain encodable"),
                    input
                );
            }
        }
    }
    #[test]
    fn encoder_rejects_invalid_map_order_and_over_limit_values() {
        assert_eq!(
            encode_canonical(&Value::Map(vec![(2, Value::Null), (1, Value::Null)])),
            Err(Error::UnsortedMapKeys)
        );
        assert_eq!(
            encode_canonical(&Value::Map(vec![(1, Value::Null), (1, Value::Null)])),
            Err(Error::DuplicateMapKey)
        );
        assert_eq!(
            encode_canonical(&Value::Signed(1)),
            Err(Error::InvalidNegativeInteger)
        );
        assert_eq!(
            encode_canonical(&Value::Bytes(vec![0; MAX_STRING_BYTES + 1])),
            Err(Error::StringTooLarge)
        );
        let over_limit = Value::Array(
            (0..4)
                .map(|_| Value::Bytes(vec![0; MAX_STRING_BYTES]))
                .collect(),
        );
        assert_eq!(encode_canonical(&over_limit), Err(Error::EventTooLarge));
    }
}
