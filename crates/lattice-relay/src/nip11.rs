//! Bounded parsing of NIP-11 relay capability documents.
//!
//! This module performs no network operations. [`parse_nip11`] accepts a JSON
//! document of at most 65,536 bytes and preserves only the capability fields
//! understood by this crate. Unknown fields are accepted, but duplicate object
//! keys anywhere in the document are rejected.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeMap;
use std::fmt;

/// Maximum accepted serialized NIP-11 document size, in bytes.
pub const MAX_NIP11_BYTES: usize = 65_536;
/// Minimum `max_message_length` required for the Lattice profile.
pub const LATTICE_PROFILE_MIN_MESSAGE_LENGTH: u64 = 66_048;

/// The capabilities advertised by a relay's NIP-11 document.
///
/// Missing fields are represented by `None`; the parser does not infer relay
/// support from omitted information.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayCapabilities {
    /// NIP identifiers listed by `supported_nips`, if supplied.
    pub supported_nips: Option<Vec<u64>>,
    /// Advertised maximum message length, if supplied.
    pub max_message_length: Option<u64>,
}

impl RelayCapabilities {
    /// Whether the relay advertises both NIP-40 and sufficient message size
    /// for the Lattice profile.
    #[must_use]
    pub fn supports_lattice_profile(&self) -> bool {
        self.supported_nips
            .as_ref()
            .is_some_and(|nips| nips.contains(&40))
            && self
                .max_message_length
                .is_some_and(|length| length >= LATTICE_PROFILE_MIN_MESSAGE_LENGTH)
    }
}

/// A failure while validating a NIP-11 capability document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nip11Error {
    /// The serialized document exceeds [`MAX_NIP11_BYTES`].
    InputTooLarge { actual: usize, maximum: usize },
    /// The bytes are not valid JSON, or contain a duplicate object key.
    InvalidJson(String),
    /// The JSON root is not an object.
    RootNotObject,
    /// `supported_nips` exists but is not an array.
    SupportedNipsNotArray,
    /// An entry in `supported_nips` is not a positive unsigned NIP ID.
    InvalidNipId { index: usize },
    /// `max_message_length` exists but is not a nonnegative integer.
    InvalidMaxMessageLength,
}

impl fmt::Display for Nip11Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => {
                write!(f, "NIP-11 document is {actual} bytes; maximum is {maximum}")
            }
            Self::InvalidJson(reason) => write!(f, "invalid NIP-11 JSON: {reason}"),
            Self::RootNotObject => f.write_str("NIP-11 JSON root must be an object"),
            Self::SupportedNipsNotArray => f.write_str("NIP-11 supported_nips must be an array"),
            Self::InvalidNipId { index } => {
                write!(
                    f,
                    "NIP-11 supported_nips entry {index} is not a valid NIP ID"
                )
            }
            Self::InvalidMaxMessageLength => {
                f.write_str("NIP-11 max_message_length must be a nonnegative integer")
            }
        }
    }
}

impl std::error::Error for Nip11Error {}

/// Parse and validate a bounded NIP-11 JSON capability document.
///
/// Every JSON object is checked for duplicate key names, including objects in
/// otherwise-unrecognized extension fields. NIP IDs are positive `u64`
/// integers; max message length must be a nonnegative JSON integer.
///
/// # Errors
///
/// Returns an error for oversized input, malformed JSON, duplicate object
/// keys, or invalid types and values for supported capability fields.
pub fn parse_nip11(input: &[u8]) -> Result<RelayCapabilities, Nip11Error> {
    if input.len() > MAX_NIP11_BYTES {
        return Err(Nip11Error::InputTooLarge {
            actual: input.len(),
            maximum: MAX_NIP11_BYTES,
        });
    }

    let value: JsonValue = serde_json::from_slice(input)
        .map_err(|error| Nip11Error::InvalidJson(error.to_string()))?;
    let JsonValue::Object(mut object) = value else {
        return Err(Nip11Error::RootNotObject);
    };

    let supported_nips = match object.remove("supported_nips") {
        None => None,
        Some(JsonValue::Array(items)) => {
            let mut nips = Vec::with_capacity(items.len());
            for (index, item) in items.into_iter().enumerate() {
                let JsonValue::Number(Number::Unsigned(id)) = item else {
                    return Err(Nip11Error::InvalidNipId { index });
                };
                if id == 0 {
                    return Err(Nip11Error::InvalidNipId { index });
                }
                nips.push(id);
            }
            Some(nips)
        }
        Some(_) => return Err(Nip11Error::SupportedNipsNotArray),
    };

    let max_message_length = match object.remove("max_message_length") {
        None => None,
        Some(JsonValue::Number(Number::Unsigned(length))) => Some(length),
        Some(_) => return Err(Nip11Error::InvalidMaxMessageLength),
    };

    Ok(RelayCapabilities {
        supported_nips,
        max_message_length,
    })
}

#[derive(Debug)]
enum Number {
    Unsigned(u64),
    Signed,
    Float,
}

#[derive(Debug)]
enum JsonValue {
    Null,
    Bool,
    Number(Number),
    String,
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonValueVisitor)
    }
}

struct JsonValueVisitor;

impl<'de> Visitor<'de> for JsonValueVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::Null)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::Bool)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Ok(value) = u64::try_from(value) {
            Ok(JsonValue::Number(Number::Unsigned(value)))
        } else {
            Ok(JsonValue::Number(Number::Signed))
        }
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::Number(Number::Unsigned(value)))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::Number(Number::Float))
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::String)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonValue::String)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, JsonValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate object key {key:?}")));
            }
        }
        Ok(JsonValue::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::{LATTICE_PROFILE_MIN_MESSAGE_LENGTH, MAX_NIP11_BYTES, Nip11Error, parse_nip11};

    fn parse(json: &str) -> Result<super::RelayCapabilities, Nip11Error> {
        parse_nip11(json.as_bytes())
    }

    #[test]
    fn lattice_profile_requires_nip_40_and_exact_size_threshold() {
        let capabilities = parse(r#"{"supported_nips":[40],"max_message_length":66048}"#)
            .expect("valid capabilities");
        assert!(capabilities.supports_lattice_profile());
        assert_eq!(LATTICE_PROFILE_MIN_MESSAGE_LENGTH, 66_048);
    }

    #[test]
    fn missing_or_unsupported_nip_40_is_not_eligible() {
        for json in [
            r#"{"max_message_length":66048}"#,
            r#"{"supported_nips":[],"max_message_length":66048}"#,
            r#"{"supported_nips":[39],"max_message_length":66048}"#,
        ] {
            assert!(!parse(json).unwrap().supports_lattice_profile());
        }
        assert!(
            !parse(r#"{"supported_nips":[40]}"#)
                .unwrap()
                .supports_lattice_profile()
        );
    }

    #[test]
    fn rejects_insufficient_size_and_malformed_capability_types() {
        assert!(
            !parse(r#"{"supported_nips":[40],"max_message_length":66047}"#)
                .unwrap()
                .supports_lattice_profile()
        );
        for json in [
            r#"{"supported_nips":"40"}"#,
            r#"{"supported_nips":["40"]}"#,
            r#"{"supported_nips":[-1]}"#,
            r#"{"supported_nips":[0]}"#,
            r#"{"supported_nips":[1.5]}"#,
            r#"{"max_message_length":"66048"}"#,
            r#"{"max_message_length":-1}"#,
            r#"{"max_message_length":1.5}"#,
        ] {
            assert!(parse(json).is_err(), "expected rejection for {json}");
        }
    }

    #[test]
    fn rejects_duplicate_keys_and_accepts_unknown_fields() {
        for json in [
            r#"{"supported_nips":[40],"supported_nips":[40]}"#,
            r#"{"extension":{"value":1,"value":2}}"#,
        ] {
            assert!(matches!(parse(json), Err(Nip11Error::InvalidJson(_))));
        }
        let parsed = parse(r#"{"extension":{"nested":[true,null]},"supported_nips":[40],"max_message_length":66048}"#)
            .unwrap();
        assert!(parsed.supports_lattice_profile());
        assert_eq!(parse("{}").unwrap().supported_nips, None);
        assert_eq!(parse("{}").unwrap().max_message_length, None);
    }

    #[test]
    fn enforces_json_and_input_size_bounds() {
        let mut exact_limit = br"{}".to_vec();
        exact_limit.resize(MAX_NIP11_BYTES, b' ');
        assert!(parse_nip11(&exact_limit).is_ok());
        let too_large = vec![b' '; MAX_NIP11_BYTES + 1];
        assert!(matches!(
            parse_nip11(&too_large),
            Err(Nip11Error::InputTooLarge { .. })
        ));
        assert!(matches!(parse("{"), Err(Nip11Error::InvalidJson(_))));
        assert!(matches!(parse("[]"), Err(Nip11Error::RootNotObject)));
    }
}
