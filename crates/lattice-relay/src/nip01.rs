//! Strict NIP-01 signed-event representation and verification.
//!
//! This module implements the standard event fields and BIP340 signature
//! contract only. It deliberately does not apply relay-profile kind, tag, or
//! content policies.

use core::fmt;

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum size, in UTF-8 bytes, of a complete NIP-01 event JSON object.
pub const MAX_NIP01_EVENT_JSON_BYTES: usize = 65_536;

/// A validated NIP-01 version 1 event.
///
/// Fields are private so events can only be created from a Schnorr secret or
/// parsed from JSON that passes the complete NIP-01 validation path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrEventV1 {
    id: [u8; 32],
    pubkey: [u8; 32],
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: [u8; 64],
}

/// Failure while constructing, parsing, serializing, or verifying a NIP-01 event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrEventError {
    /// The secret key is zero or is not a valid secp256k1 scalar.
    InvalidSecretKey,
    /// A public key is not a valid x-only secp256k1 key.
    InvalidPublicKey,
    /// A signature is not a valid BIP340 signature encoding.
    InvalidSignature,
    /// An event ID, public key, or signature has the wrong hex width.
    InvalidHexWidth {
        /// Name of the field with the invalid width.
        field: &'static str,
        /// Required number of hexadecimal characters.
        expected: usize,
        /// Actual number of bytes in the hexadecimal string.
        actual: usize,
    },
    /// A hex field contains non-hexadecimal or non-lowercase characters.
    InvalidHex {
        /// Name of the field containing invalid hex.
        field: &'static str,
    },
    /// JSON is malformed, has duplicate or unknown fields, or has a wrong field type.
    InvalidJson,
    /// The event's declared ID differs from the ID derived from its fields.
    IdMismatch,
    /// The signature does not verify for the event ID and public key.
    SignatureMismatch,
    /// A complete event JSON object exceeds the 65,536-byte limit.
    EventTooLarge {
        /// Observed serialized or parsed size in bytes.
        actual: usize,
    },
    /// Compact JSON serialization failed.
    SerializationFailed,
}

impl fmt::Display for NostrEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => f.write_str("invalid Schnorr secret key"),
            Self::InvalidPublicKey => f.write_str("invalid x-only public key"),
            Self::InvalidSignature => f.write_str("invalid BIP340 signature encoding"),
            Self::InvalidHexWidth {
                field,
                expected,
                actual,
            } => write!(f, "{field} hex width is {actual}, expected {expected}"),
            Self::InvalidHex { field } => {
                write!(f, "{field} must use lowercase hexadecimal")
            }
            Self::InvalidJson => f.write_str("invalid NIP-01 event JSON"),
            Self::IdMismatch => f.write_str("event ID does not match its fields"),
            Self::SignatureMismatch => f.write_str("event Schnorr signature does not verify"),
            Self::EventTooLarge { actual } => write!(
                f,
                "event JSON is {actual} bytes, exceeding the {MAX_NIP01_EVENT_JSON_BYTES}-byte limit"
            ),
            Self::SerializationFailed => f.write_str("could not serialize NIP-01 event JSON"),
        }
    }
}

impl std::error::Error for NostrEventError {}

impl NostrEventV1 {
    /// Create and sign an event using a 32-byte BIP340 secret key.
    ///
    /// Tags retain their supplied order. The event ID is SHA-256 of the exact
    /// compact JSON preimage, and BIP340 signs that 32-byte ID using zero
    /// auxiliary randomness for deterministic signing.
    ///
    /// # Errors
    ///
    /// Returns [`NostrEventError::InvalidSecretKey`] for a zero or invalid
    /// scalar, or [`NostrEventError::EventTooLarge`] if the complete compact
    /// event JSON would exceed [`MAX_NIP01_EVENT_JSON_BYTES`].
    pub fn create(
        secret_key: &[u8; 32],
        created_at: u64,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<Self, NostrEventError> {
        let signing_key =
            SigningKey::from_bytes(secret_key).map_err(|_| NostrEventError::InvalidSecretKey)?;
        let pubkey: [u8; 32] = signing_key.verifying_key().to_bytes().into();
        let id = calculate_id(pubkey, created_at, kind, &tags, &content)?;
        let signature = signing_key
            .sign_prehash_with_aux_rand(&id, &[0_u8; 32])
            .map_err(|_| NostrEventError::InvalidSignature)?;
        let event = Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: signature.to_bytes(),
        };
        event.to_json()?;
        Ok(event)
    }

    /// Parse an exact standard-field NIP-01 JSON object and validate its ID and
    /// Schnorr signature.
    ///
    /// Duplicate and unknown fields, incorrect field types, noncanonical
    /// lowercase-hex encodings, invalid keys or signatures, and mismatched IDs
    /// are rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed [`NostrEventError`] for malformed or invalid events, or
    /// [`NostrEventError::EventTooLarge`] when `json` exceeds the byte limit.
    pub fn parse_json(json: &[u8]) -> Result<Self, NostrEventError> {
        if json.len() > MAX_NIP01_EVENT_JSON_BYTES {
            return Err(NostrEventError::EventTooLarge { actual: json.len() });
        }

        let parsed: EventJsonOwned =
            serde_json::from_slice(json).map_err(|_| NostrEventError::InvalidJson)?;
        let id = decode_hex::<32>(&parsed.id, "id")?;
        let pubkey = decode_hex::<32>(&parsed.pubkey, "pubkey")?;
        let sig = decode_hex::<64>(&parsed.sig, "sig")?;

        VerifyingKey::from_bytes(&pubkey).map_err(|_| NostrEventError::InvalidPublicKey)?;
        Signature::try_from(sig.as_slice()).map_err(|_| NostrEventError::InvalidSignature)?;

        let event = Self {
            id,
            pubkey,
            created_at: parsed.created_at,
            kind: parsed.kind,
            tags: parsed.tags,
            content: parsed.content,
            sig,
        };
        event.verify_result()?;
        Ok(event)
    }

    /// Return compact standard-field JSON in deterministic field order.
    ///
    /// The output is bounded by [`MAX_NIP01_EVENT_JSON_BYTES`]. All binary
    /// fields are rendered as lowercase, fixed-width hexadecimal strings.
    ///
    /// # Errors
    ///
    /// Returns [`NostrEventError::EventTooLarge`] if the event exceeds the
    /// complete-JSON byte limit, or [`NostrEventError::SerializationFailed`]
    /// if JSON serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, NostrEventError> {
        let json = EventJsonRef {
            id: encode_hex(&self.id),
            pubkey: encode_hex(&self.pubkey),
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
            sig: encode_hex(&self.sig),
        };
        let encoded =
            serde_json::to_vec(&json).map_err(|_| NostrEventError::SerializationFailed)?;
        if encoded.len() > MAX_NIP01_EVENT_JSON_BYTES {
            return Err(NostrEventError::EventTooLarge {
                actual: encoded.len(),
            });
        }
        Ok(encoded)
    }

    /// Return the event ID as its 32-byte digest.
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Return the x-only secp256k1 public key as 32 bytes.
    #[must_use]
    pub const fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// Return the event creation time in Unix seconds.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Return the event kind without imposing relay-profile policy.
    #[must_use]
    pub const fn kind(&self) -> u64 {
        self.kind
    }

    /// Return ordered event tags.
    #[must_use]
    pub fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }

    /// Return the event content string.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Return the BIP340 signature as 64 bytes.
    #[must_use]
    pub const fn sig(&self) -> &[u8; 64] {
        &self.sig
    }

    /// Return the event ID digest as bytes.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Check that both the deterministic event ID and BIP340 signature match
    /// this event's fields.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_result().is_ok()
    }

    fn verify_result(&self) -> Result<(), NostrEventError> {
        let expected_id = calculate_id(
            self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;
        if self.id != expected_id {
            return Err(NostrEventError::IdMismatch);
        }

        let verifying_key = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|_| NostrEventError::InvalidPublicKey)?;
        let signature = Signature::try_from(self.sig.as_slice())
            .map_err(|_| NostrEventError::InvalidSignature)?;
        verifying_key
            .verify_raw(&self.id, &signature)
            .map_err(|_| NostrEventError::SignatureMismatch)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventJsonOwned {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

#[derive(Serialize)]
struct EventJsonRef<'a> {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: &'a [Vec<String>],
    content: &'a str,
    sig: String,
}

fn calculate_id(
    pubkey: [u8; 32],
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32], NostrEventError> {
    let pubkey_hex = encode_hex(&pubkey);
    let preimage = serde_json::to_vec(&(0_u8, pubkey_hex, created_at, kind, tags, content))
        .map_err(|_| NostrEventError::SerializationFailed)?;
    Ok(Sha256::digest(preimage).into())
}

fn encode_hex<const N: usize>(bytes: &[u8; N]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(N * 2);
    for byte in bytes {
        let byte = *byte;
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex<const N: usize>(
    encoded: &str,
    field: &'static str,
) -> Result<[u8; N], NostrEventError> {
    if encoded.len() != N * 2 {
        return Err(NostrEventError::InvalidHexWidth {
            field,
            expected: N * 2,
            actual: encoded.len(),
        });
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or(NostrEventError::InvalidHex { field })?;
        let low = decode_nibble(pair[1]).ok_or(NostrEventError::InvalidHex { field })?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_key() -> [u8; 32] {
        let mut secret = [0_u8; 32];
        secret[31] = 3;
        secret
    }

    #[test]
    fn create_and_parse_round_trip_preserves_order_and_json() {
        let event = NostrEventV1::create(
            &test_secret_key(),
            1_750_000_000,
            42,
            vec![
                vec!["e".into(), "abc".into()],
                vec!["p".into(), "def".into()],
            ],
            "hello 🌍".into(),
        )
        .unwrap();
        assert!(event.verify());

        let json = event.to_json().unwrap();
        let parsed = NostrEventV1::parse_json(&json).unwrap();
        assert_eq!(parsed, event);
        assert_eq!(parsed.to_json().unwrap(), json);
        assert_eq!(parsed.tags()[0][0], "e");
        assert_eq!(parsed.tags()[1][0], "p");
    }

    #[test]
    fn fixed_secret_produces_known_id_pubkey_and_bip340_signature() {
        let event = NostrEventV1::create(&test_secret_key(), 1, 1, vec![], String::new()).unwrap();
        assert_eq!(
            encode_hex(event.id()),
            "6968368de9af49462cef7874f22f2bd810cb3f5f97b71dba2b5454eaee917f01"
        );
        assert_eq!(
            encode_hex(event.pubkey()),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        assert_eq!(
            encode_hex(event.sig()),
            "b310b467d6e83d548c7beea685cdff8932308f459d94d0b1625d6ad6160d557bcbcb167397a572f74b384e9af7775ed9219564830d0bb5d49e995a0a5dc7d545"
        );
        assert!(event.verify());
    }

    #[test]
    fn verification_rejects_field_id_and_signature_tampering() {
        let event = NostrEventV1::create(
            &test_secret_key(),
            1,
            1,
            vec![vec!["t".into(), "test".into()]],
            "body".into(),
        )
        .unwrap();

        let mut changed_field = event.clone();
        changed_field.content.push('!');
        assert!(!changed_field.verify());

        let mut changed_id = event.clone();
        changed_id.id[0] ^= 1;
        assert!(!changed_id.verify());

        let mut changed_signature = event;
        changed_signature.sig[0] ^= 1;
        assert!(!changed_signature.verify());
    }

    #[test]
    fn parser_rejects_duplicate_unknown_and_noncanonical_hex_fields() {
        let event = NostrEventV1::create(&test_secret_key(), 1, 1, vec![], String::new()).unwrap();
        let json = String::from_utf8(event.to_json().unwrap()).unwrap();
        let duplicate_id = json.replacen(
            "{\"id\":",
            &format!("{{\"id\":\"{}\",\"id\":", encode_hex(event.id())),
            1,
        );
        assert_eq!(
            NostrEventV1::parse_json(duplicate_id.as_bytes()),
            Err(NostrEventError::InvalidJson)
        );

        let with_unknown = json.replacen("{\"id\":", "{\"extra\":0,\"id\":", 1);
        assert_eq!(
            NostrEventV1::parse_json(with_unknown.as_bytes()),
            Err(NostrEventError::InvalidJson)
        );

        let uppercase_id = json.replacen(
            &encode_hex(event.id()),
            &encode_hex(event.id()).to_uppercase(),
            1,
        );
        assert!(matches!(
            NostrEventV1::parse_json(uppercase_id.as_bytes()),
            Err(NostrEventError::InvalidHex { field: "id" })
        ));
    }

    #[test]
    fn hostile_nostr_json_corpus_never_returns_an_unverified_event() {
        let event = NostrEventV1::create(
            &test_secret_key(),
            42,
            39_001,
            vec![vec!["t".into(), "lattice1.test".into()]],
            "opaque".into(),
        )
        .expect("valid signed seed");
        let encoded = event.to_json().expect("serialize signed seed");
        for index in 0..encoded.len() {
            for mask in [0x01, 0x80] {
                let mut mutated = encoded.clone();
                mutated[index] ^= mask;
                if let Ok(decoded) = NostrEventV1::parse_json(&mutated) {
                    assert!(decoded.verify());
                }
            }
        }

        let mut state = 0x4528_21e6_38d0_1377_u64;
        for _ in 0..1_024 {
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
            let _ = NostrEventV1::parse_json(&input);
        }
    }
    #[test]
    fn complete_json_size_limit_includes_exact_boundary() {
        let empty = NostrEventV1::create(&test_secret_key(), 1, 1, vec![], String::new()).unwrap();
        let empty_size = empty.to_json().unwrap().len();
        let content_len = MAX_NIP01_EVENT_JSON_BYTES - empty_size;
        let at_limit =
            NostrEventV1::create(&test_secret_key(), 1, 1, vec![], "x".repeat(content_len))
                .unwrap();
        let json = at_limit.to_json().unwrap();
        assert_eq!(json.len(), MAX_NIP01_EVENT_JSON_BYTES);
        assert!(NostrEventV1::parse_json(&json).is_ok());

        let too_large = NostrEventV1::create(
            &test_secret_key(),
            1,
            1,
            vec![],
            "x".repeat(content_len + 1),
        );
        assert!(matches!(
            too_large,
            Err(NostrEventError::EventTooLarge { .. })
        ));

        let mut oversized_input = json;
        oversized_input.push(b' ');
        assert!(matches!(
            NostrEventV1::parse_json(&oversized_input),
            Err(NostrEventError::EventTooLarge { actual })
                if actual == MAX_NIP01_EVENT_JSON_BYTES + 1
        ));
    }
}
