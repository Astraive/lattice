//! Cross-layer validation for the accepted candidate Nostr mailbox profile.
//!
//! This module validates NIP-01 identity/signature, the exact profile tags,
//! canonical base64url, envelope metadata, and the inner signed event together.
//! It performs no network I/O and does not protect the caller-owned relay key or
//! mailbox token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use core::fmt;

use crate::nip01::{NostrEventError, NostrEventV1};
use crate::nip11::RelayCapabilities;
use crate::{DeliveryClass, EnvelopeError, EnvelopeV1};

/// NIP-01 event kind for an opaque Lattice envelope.
pub const LATTICE_RELAY_KIND: u64 = 39_001;
/// Maximum binary envelope payload admitted by the relay profile.
pub const MAX_RELAY_ENVELOPE_BYTES: usize = 45_000;
/// Maximum unpadded base64url content for a maximum-size profile envelope.
pub const MAX_RELAY_CONTENT_BYTES: usize = 60_000;
const MAILBOX_TAG_PREFIX: &str = "lattice1.";

/// A random per-generation mailbox token. It is not a Space or device ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxToken([u8; 32]);

impl MailboxToken {
    /// Constructs a token from its random fixed-width bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width mailbox token bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the exact private retrieval tag value.
    #[must_use]
    pub fn retrieval_tag(&self) -> String {
        format!("{MAILBOX_TAG_PREFIX}{}", lower_hex(&self.0))
    }
}

/// A fully validated Nostr event and its independently verified Lattice envelope.
#[derive(Debug, Eq, PartialEq)]
pub struct RelayProfileMessage {
    event: NostrEventV1,
    envelope: EnvelopeV1,
    mailbox: MailboxToken,
}

/// Failure to satisfy the candidate relay profile across protocol layers.
#[derive(Debug, Eq, PartialEq)]
pub enum RelayProfileError {
    /// The outer event is not the Lattice custom addressable kind.
    WrongKind,
    /// Tags are missing, extra, reordered, or have the wrong tuple shape.
    InvalidTags,
    /// The mailbox tag does not contain a 32-byte lowercase-hex token.
    InvalidMailboxTag,
    /// The expiration tag is not canonical unsigned decimal seconds.
    InvalidExpirationTag,
    /// The `d` tag does not equal the canonical envelope ID.
    EnvelopeAddressMismatch,
    /// The NIP-01 timestamp differs from the envelope creation time.
    CreationTimeMismatch,
    /// The NIP-40 expiration differs from the envelope expiry.
    ExpirationMismatch,
    /// Base64url is padded, noncanonical, malformed, or too large.
    InvalidContent,
    /// The inner envelope exceeds the relay-specific 45,000-byte limit.
    EnvelopeTooLarge(usize),
    /// File chunks are not eligible for the Nostr relay profile.
    UnsupportedDeliveryClass,
    /// NIP-11 did not advertise both required relay capabilities.
    IncompatibleRelay,
    /// NIP-01 event parsing or signature verification failed.
    Nostr(NostrEventError),
    /// Canonical envelope parsing or expiry validation failed.
    Envelope(EnvelopeError),
}

impl fmt::Display for RelayProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind => formatter.write_str("Nostr event is not Lattice relay kind 39001"),
            Self::InvalidTags => {
                formatter.write_str("Nostr event tags do not match the Lattice profile")
            }
            Self::InvalidMailboxTag => {
                formatter.write_str("Lattice mailbox retrieval tag is invalid")
            }
            Self::InvalidExpirationTag => {
                formatter.write_str("Nostr expiration tag is not canonical unsigned decimal")
            }
            Self::EnvelopeAddressMismatch => {
                formatter.write_str("Nostr d tag does not match the envelope ID")
            }
            Self::CreationTimeMismatch => {
                formatter.write_str("Nostr created_at does not match envelope creation time")
            }
            Self::ExpirationMismatch => {
                formatter.write_str("Nostr expiration does not match envelope expiry")
            }
            Self::InvalidContent => {
                formatter.write_str("Nostr content is not canonical bounded unpadded base64url")
            }
            Self::EnvelopeTooLarge(size) => write!(
                formatter,
                "relay envelope is {size} bytes; maximum is {MAX_RELAY_ENVELOPE_BYTES}"
            ),
            Self::UnsupportedDeliveryClass => {
                formatter.write_str("file chunks are not supported by the Nostr relay profile")
            }
            Self::IncompatibleRelay => {
                formatter.write_str("relay does not advertise NIP-40 and the required message size")
            }
            Self::Nostr(error) => write!(formatter, "invalid NIP-01 event: {error}"),
            Self::Envelope(error) => write!(formatter, "invalid Lattice envelope: {error}"),
        }
    }
}

impl std::error::Error for RelayProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Nostr(error) => Some(error),
            Self::Envelope(error) => Some(error),
            _ => None,
        }
    }
}

impl RelayProfileMessage {
    /// Creates a signed kind-39001 event for one existing protected envelope.
    ///
    /// The Nostr secret key must be independently generated and protected by the
    /// caller; this API never accepts or exports the Lattice device identity key.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized/file envelope or invalid Nostr key.
    pub fn create(
        envelope: EnvelopeV1,
        mailbox: MailboxToken,
        relay_secret_key: &[u8; 32],
    ) -> Result<Self, RelayProfileError> {
        validate_envelope_size(&envelope)?;
        if envelope.delivery_class() == DeliveryClass::FileChunk {
            return Err(RelayProfileError::UnsupportedDeliveryClass);
        }
        let content = URL_SAFE_NO_PAD.encode(envelope.encode());
        let tags = vec![
            vec!["d".to_owned(), lower_hex(envelope.envelope_id().as_bytes())],
            vec!["t".to_owned(), mailbox.retrieval_tag()],
            vec!["expiration".to_owned(), envelope.expires_at().to_string()],
        ];
        let event = NostrEventV1::create(
            relay_secret_key,
            envelope.created_at(),
            LATTICE_RELAY_KIND,
            tags,
            content,
        )
        .map_err(RelayProfileError::Nostr)?;
        Ok(Self {
            event,
            envelope,
            mailbox,
        })
    }

    /// Parses and validates all NIP-01, NIP-40, envelope, and inner-event layers.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid signatures/IDs, tags, content, expiry,
    /// unsupported delivery classes, or any envelope/inner-event violation.
    pub fn decode(json: &[u8], now: u64) -> Result<Self, RelayProfileError> {
        let event = NostrEventV1::parse_json(json).map_err(RelayProfileError::Nostr)?;
        if event.kind() != LATTICE_RELAY_KIND {
            return Err(RelayProfileError::WrongKind);
        }
        let tags = event.tags();
        if tags.len() != 3 || tags.iter().any(|tag| tag.len() != 2) {
            return Err(RelayProfileError::InvalidTags);
        }
        if tags[0][0] != "d" || tags[1][0] != "t" || tags[2][0] != "expiration" {
            return Err(RelayProfileError::InvalidTags);
        }
        let mailbox_hex = tags[1][1]
            .strip_prefix(MAILBOX_TAG_PREFIX)
            .ok_or(RelayProfileError::InvalidMailboxTag)?;
        let mailbox = MailboxToken(
            parse_lower_hex::<32>(mailbox_hex).ok_or(RelayProfileError::InvalidMailboxTag)?,
        );
        let expiration = tags[2][1]
            .parse::<u64>()
            .ok()
            .filter(|value| value.to_string() == tags[2][1])
            .ok_or(RelayProfileError::InvalidExpirationTag)?;
        if event.content().len() > MAX_RELAY_CONTENT_BYTES {
            return Err(RelayProfileError::InvalidContent);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(event.content())
            .map_err(|_| RelayProfileError::InvalidContent)?;
        if bytes.len() > MAX_RELAY_ENVELOPE_BYTES
            || URL_SAFE_NO_PAD.encode(&bytes) != event.content()
        {
            return Err(RelayProfileError::InvalidContent);
        }
        let envelope = EnvelopeV1::decode_at(&bytes, now).map_err(RelayProfileError::Envelope)?;
        validate_envelope_size(&envelope)?;
        if envelope.delivery_class() == DeliveryClass::FileChunk {
            return Err(RelayProfileError::UnsupportedDeliveryClass);
        }
        if tags[0][1] != lower_hex(envelope.envelope_id().as_bytes()) {
            return Err(RelayProfileError::EnvelopeAddressMismatch);
        }
        if event.created_at() != envelope.created_at() {
            return Err(RelayProfileError::CreationTimeMismatch);
        }
        if expiration != envelope.expires_at() {
            return Err(RelayProfileError::ExpirationMismatch);
        }
        Ok(Self {
            event,
            envelope,
            mailbox,
        })
    }

    /// Returns the validated signed outer event.
    #[must_use]
    pub const fn event(&self) -> &NostrEventV1 {
        &self.event
    }

    /// Returns the verified protected inner envelope.
    #[must_use]
    pub const fn envelope(&self) -> &EnvelopeV1 {
        &self.envelope
    }

    /// Returns the per-generation retrieval token.
    #[must_use]
    pub const fn mailbox(&self) -> MailboxToken {
        self.mailbox
    }

    /// Serializes the validated NIP-01 event to its bounded canonical JSON form.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProfileError::Nostr`] if the serialized NIP-01 event
    /// exceeds its protocol bound or serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, RelayProfileError> {
        self.event.to_json().map_err(RelayProfileError::Nostr)
    }
}

/// Fails closed unless NIP-11 advertises the required NIP-40 and event size.
///
/// # Errors
///
/// Returns [`RelayProfileError::IncompatibleRelay`] when either required
/// capability is absent or below the profile minimum.
pub fn require_compatible_relay(capabilities: &RelayCapabilities) -> Result<(), RelayProfileError> {
    if capabilities.supports_lattice_profile() {
        Ok(())
    } else {
        Err(RelayProfileError::IncompatibleRelay)
    }
}

fn validate_envelope_size(envelope: &EnvelopeV1) -> Result<(), RelayProfileError> {
    let size = envelope.encode().len();
    if size > MAX_RELAY_ENVELOPE_BYTES {
        return Err(RelayProfileError::EnvelopeTooLarge(size));
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = lower_hex_nibble(pair[0])?;
        let low = lower_hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::DeviceIdentity;

    use super::{
        LATTICE_RELAY_KIND, MailboxToken, RelayProfileError, RelayProfileMessage,
        require_compatible_relay,
    };
    use crate::nip01::NostrEventV1;
    use crate::nip11::{LATTICE_PROFILE_MIN_MESSAGE_LENGTH, RelayCapabilities};
    use crate::{DeliveryClass, EnvelopeV1};

    fn envelope() -> EnvelopeV1 {
        let identity = DeviceIdentity::generate().expect("device identity");
        let event = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id: [1; 16],
                channel_id: None,
                author_sequence: 1,
                lamport: 0,
                wall_time_hint: 0,
                parents: Vec::new(),
                kind: EventKind::Message,
                protected_body: vec![0x01, 0x02],
                mls_group_reference: [2; 32],
                mls_epoch: 0,
            },
        )
        .expect("signed event");
        EnvelopeV1::new(event, DeliveryClass::InteractiveText, 100, 200, 1, 1)
            .expect("bounded envelope")
    }

    #[test]
    fn round_trip_checks_nostr_tags_envelope_expiry_and_inner_signature() {
        let original = envelope();
        let mailbox = MailboxToken::from_bytes([3; 32]);
        let message =
            RelayProfileMessage::create(original, mailbox, &[1; 32]).expect("profile event");
        let json = message.to_json().expect("serialize profile event");
        let decoded = RelayProfileMessage::decode(&json, 150).expect("validate all layers");
        assert_eq!(decoded.envelope(), message.envelope());
        assert_eq!(decoded.mailbox(), mailbox);
        assert_eq!(decoded.event().kind(), LATTICE_RELAY_KIND);
        assert_eq!(
            RelayProfileMessage::decode(&json, 200),
            Err(RelayProfileError::Envelope(crate::EnvelopeError::Expired {
                expires_at: 200,
                now: 200,
            }))
        );
    }

    #[test]
    fn mismatched_expiration_and_unsupported_relay_capabilities_fail_closed() {
        let original = envelope();
        let mailbox = MailboxToken::from_bytes([3; 32]);
        let base = RelayProfileMessage::create(original, mailbox, &[1; 32]).expect("profile event");
        let mut tags = base.event().tags().to_vec();
        tags[2][1] = "201".to_owned();
        let forged_expiration = NostrEventV1::create(
            &[1; 32],
            base.event().created_at(),
            LATTICE_RELAY_KIND,
            tags,
            base.event().content().to_owned(),
        )
        .expect("validly signed mismatched profile event")
        .to_json()
        .expect("serialize mismatched event");
        assert_eq!(
            RelayProfileMessage::decode(&forged_expiration, 150),
            Err(RelayProfileError::ExpirationMismatch)
        );
        assert_eq!(
            require_compatible_relay(&RelayCapabilities {
                supported_nips: Some(vec![40]),
                max_message_length: Some(LATTICE_PROFILE_MIN_MESSAGE_LENGTH - 1),
            }),
            Err(RelayProfileError::IncompatibleRelay)
        );
        assert!(
            require_compatible_relay(&RelayCapabilities {
                supported_nips: Some(vec![40]),
                max_message_length: Some(LATTICE_PROFILE_MIN_MESSAGE_LENGTH),
            })
            .is_ok()
        );
    }
}
