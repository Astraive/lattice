//! One-shot publication of durable outbox envelopes through the versioned
//! opaque Nostr mailbox profile.
//!
//! Relay acceptance records only local forwarding. This module never marks an
//! outbox item delivered; that requires a separate destination receipt.

use std::collections::{HashMap, HashSet};

use lattice_events::{EventKind, VerifiedSignatureOnlyEvent};
use lattice_platform::{OsKeyringProtectionError, OsKeyringProtector};
use lattice_relay::{
    DeliveryClass, EnvelopeV1, MAX_ENVELOPE_LIFETIME_SECONDS,
    network::{MAX_RETRIEVED_EVENTS, RelayClient, RelayNetworkError},
    profile::{
        MailboxToken, RelayProfileError, RelayProfileMessage, RelaySigningKey, RelaySigningKeyError,
    },
    settings::{RelaySettingsError, validate_relay_url},
};
use lattice_storage::{MAX_OUTBOX_EVENTS, MAX_OUTBOX_PAGE_SIZE, OutboxState, Store, StoreError};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Failures while validating, publishing, or recording one outbox relay hop.
#[derive(Debug, Error)]
pub enum RelayOutboxError {
    /// The caller supplied a negative next-attempt timestamp.
    #[error("next outbox attempt time must be nonnegative")]
    InvalidSchedule,
    /// The durable outbox row was not found.
    #[error("outbox event was not found")]
    MissingOutboxEntry,
    /// Only nonterminal rows can be sent to a relay.
    #[error("outbox state {0:?} cannot be forwarded")]
    NotForwardable(OutboxState),
    /// The attempt counter cannot advance without overflowing its durable width.
    #[error("outbox forwarding attempt counter is exhausted")]
    AttemptsExhausted,
    /// The two-endpoint round requires distinct, secure WSS URLs.
    #[error("relay round requires two distinct secure relay URLs")]
    InvalidRelaySet,
    /// A relay URL is invalid under the shared relay-settings policy.
    #[error("invalid relay URL: {0}")]
    RelayUrl(#[from] RelaySettingsError),
    /// Durable bytes are not a valid, unexpired candidate envelope.
    #[error("invalid outbox envelope: {0}")]
    Envelope(#[from] lattice_relay::EnvelopeError),
    /// The outbox row's event identifier differs from the verified inner event.
    #[error("outbox event ID does not match the envelope inner event ID")]
    InnerEventMismatch,
    /// Durable event has a kind excluded from relay-profile publication.
    #[error("outbox event kind cannot be published through the relay profile")]
    IneligibleInnerEvent,
    /// The envelope cannot be represented by the versioned relay profile.
    #[error("relay profile rejected envelope: {0}")]
    Profile(#[from] RelayProfileError),
    /// The relay operation failed before a positive exact-event `OK` receipt.
    #[error("relay operation failed: {0}")]
    Network(#[from] RelayNetworkError),
    /// The relay accepted the event, but local forwarding state could not be saved.
    #[error(
        "relay accepted event {relay_event_id:02x?}, but local forwarding state was not saved: {source}"
    )]
    AcceptedButNotRecorded {
        relay_event_id: [u8; 32],
        #[source]
        source: StoreError,
    },
    /// Local storage failed while loading the durable outbox row.
    #[error("outbox storage failed: {0}")]
    Storage(#[from] StoreError),
}

/// Retrieval-round configuration or decoded-message failures.
#[derive(Debug, Error)]
pub enum RelayRetrievalError {
    /// The two-endpoint round requires distinct secure WSS URLs.
    #[error("relay round requires two distinct secure relay URLs")]
    InvalidRelaySet,
    /// A relay URL is invalid under the shared relay-settings policy.
    #[error("invalid relay URL: {0}")]
    RelayUrl(#[from] RelaySettingsError),
    /// A validated outer event could not be serialized for exact deduplication.
    #[error("relay message could not be serialized for exact deduplication: {0}")]
    Profile(#[from] RelayProfileError),
}

/// Error while validating one caller-supplied relay URL and peer.
fn validate_relay_pair(urls: [&str; 2]) -> Result<(), RelayOutboxError> {
    if urls[0] == urls[1] {
        return Err(RelayOutboxError::InvalidRelaySet);
    }
    validate_relay_url(urls[0])?;
    validate_relay_url(urls[1])?;
    Ok(())
}

const RELAY_KEY_RECORD_DOMAIN: &[u8] = b"lattice:relay-signing-key-record:v1\0";

/// Loads or initializes this identity's relay-only signing key under the
/// platform profile protector. The raw secret is never persisted in app data.
///
/// # Errors
///
/// Returns an error if the stored key cannot be unprotected, key material cannot be generated, or a storage operation fails.
pub fn load_or_create_relay_signing_key(
    store: &mut Store,
    protector: &OsKeyringProtector,
    identity_fingerprint: &[u8; 32],
) -> Result<RelaySigningKey, RelaySigningKeyStorageError> {
    if let Some(ciphertext) = store.load_protected_relay_signing_key(identity_fingerprint)? {
        return unprotect_relay_signing_key(protector, &ciphertext, identity_fingerprint);
    }

    let candidate = RelaySigningKey::generate()?;
    let plaintext = relay_signing_key_payload(identity_fingerprint, candidate.as_bytes());
    let ciphertext = protector.wrap_detailed(&plaintext)?;
    if store.save_protected_relay_signing_key(identity_fingerprint, &ciphertext)? {
        return Ok(candidate);
    }

    let ciphertext = store
        .load_protected_relay_signing_key(identity_fingerprint)?
        .ok_or(RelaySigningKeyStorageError::MissingAfterRace)?;
    unprotect_relay_signing_key(protector, &ciphertext, identity_fingerprint)
}

fn relay_signing_key_payload(
    identity_fingerprint: &[u8; 32],
    key_bytes: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(
        RELAY_KEY_RECORD_DOMAIN.len() + identity_fingerprint.len() + key_bytes.len(),
    ));
    payload.extend_from_slice(RELAY_KEY_RECORD_DOMAIN);
    payload.extend_from_slice(identity_fingerprint);
    payload.extend_from_slice(key_bytes);
    payload
}

fn unprotect_relay_signing_key(
    protector: &OsKeyringProtector,
    ciphertext: &[u8],
    identity_fingerprint: &[u8; 32],
) -> Result<RelaySigningKey, RelaySigningKeyStorageError> {
    let plaintext = Zeroizing::new(protector.unwrap_detailed(ciphertext)?);
    let key = decode_relay_signing_key_payload(identity_fingerprint, &plaintext)?;
    Ok(RelaySigningKey::from_bytes(*key)?)
}

fn decode_relay_signing_key_payload(
    identity_fingerprint: &[u8; 32],
    plaintext: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RelaySigningKeyStorageError> {
    let expected_len = RELAY_KEY_RECORD_DOMAIN.len() + identity_fingerprint.len() + 32;
    if plaintext.len() != expected_len {
        return Err(RelaySigningKeyStorageError::InvalidKeyWidth);
    }
    let identity_start = RELAY_KEY_RECORD_DOMAIN.len();
    let key_start = identity_start + identity_fingerprint.len();
    if plaintext.get(..identity_start) != Some(RELAY_KEY_RECORD_DOMAIN)
        || plaintext.get(identity_start..key_start) != Some(identity_fingerprint)
    {
        return Err(RelaySigningKeyStorageError::IdentityMismatch);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&plaintext[key_start..]);
    Ok(key)
}

/// Caller-controlled inputs for one bounded two-relay publication round.
pub struct RelayOutboxRoundRequest<'a> {
    /// Inner event ID used to reload one durable outbox row.
    pub event_id: [u8; 32],
    /// Two independently configured secure relay endpoints.
    pub relay_urls: [&'a str; 2],
    /// Generation-scoped opaque mailbox selector.
    pub mailbox: MailboxToken,
    /// Independently generated and platform-protected Schnorr relay key.
    pub relay_signing_key: &'a RelaySigningKey,
    /// Current Unix time in seconds for exact envelope expiry validation.
    pub now_seconds: u64,
    /// Nonnegative next-attempt Unix time in milliseconds.
    pub next_attempt_ms: i64,
}

/// Per-endpoint result of the bounded relay publication round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPublishStatus {
    /// Exact configured endpoint.
    pub relay_url: String,
    /// Acceptance or failure for this relay only.
    pub outcome: RelayPublishOutcome,
}

/// A relay acceptance never represents recipient delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayPublishOutcome {
    /// The endpoint returned a matching positive NIP-01 `OK`.
    Accepted { relay_event_id: [u8; 32] },
    /// This endpoint rejected the event or failed independently.
    Failed { reason: String },
    /// The endpoint accepted the event, but local forwarding status was not persisted.
    AcceptedButNotRecorded {
        relay_event_id: [u8; 32],
        reason: String,
    },
}

/// Per-endpoint result of one bounded mailbox retrieval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRetrievalStatus {
    /// Exact configured endpoint.
    pub relay_url: String,
    /// Number of independently validated profile messages returned by this endpoint.
    pub retrieved: usize,
    /// Network, cancellation, or response-limit failure; absence means this query reached EOSE.
    pub error: Option<String>,
}

/// One unique validated message retained from a relay response.
#[derive(Debug)]
pub struct RelayRetrievedMessage {
    /// First relay endpoint that returned this unique inner event.
    pub source_relay_url: String,
    /// Fully NIP-01- and envelope-validated profile event.
    pub message: RelayProfileMessage,
}

/// Results from two independent relay queries after ID-level deduplication.
#[derive(Debug)]
pub struct RelayMailboxRound {
    /// First-seen unique envelopes, ready for the caller's Core authenticated ingress.
    pub messages: Vec<RelayRetrievedMessage>,
    /// Independent status from each queried endpoint.
    pub relays: [RelayRetrievalStatus; 2],
    /// Number of detected ID/decoded-byte integrity conflicts.
    pub integrity_conflicts: usize,
}

/// Failures while loading or initializing a protected relay-only key.
#[derive(Debug, Error)]
pub enum RelaySigningKeyStorageError {
    /// Durable protected key storage failed.
    #[error("relay signing-key storage failed: {0}")]
    Storage(#[from] StoreError),
    /// The platform protector could not wrap or unwrap the key.
    #[error("relay signing-key platform protection failed: {0}")]
    Platform(#[from] OsKeyringProtectionError),
    /// The loaded or generated value is not a valid Schnorr key.
    #[error("relay signing-key material is invalid: {0}")]
    Key(#[from] RelaySigningKeyError),
    /// The record disappeared after another initializer won the insert race.
    #[error("protected relay signing-key record disappeared after initialization")]
    MissingAfterRace,
    /// The protected key record did not contain exactly 32 secret bytes.
    #[error("protected relay signing-key material has the wrong width")]
    InvalidKeyWidth,
    /// The protected key record is not bound to the requested identity.
    #[error("protected relay signing-key record belongs to another identity")]
    IdentityMismatch,
}

fn outbox_entry_envelope(
    entry: &lattice_storage::OutboxEntry,
    now_seconds: u64,
) -> Result<EnvelopeV1, RelayOutboxError> {
    if let Ok(envelope) = EnvelopeV1::decode(&entry.envelope_bytes) {
        if envelope.event_id().as_bytes() != &entry.event_id {
            return Err(RelayOutboxError::InnerEventMismatch);
        }
        if envelope.expires_at() <= now_seconds {
            return Err(RelayOutboxError::Envelope(
                lattice_relay::EnvelopeError::Expired {
                    expires_at: envelope.expires_at(),
                    now: now_seconds,
                },
            ));
        }
        return Ok(envelope);
    }

    let event =
        VerifiedSignatureOnlyEvent::decode_verify(&entry.envelope_bytes).map_err(|error| {
            RelayOutboxError::Envelope(lattice_relay::EnvelopeError::InvalidSignedEvent(error))
        })?;
    if event.event_id().as_bytes() != &entry.event_id {
        return Err(RelayOutboxError::InnerEventMismatch);
    }
    let created_at = event.wall_time_hint() / 1_000;
    let expires_at = created_at
        .checked_add(MAX_ENVELOPE_LIFETIME_SECONDS)
        .ok_or(RelayOutboxError::Envelope(
            lattice_relay::EnvelopeError::ExpiryTooFar,
        ))?;
    let delivery_class = match event.kind() {
        EventKind::Membership
        | EventKind::MlsControl
        | EventKind::RelayMailboxControl
        | EventKind::FileManifest => DeliveryClass::SecurityDependency,
        EventKind::Message
        | EventKind::Edit
        | EventKind::Tombstone
        | EventKind::Reaction
        | EventKind::Pin => DeliveryClass::InteractiveText,
        EventKind::VoiceSignal => DeliveryClass::DeferredHistory,
        EventKind::Ephemeral => return Err(RelayOutboxError::IneligibleInnerEvent),
    };
    let envelope = EnvelopeV1::new(event, delivery_class, created_at, expires_at, 0, 0)?;
    if envelope.expires_at() <= now_seconds {
        return Err(RelayOutboxError::Envelope(
            lattice_relay::EnvelopeError::Expired {
                expires_at: envelope.expires_at(),
                now: now_seconds,
            },
        ));
    }
    Ok(envelope)
}

fn validate_relay_pair_for_retrieval(urls: [&str; 2]) -> Result<(), RelayRetrievalError> {
    if urls[0] == urls[1] {
        return Err(RelayRetrievalError::InvalidRelaySet);
    }
    validate_relay_url(urls[0])?;
    validate_relay_url(urls[1])?;
    Ok(())
}

/// Publishes one exact, deterministically wrapped outbox event to both relays.
///
/// A single outer event is signed before either connection and sent unchanged
/// to both independently configured endpoints. Each matching positive `OK`
/// records relay acceptance as `Forwarded`, never recipient delivery. A failure
/// from one relay does not prevent attempting the other.
///
/// # Errors
///
/// Returns an error if relay configuration, scheduling, the outbox row, or the envelope is invalid, or a storage operation fails.
pub async fn publish_outbox_entry_to_two_relays(
    store: &mut Store,
    relay: &RelayClient,
    request: RelayOutboxRoundRequest<'_>,
    cancellation: &CancellationToken,
) -> Result<[RelayPublishStatus; 2], RelayOutboxError> {
    let RelayOutboxRoundRequest {
        event_id,
        relay_urls,
        mailbox,
        relay_signing_key,
        now_seconds,
        next_attempt_ms,
    } = request;
    validate_relay_pair(relay_urls)?;
    if next_attempt_ms < 0 {
        return Err(RelayOutboxError::InvalidSchedule);
    }
    let entry = load_outbox_entry(store, event_id)?;
    if !matches!(
        entry.state,
        OutboxState::Queued
            | OutboxState::Forwarding
            | OutboxState::Forwarded
            | OutboxState::PeerIngressAccepted
    ) {
        return Err(RelayOutboxError::NotForwardable(entry.state));
    }
    if entry.attempt_count == u32::MAX {
        return Err(RelayOutboxError::AttemptsExhausted);
    }
    let envelope = outbox_entry_envelope(&entry, now_seconds)?;
    let message = RelayProfileMessage::create(envelope, mailbox, relay_signing_key.as_bytes())?;
    store.mark_forwarding_attempt(event_id, next_attempt_ms)?;

    let (first, second) = tokio::join!(
        relay.publish(relay_urls[0], &message, cancellation),
        relay.publish(relay_urls[1], &message, cancellation),
    );
    let first = first
        .map(|acceptance| *acceptance.event_id())
        .map_err(|e| e.to_string());
    let second = second
        .map(|acceptance| *acceptance.event_id())
        .map_err(|e| e.to_string());
    Ok([
        record_relay_round_result(store, event_id, relay_urls[0], next_attempt_ms, first),
        record_relay_round_result(store, event_id, relay_urls[1], next_attempt_ms, second),
    ])
}

fn record_relay_round_result(
    store: &mut Store,
    event_id: [u8; 32],
    relay_url: &str,
    next_attempt_ms: i64,
    result: Result<[u8; 32], String>,
) -> RelayPublishStatus {
    let outcome = match result {
        Ok(relay_event_id) => {
            match record_relay_acceptance(store, event_id, relay_event_id, next_attempt_ms) {
                Ok(()) => RelayPublishOutcome::Accepted { relay_event_id },
                Err(error) => RelayPublishOutcome::AcceptedButNotRecorded {
                    relay_event_id,
                    reason: error.to_string(),
                },
            }
        }
        Err(reason) => RelayPublishOutcome::Failed { reason },
    };
    RelayPublishStatus {
        relay_url: relay_url.to_owned(),
        outcome,
    }
}

/// Queries both relays using the exact generation mailbox and merges their
/// individually bounded results. Results preserve first-seen endpoint and
/// response order; Core ingress remains responsible for causal dependency
/// resolution and authentication before projection.
///
/// # Errors
///
/// Returns an error if relay configuration is invalid or retrieved messages conflict during exact deduplication. Per-relay network failures are returned in the round statuses.
pub async fn retrieve_mailbox_from_two_relays(
    relay: &RelayClient,
    relay_urls: [&str; 2],
    mailbox: MailboxToken,
    now_seconds: u64,
    cancellation: &CancellationToken,
) -> Result<RelayMailboxRound, RelayRetrievalError> {
    validate_relay_pair_for_retrieval(relay_urls)?;
    let (first, second) = tokio::join!(
        relay.retrieve(relay_urls[0], mailbox, now_seconds, cancellation),
        relay.retrieve(relay_urls[1], mailbox, now_seconds, cancellation),
    );
    let mut candidates = Vec::with_capacity(2 * MAX_RETRIEVED_EVENTS);
    let relay_statuses = [
        record_retrieval_result(&mut candidates, relay_urls[0], first),
        record_retrieval_result(&mut candidates, relay_urls[1], second),
    ];
    let (messages, integrity_conflicts) =
        deduplicate_relay_candidates(candidates).map_err(RelayRetrievalError::Profile)?;
    Ok(RelayMailboxRound {
        messages,
        relays: relay_statuses,
        integrity_conflicts,
    })
}

fn record_retrieval_result(
    candidates: &mut Vec<(String, RelayProfileMessage)>,
    relay_url: &str,
    result: Result<Vec<RelayProfileMessage>, RelayNetworkError>,
) -> RelayRetrievalStatus {
    match result {
        Ok(messages) => {
            let retrieved = messages.len();
            candidates.extend(
                messages
                    .into_iter()
                    .map(|message| (relay_url.to_owned(), message)),
            );
            RelayRetrievalStatus {
                relay_url: relay_url.to_owned(),
                retrieved,
                error: None,
            }
        }
        Err(error) => RelayRetrievalStatus {
            relay_url: relay_url.to_owned(),
            retrieved: 0,
            error: Some(error.to_string()),
        },
    }
}

fn deduplicate_relay_candidates(
    candidates: Vec<(String, RelayProfileMessage)>,
) -> Result<(Vec<RelayRetrievedMessage>, usize), RelayProfileError> {
    let mut outer_bytes = HashMap::<[u8; 32], Vec<u8>>::new();
    let mut envelope_bytes = HashMap::<[u8; 32], Vec<u8>>::new();
    let mut inner_bytes = HashMap::<[u8; 32], Vec<u8>>::new();
    let mut outer_conflicts = HashSet::new();
    let mut envelope_conflicts = HashSet::new();
    let mut inner_conflicts = HashSet::new();

    for (_, message) in &candidates {
        let outer_id = *message.event().id();
        let envelope_id = *message.envelope().envelope_id().as_bytes();
        let inner_id = *message.envelope().event_id().as_bytes();
        let outer = message.to_json()?;
        let envelope = message.envelope().encode().to_vec();
        let inner = message.envelope().signed_event_bytes().to_vec();
        record_identity(&mut outer_bytes, &mut outer_conflicts, outer_id, outer);
        record_identity(
            &mut envelope_bytes,
            &mut envelope_conflicts,
            envelope_id,
            envelope,
        );
        record_identity(&mut inner_bytes, &mut inner_conflicts, inner_id, inner);
    }

    let integrity_conflicts =
        outer_conflicts.len() + envelope_conflicts.len() + inner_conflicts.len();
    let mut seen_outer = HashSet::new();
    let mut seen_envelope = HashSet::new();
    let mut seen_inner = HashSet::new();
    let mut messages = Vec::with_capacity(candidates.len());
    for (source_relay_url, message) in candidates {
        let outer_id = *message.event().id();
        let envelope_id = *message.envelope().envelope_id().as_bytes();
        let inner_id = *message.envelope().event_id().as_bytes();
        if outer_conflicts.contains(&outer_id)
            || envelope_conflicts.contains(&envelope_id)
            || inner_conflicts.contains(&inner_id)
            || seen_outer.contains(&outer_id)
            || seen_envelope.contains(&envelope_id)
            || seen_inner.contains(&inner_id)
        {
            continue;
        }
        seen_outer.insert(outer_id);
        seen_envelope.insert(envelope_id);
        seen_inner.insert(inner_id);
        messages.push(RelayRetrievedMessage {
            source_relay_url,
            message,
        });
    }
    Ok((messages, integrity_conflicts))
}

fn record_identity(
    known: &mut HashMap<[u8; 32], Vec<u8>>,
    conflicts: &mut HashSet<[u8; 32]>,
    id: [u8; 32],
    decoded_bytes: Vec<u8>,
) {
    match known.entry(id) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(decoded_bytes);
        }
        std::collections::hash_map::Entry::Occupied(entry) if entry.get() != &decoded_bytes => {
            conflicts.insert(id);
        }
        std::collections::hash_map::Entry::Occupied(_) => {}
    }
}

fn record_relay_acceptance(
    store: &mut Store,
    event_id: [u8; 32],
    relay_event_id: [u8; 32],
    next_attempt_ms: i64,
) -> Result<(), RelayOutboxError> {
    store
        .mark_forwarded(event_id, next_attempt_ms)
        .map_err(|source| RelayOutboxError::AcceptedButNotRecorded {
            relay_event_id,
            source,
        })
}

fn load_outbox_entry(
    store: &Store,
    event_id: [u8; 32],
) -> Result<lattice_storage::OutboxEntry, RelayOutboxError> {
    let mut after = None;
    let page_count = MAX_OUTBOX_EVENTS.div_ceil(MAX_OUTBOX_PAGE_SIZE);
    for _ in 0..page_count {
        let page = store.list_outbox_page(after, MAX_OUTBOX_PAGE_SIZE)?;
        if let Some(entry) = page.iter().find(|entry| entry.event_id == event_id) {
            return Ok(entry.clone());
        }
        if page.len() < MAX_OUTBOX_PAGE_SIZE {
            break;
        }
        after = page.last().map(|entry| entry.event_id);
    }
    Err(RelayOutboxError::MissingOutboxEntry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_events::EventDraft;
    use lattice_identity::DeviceIdentity;
    use std::time::Duration;

    #[test]
    fn relay_signing_key_record_is_bound_to_its_device_identity() {
        let identity = [0x11; 32];
        let other_identity = [0x22; 32];
        let key = RelaySigningKey::generate().expect("relay-only Schnorr key");
        let payload = relay_signing_key_payload(&identity, key.as_bytes());

        let restored =
            decode_relay_signing_key_payload(&identity, &payload).expect("load bound key record");
        assert_eq!(&*restored, key.as_bytes());
        assert!(matches!(
            decode_relay_signing_key_payload(&other_identity, &payload),
            Err(RelaySigningKeyStorageError::IdentityMismatch)
        ));
        let mut wrong_domain = payload.to_vec();
        wrong_domain[0] ^= 1;
        assert!(matches!(
            decode_relay_signing_key_payload(&identity, &wrong_domain),
            Err(RelaySigningKeyStorageError::IdentityMismatch)
        ));
    }

    fn signed_application_event(
        identity: &DeviceIdentity,
        author_sequence: u64,
        wall_time_hint: u64,
    ) -> VerifiedSignatureOnlyEvent {
        VerifiedSignatureOnlyEvent::create(
            identity,
            EventDraft {
                space_id: [0x11; 16],
                channel_id: None,
                author_sequence,
                lamport: author_sequence,
                wall_time_hint,
                parents: Vec::new(),
                kind: EventKind::Message,
                protected_body: vec![0x42],
                mls_group_reference: [0x22; 32],
                mls_epoch: 1,
            },
        )
        .expect("signed application event")
    }

    fn relay_message(author_sequence: u64) -> RelayProfileMessage {
        let identity = DeviceIdentity::generate().expect("device identity");
        let created_at = 10_000 + author_sequence;
        let event = signed_application_event(&identity, author_sequence, created_at * 1_000);
        let envelope = EnvelopeV1::new(
            event,
            DeliveryClass::InteractiveText,
            created_at,
            created_at + MAX_ENVELOPE_LIFETIME_SECONDS,
            0,
            0,
        )
        .expect("bounded envelope");
        RelayProfileMessage::create(envelope, MailboxToken::from_bytes([0x33; 32]), &[1; 32])
            .expect("signed relay message")
    }

    #[test]
    fn raw_outbox_signed_event_wraps_deterministically_without_rewriting_row() {
        let identity = DeviceIdentity::generate().expect("device identity");
        let event = signed_application_event(&identity, 1, 1_500_000);
        let event_id = *event.event_id().as_bytes();
        let event_bytes = event.encode();
        let mut store = Store::open(":memory:").expect("open store");
        store
            .commit_authored_with_outbox(
                *event.author_fingerprint(),
                event_id,
                event.author_sequence(),
                event_bytes,
                &[],
                event_bytes,
                0,
            )
            .expect("commit exact signed-event outbox bytes");
        let entry = store.list_outbox_page(None, 1).expect("read outbox")[0].clone();

        let first = outbox_entry_envelope(&entry, 1_600).expect("wrap durable event");
        let retry = outbox_entry_envelope(&entry, 1_900).expect("wrap retry deterministically");

        assert_eq!(first.event_id().as_bytes(), &event_id);
        assert_eq!(first.created_at(), 1_500);
        assert_eq!(first.expires_at(), 1_500 + MAX_ENVELOPE_LIFETIME_SECONDS);
        assert_eq!(first.encode(), retry.encode());
        assert_eq!(entry.envelope_bytes, event_bytes);
    }

    #[test]
    fn two_relay_candidates_deduplicate_and_preserve_first_seen_order() {
        let later = relay_message(2);
        let earlier = relay_message(1);
        let duplicate =
            RelayProfileMessage::decode(&later.to_json().expect("serialize duplicate"), 20_000)
                .expect("decode duplicate");

        let (messages, integrity_conflicts) = deduplicate_relay_candidates(vec![
            ("wss://relay-a.example".to_owned(), later),
            ("wss://relay-b.example".to_owned(), earlier),
            ("wss://relay-b.example".to_owned(), duplicate),
        ])
        .expect("deduplicate validated relay candidates");

        assert_eq!(integrity_conflicts, 0);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].source_relay_url, "wss://relay-a.example");
        assert_eq!(messages[1].source_relay_url, "wss://relay-b.example");
        assert_eq!(messages[0].message.envelope().event().author_sequence(), 2);
        assert_eq!(messages[1].message.envelope().event().author_sequence(), 1);
    }

    #[test]
    fn one_relay_acceptance_and_one_failure_keep_independent_outcomes() {
        let mut store = queued_store();
        store
            .mark_forwarding_attempt([0x22; 32], 45)
            .expect("record relay attempt");

        let accepted = record_relay_round_result(
            &mut store,
            [0x22; 32],
            "wss://relay-a.example",
            45,
            Ok([0x44; 32]),
        );
        let failed = record_relay_round_result(
            &mut store,
            [0x22; 32],
            "wss://relay-b.example",
            45,
            Err("relay timeout".to_owned()),
        );

        assert_eq!(
            accepted.outcome,
            RelayPublishOutcome::Accepted {
                relay_event_id: [0x44; 32]
            }
        );
        assert_eq!(
            failed.outcome,
            RelayPublishOutcome::Failed {
                reason: "relay timeout".to_owned()
            }
        );
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Forwarded);
        assert_ne!(row[0].state, OutboxState::Delivered);
    }

    fn queued_store() -> Store {
        let mut store = Store::open(":memory:").expect("open store");
        store
            .commit_authored_with_outbox([0x11; 32], [0x22; 32], 1, &[0xa1], &[], &[0x01], 0)
            .expect("commit outbox row");
        store
    }

    #[test]
    fn accepted_relay_event_marks_only_outbox_forwarded() {
        let mut store = queued_store();
        store
            .mark_forwarding_attempt([0x22; 32], 45)
            .expect("record relay attempt");
        record_relay_acceptance(&mut store, [0x22; 32], [0x44; 32], 45)
            .expect("record relay acceptance");
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Forwarded);
        assert_eq!(row[0].attempt_count, 1);
        assert_eq!(row[0].next_attempt_ms, 45);
    }

    #[tokio::test]
    async fn two_relay_outbox_preflight_rejects_schedule_and_malformed_events() {
        let mut store = queued_store();
        let relay = RelayClient::new(Duration::from_secs(1)).expect("relay client");
        let cancellation = CancellationToken::new();
        let relay_signing_key = RelaySigningKey::from_bytes([1; 32]).expect("relay key");
        assert!(matches!(
            Box::pin(publish_outbox_entry_to_two_relays(
                &mut store,
                &relay,
                RelayOutboxRoundRequest {
                    event_id: [0x22; 32],
                    relay_urls: ["wss://relay-a.example", "wss://relay-b.example"],
                    mailbox: MailboxToken::from_bytes([0x33; 32]),
                    relay_signing_key: &relay_signing_key,
                    now_seconds: 10,
                    next_attempt_ms: -1,
                },
                &cancellation,
            ))
            .await,
            Err(RelayOutboxError::InvalidSchedule)
        ));
        assert!(matches!(
            Box::pin(publish_outbox_entry_to_two_relays(
                &mut store,
                &relay,
                RelayOutboxRoundRequest {
                    event_id: [0x22; 32],
                    relay_urls: ["wss://relay-a.example", "wss://relay-b.example"],
                    mailbox: MailboxToken::from_bytes([0x33; 32]),
                    relay_signing_key: &relay_signing_key,
                    now_seconds: 10,
                    next_attempt_ms: 20,
                },
                &cancellation,
            ))
            .await,
            Err(RelayOutboxError::Envelope(_))
        ));
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Queued);
        assert_eq!(row[0].attempt_count, 0);
    }

    #[tokio::test]
    async fn two_relay_outbox_does_not_publish_a_failed_row() {
        let mut store = queued_store();
        store.mark_failed([0x22; 32]).expect("mark row failed");
        let relay = RelayClient::new(Duration::from_secs(1)).expect("relay client");
        let cancellation = CancellationToken::new();
        let relay_signing_key = RelaySigningKey::from_bytes([1; 32]).expect("relay key");
        assert!(matches!(
            Box::pin(publish_outbox_entry_to_two_relays(
                &mut store,
                &relay,
                RelayOutboxRoundRequest {
                    event_id: [0x22; 32],
                    relay_urls: ["wss://relay-a.example", "wss://relay-b.example"],
                    mailbox: MailboxToken::from_bytes([0x33; 32]),
                    relay_signing_key: &relay_signing_key,
                    now_seconds: 10,
                    next_attempt_ms: 20,
                },
                &cancellation,
            ))
            .await,
            Err(RelayOutboxError::NotForwardable(OutboxState::Failed))
        ));
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Failed);
        assert_eq!(row[0].attempt_count, 0);
    }
}
