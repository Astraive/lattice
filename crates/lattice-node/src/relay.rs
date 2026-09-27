//! One-shot publication of durable outbox envelopes through the versioned
//! opaque Nostr mailbox profile.
//!
//! Relay acceptance records only local forwarding. This module never marks an
//! outbox item delivered; that requires a separate destination receipt.

use lattice_relay::{
    EnvelopeV1,
    network::{RelayAcceptance, RelayClient, RelayNetworkError},
    profile::{MailboxToken, RelayProfileError, RelayProfileMessage},
};
use lattice_storage::{MAX_OUTBOX_EVENTS, MAX_OUTBOX_PAGE_SIZE, OutboxState, Store, StoreError};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Failures while validating, publishing, or recording one outbox relay hop.
#[derive(Debug, Error)]
pub enum RelayOutboxError {
    /// The caller supplied a negative next-attempt timestamp.
    #[error("next outbox attempt time must be nonnegative")]
    InvalidSchedule,
    /// The durable outbox row was not found.
    #[error("outbox event was not found")]
    MissingOutboxEntry,
    /// Only queued or previously forwarded rows can be sent to a relay.
    #[error("outbox state {0:?} cannot be forwarded")]
    NotForwardable(OutboxState),
    /// The attempt counter cannot advance without overflowing its durable width.
    #[error("outbox forwarding attempt counter is exhausted")]
    AttemptsExhausted,
    /// The durable bytes are not a valid, unexpired candidate envelope.
    #[error("invalid outbox envelope: {0}")]
    Envelope(#[from] lattice_relay::EnvelopeError),
    /// The outbox row's event identifier differs from the verified inner event.
    #[error("outbox event ID does not match the envelope inner event ID")]
    InnerEventMismatch,
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

/// Caller-controlled inputs for one durable relay publication attempt.
pub struct RelayOutboxRequest<'a> {
    /// Inner event ID used to find the durable outbox row.
    pub event_id: [u8; 32],
    /// Relay endpoint.
    pub relay_url: &'a str,
    /// Generation-scoped opaque mailbox selector.
    pub mailbox: MailboxToken,
    /// Independently protected Nostr relay signing key.
    pub relay_secret_key: &'a [u8; 32],
    /// Current Unix time in seconds for envelope expiry validation.
    pub now_seconds: u64,
    /// Nonnegative next-attempt Unix time in milliseconds.
    pub next_attempt_ms: i64,
}

/// Publishes one durable queued envelope to a versioned private relay mailbox.
///
/// The caller supplies the independently protected Nostr relay key and the
/// generation-scoped mailbox token. The function reloads the authoritative
/// durable row, verifies its inner signed event and expiry, and marks it
/// `Forwarded` only after a positive exact-event relay receipt. It never marks
/// the row `Delivered`. Serialize concurrent attempts for one outbox event.
/// `now_seconds` is Unix seconds; `next_attempt_ms` is a caller-selected
/// nonnegative Unix-millisecond retry time.
///
/// # Errors
///
/// Returns an error for missing/ineligible rows, invalid schedule or envelope,
/// profile rejection, network failure, or failure to persist local forwarding
/// after relay acceptance.
pub async fn publish_outbox_entry_once(
    store: &mut Store,
    relay: &RelayClient,
    request: RelayOutboxRequest<'_>,
    cancellation: &CancellationToken,
) -> Result<RelayAcceptance, RelayOutboxError> {
    let RelayOutboxRequest {
        event_id,
        relay_url,
        mailbox,
        relay_secret_key,
        now_seconds,
        next_attempt_ms,
    } = request;
    if next_attempt_ms < 0 {
        return Err(RelayOutboxError::InvalidSchedule);
    }
    let entry = load_outbox_entry(store, event_id)?;
    if !matches!(entry.state, OutboxState::Queued | OutboxState::Forwarded) {
        return Err(RelayOutboxError::NotForwardable(entry.state));
    }
    if entry.attempt_count == u32::MAX {
        return Err(RelayOutboxError::AttemptsExhausted);
    }
    let envelope = EnvelopeV1::decode_at(&entry.envelope_bytes, now_seconds)?;
    if envelope.event_id().as_bytes() != &entry.event_id {
        return Err(RelayOutboxError::InnerEventMismatch);
    }
    let message = RelayProfileMessage::create(envelope, mailbox, relay_secret_key)?;
    let acceptance = relay.publish(relay_url, &message, cancellation).await?;
    record_relay_acceptance(store, event_id, *acceptance.event_id(), next_attempt_ms)?;
    Ok(acceptance)
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
    use std::time::Duration;

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
        record_relay_acceptance(&mut store, [0x22; 32], [0x44; 32], 45)
            .expect("record relay acceptance");
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Forwarded);
        assert_eq!(row[0].attempt_count, 1);
        assert_eq!(row[0].next_attempt_ms, 45);
    }

    #[tokio::test]
    async fn relay_outbox_preflight_rejects_schedule_and_malformed_envelopes() {
        let mut store = queued_store();
        let relay = RelayClient::new(Duration::from_secs(1)).expect("relay client");
        let cancellation = CancellationToken::new();
        assert!(matches!(
            publish_outbox_entry_once(
                &mut store,
                &relay,
                RelayOutboxRequest {
                    event_id: [0x22; 32],
                    relay_url: "invalid://relay",
                    mailbox: MailboxToken::from_bytes([0x33; 32]),
                    relay_secret_key: &[1; 32],
                    now_seconds: 10,
                    next_attempt_ms: -1,
                },
                &cancellation,
            )
            .await,
            Err(RelayOutboxError::InvalidSchedule)
        ));
        assert!(matches!(
            publish_outbox_entry_once(
                &mut store,
                &relay,
                RelayOutboxRequest {
                    event_id: [0x22; 32],
                    relay_url: "invalid://relay",
                    mailbox: MailboxToken::from_bytes([0x33; 32]),
                    relay_secret_key: &[1; 32],
                    now_seconds: 10,
                    next_attempt_ms: 20,
                },
                &cancellation,
            )
            .await,
            Err(RelayOutboxError::Envelope(_))
        ));
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Queued);
        assert_eq!(row[0].attempt_count, 0);
    }

    #[tokio::test]
    async fn relay_outbox_never_republishes_a_delivered_row() {
        let mut store = queued_store();
        store.mark_forwarded([0x22; 32], 1).expect("mark forwarded");
        store
            .record_destination_receipt([0x22; 32])
            .expect("record destination receipt");
        let relay = RelayClient::new(Duration::from_secs(1)).expect("relay client");
        let cancellation = CancellationToken::new();
        assert!(matches!(
            publish_outbox_entry_once(
                &mut store,
                &relay,
                RelayOutboxRequest {
                    event_id: [0x22; 32],
                    relay_url: "invalid://relay",
                    mailbox: MailboxToken::from_bytes([0x33; 32]),
                    relay_secret_key: &[1; 32],
                    now_seconds: 10,
                    next_attempt_ms: 20,
                },
                &cancellation,
            )
            .await,
            Err(RelayOutboxError::NotForwardable(OutboxState::Delivered))
        ));
        let row = store.list_outbox_page(None, 1).expect("read outbox");
        assert_eq!(row[0].state, OutboxState::Delivered);
        assert_eq!(row[0].attempt_count, 1);
    }
}
