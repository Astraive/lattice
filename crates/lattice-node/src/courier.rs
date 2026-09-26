//! Versioned, authenticated envelope transfer for opt-in courier queues.
//!
//! A send consumes its source queue row before transmitting the decremented
//! envelope. Disconnects can lose that copy; the sender never restores it.

use lattice_crypto::NoiseRole;
use lattice_identity::{DeviceIdentity, PinnedIdentity};
use lattice_mesh::{
    CourierMetadata, EnvelopeId as LocalEnvelopeId, EventId as LocalEventId, PeerId, TrafficClass,
};
use lattice_platform::TransportAdapter;
use lattice_relay::{DeliveryClass, EnvelopeV1, MAX_ENVELOPE_BYTES};
use lattice_storage::{CourierQueueError, Store};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::sync::{
    AuthenticatedSyncError, establish_courier_channel, receive_courier_frame, send_courier_frame,
};

const WIRE_MAGIC: &[u8; 4] = b"LCOR";
const WIRE_VERSION: u8 = 1;
const START_KIND: u8 = 1;
const CHUNK_KIND: u8 = 2;
const ACCEPT_KIND: u8 = 3;
const REJECT_KIND: u8 = 4;
const HEADER_BYTES: usize = 10;
const MAX_CHUNK_BYTES: usize = 60_000;
const MAX_CHUNK_COUNT: usize = MAX_ENVELOPE_BYTES.div_ceil(MAX_CHUNK_BYTES);
const LOCAL_ID_DOMAIN: &[u8] = b"lattice:courier-local-envelope-id:v1\0";
const PEER_ID_DOMAIN: &[u8] = b"lattice:courier-peer-quota-id:v1\0";

/// A rejected transfer or failure at authentication, storage, or envelope validation.
#[derive(Debug, Error)]
pub enum CourierTransferError {
    /// Pinned Noise identity authentication or bounded transport failed.
    #[error(transparent)]
    Authentication(#[from] AuthenticatedSyncError),
    /// Local courier storage rejected the operation.
    #[error(transparent)]
    Storage(#[from] CourierQueueError),
    /// The signed, canonical delivery envelope is invalid or expired.
    #[error(transparent)]
    Envelope(#[from] lattice_relay::EnvelopeError),
    /// The authenticated peer sent a malformed or out-of-order courier frame.
    #[error("malformed courier transfer frame")]
    InvalidFrame,
    /// Envelope budgets or stored metadata do not permit another courier hop.
    #[error("courier envelope is not eligible for another transfer")]
    NotForwardable,
    /// The authenticated remote rejected local queue retention.
    #[error("remote courier rejected local queue retention")]
    RemoteRejected,
}

/// Local retention receipt from one authenticated incoming transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CourierReceiveResult {
    /// Opaque local queue identifier; not the protocol envelope identifier.
    pub local_envelope_id: [u8; 16],
    /// Monotonic local queue insertion sequence.
    pub sequence: u64,
    /// Bytes retained in the local queue.
    pub bytes_retained: usize,
}

/// Exact-hop acceptance receipt after consuming one local queue copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CourierSendResult {
    /// Consumed local queue identifier.
    pub source_local_envelope_id: [u8; 16],
    /// Protocol envelope identifier after budget decrement.
    pub forwarded_envelope_id: [u8; 32],
    /// Sequence of the consumed source queue row.
    pub source_sequence: u64,
    /// Bytes transferred in the authenticated channel.
    pub bytes_sent: usize,
}

/// Receives and durably queues one envelope from the exact pinned Noise peer.
///
/// Expiry and queue admission use the wall clock when the complete transfer has
/// arrived. A successful result means local retention only, never destination
/// delivery.
///
/// # Errors
///
/// Returns authentication, transport, queue admission, malformed-frame, or
/// envelope-validation failures.
pub async fn receive_courier_once<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    store: &mut Store,
    cancellation: &CancellationToken,
) -> Result<CourierReceiveResult, CourierTransferError> {
    let mut channel = establish_courier_channel(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Responder,
        cancellation,
    )
    .await?;
    let header = receive_courier_frame(adapter, &mut channel, cancellation).await?;
    if header.len() != HEADER_BYTES || header[..6] != wire_header(START_KIND) {
        return reject(adapter, &mut channel, cancellation).await;
    }
    let length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| CourierTransferError::InvalidFrame)?,
    ) as usize;
    if length == 0 || length > MAX_ENVELOPE_BYTES {
        return reject(adapter, &mut channel, cancellation).await;
    }
    let chunk_count = length.div_ceil(MAX_CHUNK_BYTES);
    if chunk_count == 0 || chunk_count > MAX_CHUNK_COUNT {
        return reject(adapter, &mut channel, cancellation).await;
    }
    let mut encoded = Vec::with_capacity(length);
    for index in 0..chunk_count {
        let chunk = receive_courier_frame(adapter, &mut channel, cancellation).await?;
        if chunk.len() < HEADER_BYTES
            || chunk[..6] != wire_header(CHUNK_KIND)
            || u32::from_be_bytes(
                chunk[6..10]
                    .try_into()
                    .map_err(|_| CourierTransferError::InvalidFrame)?,
            ) as usize
                != index
        {
            return reject(adapter, &mut channel, cancellation).await;
        }
        let expected = (length - encoded.len()).min(MAX_CHUNK_BYTES);
        if chunk.len() != HEADER_BYTES + expected {
            return reject(adapter, &mut channel, cancellation).await;
        }
        encoded.extend_from_slice(&chunk[HEADER_BYTES..]);
    }
    let now_ms = unix_millis();
    let now_seconds = now_ms / 1000;
    store.purge_expired_courier_envelopes(now_ms)?;
    let envelope = match EnvelopeV1::decode_at(&encoded, now_seconds) {
        Ok(envelope) if envelope.remaining_hop_budget() > 0 => envelope,
        _ => return reject(adapter, &mut channel, cancellation).await,
    };
    let local_id = local_envelope_id(envelope.envelope_id().as_bytes());
    let metadata = CourierMetadata::new(
        local_id,
        LocalEventId::new(*envelope.event_id().as_bytes()),
        envelope
            .expires_at()
            .checked_mul(1000)
            .ok_or(CourierTransferError::NotForwardable)?,
        u16::from(envelope.remaining_hop_budget()),
        u16::from(envelope.remaining_copy_budget()),
        traffic_class(envelope.delivery_class()),
    );
    let bytes_retained = encoded.len();
    let receipt = match store.queue_courier_envelope(
        quota_peer_id(pinned_peer.fingerprint()),
        &metadata,
        &encoded,
        now_ms,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            let _ =
                send_courier_frame(adapter, &mut channel, &ack(REJECT_KIND), cancellation).await;
            return Err(error.into());
        }
    };
    send_courier_frame(adapter, &mut channel, &ack(ACCEPT_KIND), cancellation).await?;
    Ok(CourierReceiveResult {
        local_envelope_id: *receipt.envelope_id.as_bytes(),
        sequence: receipt.sequence,
        bytes_retained,
    })
}

/// Sends one locally queued envelope to the exact pinned Noise peer.
///
/// The source row is consumed after peer authentication but before the first
/// transfer frame. Any later transport failure loses this copy rather than
/// duplicating its copy budget.
///
/// # Errors
///
/// Returns authentication, storage, envelope-validation, framing, or remote
/// queue-rejection failures. A failure after source consumption does not restore
/// that source row.
pub async fn send_courier_once<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    store: &mut Store,
    source_id: LocalEnvelopeId,
    cancellation: &CancellationToken,
) -> Result<CourierSendResult, CourierTransferError> {
    let now_ms = unix_millis();
    let now_seconds = now_ms / 1000;
    store.purge_expired_courier_envelopes(now_ms)?;
    let preview = store.read_courier_envelope(source_id)?;
    let envelope = EnvelopeV1::decode_at(&preview.encrypted_opaque_bytes, now_seconds)?;
    if local_envelope_id(envelope.envelope_id().as_bytes()) != source_id
        || envelope.event_id().as_bytes() != preview.metadata.event_id().as_bytes()
        || envelope.expires_at().checked_mul(1000) != Some(preview.metadata.expires_at_ms())
        || traffic_class(envelope.delivery_class()) != preview.metadata.traffic_class()
        || envelope.remaining_hop_budget() <= 1
        || envelope.remaining_copy_budget() == 0
        || u16::from(envelope.remaining_copy_budget()) != preview.metadata.remaining_copy_budget()
        || u16::from(envelope.remaining_hop_budget()) != preview.metadata.hop_limit()
    {
        return Err(CourierTransferError::NotForwardable);
    }
    let mut outgoing = EnvelopeV1::decode_at(&preview.encrypted_opaque_bytes, now_seconds)?;
    outgoing.decrement_copy_budget()?;
    outgoing.decrement_hop_budget()?;
    let forwarded_envelope_id = *outgoing.envelope_id().as_bytes();
    let outgoing_bytes = outgoing.encode().to_vec();
    let next_local_id = local_envelope_id(&forwarded_envelope_id);

    let mut channel = establish_courier_channel(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Initiator,
        cancellation,
    )
    .await?;
    let transfer_now_ms = unix_millis();
    let outgoing_at_transfer = EnvelopeV1::decode_at(&outgoing_bytes, transfer_now_ms / 1000)?;
    store.purge_expired_courier_envelopes(transfer_now_ms)?;
    let consumed = store.take_courier_for_relay(source_id, next_local_id, transfer_now_ms)?;
    if consumed.sequence != preview.sequence
        || consumed.metadata.envelope_id() != next_local_id
        || consumed.encrypted_opaque_bytes != preview.encrypted_opaque_bytes
        || consumed.metadata.remaining_copy_budget()
            != u16::from(outgoing_at_transfer.remaining_copy_budget())
    {
        return Err(CourierTransferError::NotForwardable);
    }
    let mut start = wire_header(START_KIND).to_vec();
    let length =
        u32::try_from(outgoing_bytes.len()).map_err(|_| CourierTransferError::NotForwardable)?;
    start.extend_from_slice(&length.to_be_bytes());
    send_courier_frame(adapter, &mut channel, &start, cancellation).await?;
    for (index, chunk) in outgoing_bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        let mut frame = wire_header(CHUNK_KIND).to_vec();
        let chunk_index = u32::try_from(index).map_err(|_| CourierTransferError::NotForwardable)?;
        frame.extend_from_slice(&chunk_index.to_be_bytes());
        frame.extend_from_slice(chunk);
        send_courier_frame(adapter, &mut channel, &frame, cancellation).await?;
    }
    let response = receive_courier_frame(adapter, &mut channel, cancellation).await?;
    if response == ack(REJECT_KIND) {
        return Err(CourierTransferError::RemoteRejected);
    }
    if response != ack(ACCEPT_KIND) {
        return Err(CourierTransferError::InvalidFrame);
    }
    Ok(CourierSendResult {
        source_local_envelope_id: *source_id.as_bytes(),
        forwarded_envelope_id,
        source_sequence: consumed.sequence,
        bytes_sent: outgoing_bytes.len(),
    })
}

async fn reject<A: TransportAdapter + ?Sized, T>(
    adapter: &A,
    channel: &mut lattice_crypto::EstablishedNoiseTransportSession,
    cancellation: &CancellationToken,
) -> Result<T, CourierTransferError> {
    let _ = send_courier_frame(adapter, channel, &ack(REJECT_KIND), cancellation).await;
    Err(CourierTransferError::InvalidFrame)
}

fn wire_header(kind: u8) -> [u8; 6] {
    [
        WIRE_MAGIC[0],
        WIRE_MAGIC[1],
        WIRE_MAGIC[2],
        WIRE_MAGIC[3],
        WIRE_VERSION,
        kind,
    ]
}

fn ack(kind: u8) -> [u8; 6] {
    wire_header(kind)
}

fn local_envelope_id(protocol_id: &[u8; 32]) -> LocalEnvelopeId {
    let mut digest = Sha256::new();
    digest.update(LOCAL_ID_DOMAIN);
    digest.update(protocol_id);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    LocalEnvelopeId::new(bytes)
}

fn quota_peer_id(fingerprint: [u8; 32]) -> PeerId {
    let mut digest = Sha256::new();
    digest.update(PEER_ID_DOMAIN);
    digest.update(fingerprint);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    PeerId::new(bytes)
}

fn traffic_class(class: DeliveryClass) -> TrafficClass {
    match class {
        DeliveryClass::SecurityDependency => TrafficClass::Control,
        DeliveryClass::InteractiveText => TrafficClass::Interactive,
        DeliveryClass::DeferredHistory | DeliveryClass::FileChunk => TrafficClass::Bulk,
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
