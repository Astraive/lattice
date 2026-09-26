use std::{
    future::Future,
    io::{Read, Seek, Write},
    time::Duration,
};

use lattice_crypto::{EstablishedNoiseTransportSession, NoiseRole};
use lattice_files::{
    AttachmentError, AttachmentManifest, AttachmentTransferId, CHUNK_SIZE, ChunkRange,
    StreamedAttachmentReceiver,
};
use lattice_identity::{DeviceIdentity, PinnedIdentity};
use lattice_platform::TransportAdapter;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::direct_session::{
    AuthenticatedSyncError, establish_authenticated_channel_with_protocol, max_v2_plaintext_frame,
    receive_decrypted, send_encrypted,
};

const TRANSFER_PROLOGUE: &[u8] = b"lattice:direct-attachment-transfer:noise-xx:v1\0";
const TRANSFER_PROOF_DOMAIN: &[u8] = b"lattice:direct-attachment-transfer-identity-proof:v1\0";
const FRAME_MAGIC: &[u8; 4] = b"LATF";
const FRAME_VERSION: u8 = 1;
const OFFER: u8 = 1;
const ACCEPT: u8 = 2;
const REJECT: u8 = 3;
const CHUNK: u8 = 4;
const FINISH: u8 = 5;
const VERIFIED: u8 = 6;
const FRAME_HEADER_BYTES: usize = 4 + 1 + 1 + 32;

const CHUNK_FRAME_OVERHEAD: usize = FRAME_HEADER_BYTES + 4 + 4;

const ATTACHMENT_PEER_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Failure while authenticating, authorizing, or resuming one attachment transfer.
#[derive(Debug, Error)]
pub enum AuthenticatedAttachmentError {
    /// Pinned direct-session authentication, transport, or cancellation failed.
    #[error(transparent)]
    Session(#[from] AuthenticatedSyncError),
    /// The transfer manifest or staged chunk failed its integrity or I/O checks.
    #[error(transparent)]
    Attachment(#[from] AttachmentError),
    /// A TCP peer did not complete pinned authentication and send its offer in time.
    #[error("attachment peer authentication timed out")]
    PeerAuthenticationTimeout,
    /// The authenticated peer is not authorized for this event and manifest.
    #[error("authenticated peer is not authorized for this attachment")]
    PeerUnauthorized,
    /// The receiver declined the transfer.
    #[error("receiver declined the attachment transfer")]
    TransferRejected,
    /// The transfer frame is malformed, mismatched, or out of order.
    #[error("invalid attachment-transfer frame")]
    InvalidFrame,
    /// The staged receiver belongs to a different manifest than this transfer.
    #[error("staged receiver manifest does not match the attachment transfer")]
    ReceiverManifestMismatch,
    /// The authenticated adapter cannot carry one complete fixed-size chunk.
    #[error("direct path frame limit is too small for one attachment chunk")]
    FrameTooSmall,
}

/// Local outcome after the receiver has verified the complete attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentReceiveResult {
    /// Exact identity pin used for the authenticated session.
    pub authenticated_peer: PinnedIdentity,
    /// Manifest-bound transfer identity.
    pub transfer_id: AttachmentTransferId,
    /// Chunks newly written during this session; already staged chunks are excluded.
    pub chunks_received: usize,
    /// True only after chunk and whole-file digests pass in the local staging store.
    pub verified_complete: bool,
}

/// Sender outcome after the pinned receiver confirms whole-file verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentSendResult {
    /// Exact identity pin used for the authenticated session.
    pub authenticated_peer: PinnedIdentity,
    /// Manifest-bound transfer identity.
    pub transfer_id: AttachmentTransferId,
    /// Chunks sent in this session, excluding chunks the receiver already had.
    pub chunks_sent: usize,
    /// True only after the authenticated receiver returned its integrity-verified ACK.
    pub receiver_verified_complete: bool,
}

/// Sends missing attachment chunks over a separately domain-bound pinned Noise session.
///
/// The caller must supply a manifest already authorized by its signed Space
/// event policy. The peer callback runs after transcript-bound pin verification.
/// A changed source is rejected by per-chunk digest checks. The function sends
/// only chunks requested by the receiver's verified resume bitmap.
///
/// # Errors
///
/// Returns [`AuthenticatedAttachmentError`] for authorization, manifest, source,
/// frame, transport, Noise, or peer-acknowledgment failures.
#[allow(clippy::too_many_arguments)] // Keeps transport, peer, and authorization gates explicit.
pub async fn send_authenticated_attachment_once<A, R, Z>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    event_id: [u8; 32],
    manifest: &AttachmentManifest,
    source: &mut R,
    mut authorize_peer: Z,
    cancellation: &CancellationToken,
) -> Result<AttachmentSendResult, AuthenticatedAttachmentError>
where
    A: TransportAdapter + ?Sized,
    R: Read + Seek,
    Z: FnMut(&PinnedIdentity, &[u8; 32], &AttachmentManifest) -> bool,
{
    let mut channel = establish_authenticated_channel_with_protocol(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Initiator,
        cancellation,
        TRANSFER_PROLOGUE,
        TRANSFER_PROOF_DOMAIN,
    )
    .await?;
    let transfer_id = manifest.transfer_id(&event_id)?;
    if !authorize_peer(&pinned_peer, &event_id, manifest) {
        send_encrypted(
            adapter,
            &mut channel,
            &encode_frame(REJECT, transfer_id, &[]),
            cancellation,
        )
        .await?;
        return Err(AuthenticatedAttachmentError::PeerUnauthorized);
    }
    let max_frame = max_v2_plaintext_frame(adapter);
    send_encrypted(
        adapter,
        &mut channel,
        &encode_frame(OFFER, transfer_id, &event_id),
        cancellation,
    )
    .await?;
    let response = receive_decrypted(adapter, &mut channel, cancellation).await?;
    if response.len() < FRAME_HEADER_BYTES {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    if response[5] == REJECT {
        validate_frame(&response, REJECT, transfer_id)?;
        return Err(AuthenticatedAttachmentError::TransferRejected);
    }
    let bitmap = decode_accept(&response, transfer_id, manifest.chunk_hashes.len())?;
    let mut largest_requested_chunk = 0;
    for index in 0..manifest.chunk_hashes.len() {
        if bitmap_is_missing(bitmap, index) {
            largest_requested_chunk =
                largest_requested_chunk.max(expected_chunk_size(manifest, index)?);
        }
    }
    if max_frame < CHUNK_FRAME_OVERHEAD + largest_requested_chunk {
        return Err(AuthenticatedAttachmentError::FrameTooSmall);
    }
    let mut chunk = Vec::new();
    if largest_requested_chunk != 0 {
        chunk
            .try_reserve_exact(largest_requested_chunk)
            .map_err(|_| AttachmentError::StagingAllocationFailed)?;
        chunk.resize(largest_requested_chunk, 0);
    }
    let mut chunks_sent = 0_usize;
    for index in 0..manifest.chunk_hashes.len() {
        if !bitmap_is_missing(bitmap, index) {
            continue;
        }
        let length = expected_chunk_size(manifest, index)?;
        manifest.read_verified_chunk_into(source, index, &mut chunk[..length])?;
        let frame = encode_chunk(transfer_id, index, &chunk[..length])?;
        if frame.len() > max_frame {
            return Err(AuthenticatedAttachmentError::FrameTooSmall);
        }
        send_encrypted(adapter, &mut channel, &frame, cancellation).await?;
        chunks_sent = chunks_sent.saturating_add(1);
    }
    send_encrypted(
        adapter,
        &mut channel,
        &encode_frame(FINISH, transfer_id, &[]),
        cancellation,
    )
    .await?;
    let acknowledgment = receive_decrypted(adapter, &mut channel, cancellation).await?;
    validate_frame(&acknowledgment, VERIFIED, transfer_id)?;
    Ok(AttachmentSendResult {
        authenticated_peer: pinned_peer,
        transfer_id,
        chunks_sent,
        receiver_verified_complete: true,
    })
}

async fn authenticate_attachment_offer<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    event_id: &[u8; 32],
    manifest: &AttachmentManifest,
    cancellation: &CancellationToken,
) -> Result<
    (
        EstablishedNoiseTransportSession,
        AttachmentTransferId,
        Vec<u8>,
    ),
    AuthenticatedAttachmentError,
> {
    let transfer_id = manifest.transfer_id(event_id)?;
    let mut channel = establish_authenticated_channel_with_protocol(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Responder,
        cancellation,
        TRANSFER_PROLOGUE,
        TRANSFER_PROOF_DOMAIN,
    )
    .await?;
    let offer = receive_decrypted(adapter, &mut channel, cancellation).await?;
    Ok((channel, transfer_id, offer))
}

/// Receives and resumes a previously authorized manifest after explicit consent.
///
/// The caller supplies the manifest from its authenticated Space policy path,
/// a private staging store, peer authorization, and user consent. `accept` is
/// called only after the pinned peer and transfer identity have been checked;
/// the streamed receiver rebuilds resumable chunk presence from verified stored
/// bytes. The final ACK is encrypted to the pinned sender only after local whole-
/// file verification.
///
/// # Errors
///
/// Returns [`AuthenticatedAttachmentError`] for a mismatched receiver manifest,
/// authorization or consent denial, corrupt chunks, incomplete transfer, storage,
/// frame, transport, or Noise errors.
#[allow(clippy::too_many_arguments)] // Keeps transport, peer, consent, and staging gates explicit.
pub async fn receive_authenticated_attachment_once<A, S, Z, C, Consent>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    event_id: [u8; 32],
    manifest: &AttachmentManifest,
    receiver: &mut StreamedAttachmentReceiver<S>,
    mut authorize_peer: Z,
    accept_consent: C,
    cancellation: &CancellationToken,
) -> Result<AttachmentReceiveResult, AuthenticatedAttachmentError>
where
    A: TransportAdapter + ?Sized,
    S: Read + Write + Seek,
    Z: FnMut(&PinnedIdentity, &[u8; 32], &AttachmentManifest) -> bool,
    C: FnOnce(&PinnedIdentity, &AttachmentManifest) -> Consent,
    Consent: Future<Output = bool>,
{
    if receiver.manifest() != manifest {
        return Err(AuthenticatedAttachmentError::ReceiverManifestMismatch);
    }
    let (mut channel, transfer_id, offer) = tokio::time::timeout(
        ATTACHMENT_PEER_AUTH_TIMEOUT,
        authenticate_attachment_offer(
            adapter,
            local_identity,
            pinned_peer,
            &event_id,
            manifest,
            cancellation,
        ),
    )
    .await
    .map_err(|_| AuthenticatedAttachmentError::PeerAuthenticationTimeout)??;
    if offer.len() >= FRAME_HEADER_BYTES && offer[5] == REJECT {
        validate_frame(&offer, REJECT, transfer_id)?;
        return Err(AuthenticatedAttachmentError::TransferRejected);
    }
    let offer_body = validate_frame(&offer, OFFER, transfer_id)?;
    if offer_body != event_id {
        send_encrypted(
            adapter,
            &mut channel,
            &encode_frame(REJECT, transfer_id, &[]),
            cancellation,
        )
        .await?;
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    if !authorize_peer(&pinned_peer, &event_id, manifest) {
        send_encrypted(
            adapter,
            &mut channel,
            &encode_frame(REJECT, transfer_id, &[]),
            cancellation,
        )
        .await?;
        return Err(AuthenticatedAttachmentError::PeerUnauthorized);
    }
    if !accept_consent(&pinned_peer, manifest).await {
        receiver.reject()?;
        send_encrypted(
            adapter,
            &mut channel,
            &encode_frame(REJECT, transfer_id, &[]),
            cancellation,
        )
        .await?;
        return Err(AuthenticatedAttachmentError::TransferRejected);
    }
    receiver.accept()?;
    let missing_ranges = receiver.missing_ranges()?;
    let bitmap = encode_missing_bitmap(manifest.chunk_hashes.len(), &missing_ranges)?;
    let accept_frame = encode_frame(ACCEPT, transfer_id, &bitmap);
    if accept_frame.len() > max_v2_plaintext_frame(adapter) {
        return Err(AuthenticatedAttachmentError::FrameTooSmall);
    }
    send_encrypted(adapter, &mut channel, &accept_frame, cancellation).await?;
    let missing_bitmap = &bitmap[2..];
    let mut chunks_received = 0_usize;
    for index in 0..manifest.chunk_hashes.len() {
        if !bitmap_is_missing(missing_bitmap, index) {
            continue;
        }
        let frame = receive_decrypted(adapter, &mut channel, cancellation).await?;
        let (received_index, bytes) = decode_chunk(&frame, transfer_id)?;
        if received_index != index {
            return Err(AuthenticatedAttachmentError::InvalidFrame);
        }
        receiver.submit_chunk(index, bytes)?;
        chunks_received = chunks_received.saturating_add(1);
    }
    let finish = receive_decrypted(adapter, &mut channel, cancellation).await?;
    validate_frame(&finish, FINISH, transfer_id)?;
    if !receiver.is_complete() {
        return Err(AttachmentError::TransferIncomplete.into());
    }
    send_encrypted(
        adapter,
        &mut channel,
        &encode_frame(VERIFIED, transfer_id, &[]),
        cancellation,
    )
    .await?;
    Ok(AttachmentReceiveResult {
        authenticated_peer: pinned_peer,
        transfer_id,
        chunks_received,
        verified_complete: true,
    })
}

fn encode_frame(kind: u8, transfer_id: AttachmentTransferId, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + body.len());
    frame.extend_from_slice(FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.push(kind);
    frame.extend_from_slice(&transfer_id.0);
    frame.extend_from_slice(body);
    frame
}

fn validate_frame(
    frame: &[u8],
    expected_kind: u8,
    expected_id: AttachmentTransferId,
) -> Result<&[u8], AuthenticatedAttachmentError> {
    if frame.len() < FRAME_HEADER_BYTES
        || &frame[..4] != FRAME_MAGIC
        || frame[4] != FRAME_VERSION
        || frame[5] != expected_kind
        || frame[6..FRAME_HEADER_BYTES] != expected_id.0
    {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    Ok(&frame[FRAME_HEADER_BYTES..])
}

fn decode_accept(
    frame: &[u8],
    transfer_id: AttachmentTransferId,
    chunk_count: usize,
) -> Result<&[u8], AuthenticatedAttachmentError> {
    let body = validate_frame(frame, ACCEPT, transfer_id)?;
    if body.len() < 2 {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    let bitmap_length = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let expected_length = chunk_count
        .checked_add(7)
        .ok_or(AuthenticatedAttachmentError::InvalidFrame)?
        / 8;
    if bitmap_length != expected_length || body.len() != 2 + bitmap_length {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    let bitmap = &body[2..];
    if let Some(last) = bitmap.last()
        && !chunk_count.is_multiple_of(8)
        && last & !((1_u8 << (chunk_count % 8)) - 1) != 0
    {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    Ok(bitmap)
}

fn encode_missing_bitmap(
    chunk_count: usize,
    ranges: &[ChunkRange],
) -> Result<Vec<u8>, AuthenticatedAttachmentError> {
    let byte_count = chunk_count
        .checked_add(7)
        .ok_or(AuthenticatedAttachmentError::InvalidFrame)?
        / 8;
    let length =
        u16::try_from(byte_count).map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?;
    let mut body = Vec::with_capacity(2 + byte_count);
    body.extend_from_slice(&length.to_be_bytes());
    body.resize(2 + byte_count, 0);
    for range in ranges {
        if range.start >= range.end_exclusive || range.end_exclusive > chunk_count {
            return Err(AuthenticatedAttachmentError::InvalidFrame);
        }
        for index in range.start..range.end_exclusive {
            body[2 + index / 8] |= 1 << (index % 8);
        }
    }
    Ok(body)
}

fn bitmap_is_missing(bitmap: &[u8], index: usize) -> bool {
    bitmap[index / 8] & (1 << (index % 8)) != 0
}

fn encode_chunk(
    transfer_id: AttachmentTransferId,
    index: usize,
    bytes: &[u8],
) -> Result<Vec<u8>, AuthenticatedAttachmentError> {
    let index = u32::try_from(index).map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?;
    let length =
        u32::try_from(bytes.len()).map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?;
    let mut body = Vec::with_capacity(8 + bytes.len());
    body.extend_from_slice(&index.to_be_bytes());
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(bytes);
    Ok(encode_frame(CHUNK, transfer_id, &body))
}

fn decode_chunk(
    frame: &[u8],
    transfer_id: AttachmentTransferId,
) -> Result<(usize, &[u8]), AuthenticatedAttachmentError> {
    let body = validate_frame(frame, CHUNK, transfer_id)?;
    if body.len() < 8 {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    let index = usize::try_from(u32::from_be_bytes(
        body[..4]
            .try_into()
            .map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?,
    ))
    .map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?;
    let length = usize::try_from(u32::from_be_bytes(
        body[4..8]
            .try_into()
            .map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?,
    ))
    .map_err(|_| AuthenticatedAttachmentError::InvalidFrame)?;
    if length == 0 || body.len() != 8 + length || length > CHUNK_SIZE {
        return Err(AuthenticatedAttachmentError::InvalidFrame);
    }
    Ok((index, &body[8..]))
}

fn expected_chunk_size(
    manifest: &AttachmentManifest,
    index: usize,
) -> Result<usize, AttachmentError> {
    let chunk_hashes = manifest.chunk_hashes.len();
    if index >= chunk_hashes {
        return Err(AttachmentError::InvalidChunkIndex);
    }
    if index + 1 < chunk_hashes {
        return Ok(CHUNK_SIZE);
    }
    let offset = index
        .checked_mul(CHUNK_SIZE)
        .ok_or(AttachmentError::ArithmeticOverflow)?;
    usize::try_from(
        manifest
            .file_size
            .checked_sub(u64::try_from(offset).map_err(|_| AttachmentError::ArithmeticOverflow)?)
            .ok_or(AttachmentError::ArithmeticOverflow)?,
    )
    .map_err(|_| AttachmentError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, time::Duration};

    use lattice_files::{
        AttachmentManifest, CHUNK_SIZE, MAX_FILE_SIZE, StreamedAttachmentReceiver,
    };
    use lattice_identity::{DeviceIdentity, PinnedIdentity};
    use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
    use tokio_util::sync::CancellationToken;

    use super::{
        AuthenticatedAttachmentError, receive_authenticated_attachment_once,
        send_authenticated_attachment_once,
    };

    #[tokio::test]
    async fn authenticated_transfer_resumes_verified_staging_chunks() {
        let alice = DeviceIdentity::generate().expect("generate sender identity");
        let bob = DeviceIdentity::generate().expect("generate receiver identity");
        let alice_fingerprint = alice.fingerprint();
        let bob_fingerprint = bob.fingerprint();
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob_fingerprint)
                .expect("pin receiver");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin sender");
        let frame_limit = CHUNK_SIZE + 1024;
        let listener = TcpPeerListener::bind("127.0.0.1:0", frame_limit)
            .await
            .expect("bind authenticated attachment path");
        let endpoint = listener.local_addr().expect("read listener endpoint");
        let (sender_result, receiver_result) = tokio::join!(
            TcpPeerAdapter::connect(endpoint, frame_limit),
            listener.accept()
        );
        let sender_adapter = sender_result.expect("connect sender");
        let (receiver_adapter, _) = receiver_result.expect("accept receiver");

        let content = vec![0x5a; CHUNK_SIZE + 17];
        let event_id = [0x91; 32];
        let manifest = AttachmentManifest::from_reader(
            &mut Cursor::new(content.clone()),
            "resumed.bin",
            Some("application/octet-stream"),
        )
        .expect("create manifest");
        let receiver_storage = Cursor::new(content[..CHUNK_SIZE].to_vec());
        let mut staging_receiver =
            StreamedAttachmentReceiver::new(manifest.clone(), MAX_FILE_SIZE, receiver_storage)
                .expect("create resumable receiver");
        let mut source = Cursor::new(content.clone());
        let sender_cancellation = CancellationToken::new();
        let receiver_cancellation = CancellationToken::new();

        let sender = send_authenticated_attachment_once(
            &sender_adapter,
            &alice,
            alice_pins_bob,
            event_id,
            &manifest,
            &mut source,
            |peer, candidate_event_id, candidate_manifest| {
                peer.fingerprint() == bob_fingerprint
                    && candidate_event_id == &event_id
                    && candidate_manifest == &manifest
            },
            &sender_cancellation,
        );
        let receiver_task = receive_authenticated_attachment_once(
            &receiver_adapter,
            &bob,
            bob_pins_alice,
            event_id,
            &manifest,
            &mut staging_receiver,
            |peer, candidate_event_id, candidate_manifest| {
                peer.fingerprint() == alice_fingerprint
                    && candidate_event_id == &event_id
                    && candidate_manifest == &manifest
            },
            |peer, candidate_manifest| {
                let accepted =
                    peer.fingerprint() == alice_fingerprint && candidate_manifest == &manifest;
                async move { accepted }
            },
            &receiver_cancellation,
        );
        let (send_outcome, recv_outcome) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(10), sender),
            tokio::time::timeout(Duration::from_secs(10), receiver_task)
        );
        let recv_outcome = recv_outcome.expect("receiver should finish");
        let recv_result = recv_outcome.expect("receiver should succeed");
        let send_outcome = send_outcome.expect("sender should finish");
        let send_result = send_outcome.expect("sender should succeed");
        assert_eq!(send_result.transfer_id, recv_result.transfer_id);
        assert_eq!(send_result.chunks_sent, 1);
        assert_eq!(recv_result.chunks_received, 1);
        assert!(send_result.receiver_verified_complete);
        assert!(recv_result.verified_complete);
        let mut verified_content = Vec::new();
        staging_receiver
            .copy_verified_to(&mut verified_content)
            .expect("copy verified attachment");
        assert_eq!(verified_content, content);
    }

    #[tokio::test]
    async fn authenticated_transfer_requires_receiver_consent() {
        let alice = DeviceIdentity::generate().expect("generate sender identity");
        let bob = DeviceIdentity::generate().expect("generate receiver identity");
        let alice_fingerprint = alice.fingerprint();
        let bob_fingerprint = bob.fingerprint();
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob_fingerprint)
                .expect("pin receiver");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin sender");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind consent test path");
        let endpoint = listener.local_addr().expect("read listener endpoint");
        let (sender_result, receiver_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let sender_adapter = sender_result.expect("connect sender");
        let (receiver_adapter, _) = receiver_result.expect("accept receiver");

        let event_id = [0x92; 32];
        let content = b"receiver consent required".to_vec();
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(content.clone()), "private.bin", None)
                .expect("create manifest");
        let mut staging_receiver = StreamedAttachmentReceiver::new(
            manifest.clone(),
            MAX_FILE_SIZE,
            Cursor::new(Vec::new()),
        )
        .expect("create pending receiver");
        let mut source = Cursor::new(content);
        let sender_cancellation = CancellationToken::new();
        let receiver_cancellation = CancellationToken::new();

        let (send_result, recv_result) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                send_authenticated_attachment_once(
                    &sender_adapter,
                    &alice,
                    alice_pins_bob,
                    event_id,
                    &manifest,
                    &mut source,
                    |peer, _, _| peer.fingerprint() == bob_fingerprint,
                    &sender_cancellation,
                ),
                receive_authenticated_attachment_once(
                    &receiver_adapter,
                    &bob,
                    bob_pins_alice,
                    event_id,
                    &manifest,
                    &mut staging_receiver,
                    |peer, _, _| peer.fingerprint() == alice_fingerprint,
                    |_, _| async { false },
                    &receiver_cancellation,
                ),
            )
        })
        .await
        .expect("rejected transfer should finish");
        assert!(matches!(
            send_result,
            Err(AuthenticatedAttachmentError::TransferRejected)
        ));
        assert!(matches!(
            recv_result,
            Err(AuthenticatedAttachmentError::TransferRejected)
        ));
    }
    #[tokio::test]
    async fn unauthenticated_peer_that_sends_nothing_times_out() {
        let alice = DeviceIdentity::generate().expect("generate expected sender");
        let bob = DeviceIdentity::generate().expect("generate local receiver");
        let alice_fingerprint = alice.fingerprint();
        let pinned_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin expected sender");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind unauthenticated peer test path");
        let endpoint = listener.local_addr().expect("read listener endpoint");
        let (adapter_result, accepted_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let adapter = adapter_result.expect("connect silent peer");
        let (receiver_adapter, _) = accepted_result.expect("accept silent peer");
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(b"silent peer"), "silent.bin", None)
                .expect("build manifest");
        let mut receiver = StreamedAttachmentReceiver::new(
            manifest.clone(),
            MAX_FILE_SIZE,
            Cursor::new(Vec::new()),
        )
        .expect("create receiver");
        let error = tokio::time::timeout(
            Duration::from_secs(12),
            receive_authenticated_attachment_once(
                &receiver_adapter,
                &bob,
                pinned_alice,
                [0x93; 32],
                &manifest,
                &mut receiver,
                |_, _, _| true,
                |_, _| async { true },
                &CancellationToken::new(),
            ),
        )
        .await
        .expect("authentication timeout is shorter than the transfer timeout")
        .expect_err("silent unpinned socket cannot authenticate");
        assert!(matches!(
            error,
            AuthenticatedAttachmentError::PeerAuthenticationTimeout
        ));
        drop(adapter);
    }
}
