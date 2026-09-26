use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
use lattice_identity::{DeviceIdentity, PinnedIdentity};
use lattice_mesh::{
    CourierMetadata, EnvelopeId as LocalEnvelopeId, EventId as LocalEventId, PeerId, TrafficClass,
};
use lattice_node::courier::{receive_courier_once, send_courier_once};
use lattice_platform::{MAX_ENVELOPE_BYTES, TransportAdapter};
use lattice_relay::{DeliveryClass, EnvelopeV1};
use lattice_storage::{DEFAULT_COURIER_LIMITS, Store};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use tokio_util::sync::CancellationToken;

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis()
        .try_into()
        .expect("millisecond timestamp fits u64")
}

fn database_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "lattice-courier-transfer-{label}-{}-{nonce}.sqlite",
        std::process::id()
    ))
}

fn envelope(identity: &DeviceIdentity) -> EnvelopeV1 {
    let event = VerifiedSignatureOnlyEvent::create(
        identity,
        EventDraft {
            space_id: [0x31; 16],
            channel_id: Some([0x42; 16]),
            author_sequence: 1,
            lamport: 1,
            wall_time_hint: 0,
            parents: Vec::new(),
            kind: EventKind::Message,
            protected_body: vec![0x80; 120_000],
            mls_group_reference: [0x53; 32],
            mls_epoch: 0,
        },
    )
    .expect("create signed event");
    let now_seconds = unix_millis() / 1000;
    EnvelopeV1::new(
        event,
        DeliveryClass::InteractiveText,
        now_seconds,
        now_seconds + 600,
        3,
        1,
    )
    .expect("create delivery envelope")
}

fn queue_envelope(store: &mut Store, envelope: &EnvelopeV1) -> LocalEnvelopeId {
    let mut digest = Sha256::new();
    digest.update(b"lattice:courier-local-envelope-id:v1\0");
    digest.update(envelope.envelope_id().as_bytes());
    let digest = digest.finalize();
    let mut local_id = [0_u8; 16];
    local_id.copy_from_slice(&digest[..16]);
    let local_id = LocalEnvelopeId::new(local_id);
    let metadata = CourierMetadata::new(
        local_id,
        LocalEventId::new(*envelope.event_id().as_bytes()),
        envelope.expires_at() * 1000,
        u16::from(envelope.remaining_hop_budget()),
        u16::from(envelope.remaining_copy_budget()),
        TrafficClass::Interactive,
    );
    store
        .queue_courier_envelope(
            PeerId::new([0x19; 16]),
            &metadata,
            envelope.encode(),
            unix_millis(),
        )
        .expect("queue source envelope");
    local_id
}

#[tokio::test]
async fn pinned_tcp_transfer_consumes_budget_and_persists_only_on_receiver() {
    let alice = DeviceIdentity::generate().expect("generate sender identity");
    let bob = DeviceIdentity::generate().expect("generate receiver identity");
    let alice_pins_bob =
        PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob.fingerprint())
            .expect("pin receiver");
    let bob_pins_alice =
        PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
            .expect("pin sender");
    let alice_path = database_path("sender");
    let bob_path = database_path("receiver");
    let mut alice_store = Store::open(&alice_path).expect("open sender store");
    let mut bob_store = Store::open(&bob_path).expect("open receiver store");
    alice_store
        .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
        .expect("enable sender queue");
    bob_store
        .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
        .expect("enable receiver queue");
    let source = envelope(&alice);
    let source_id = queue_envelope(&mut alice_store, &source);

    let listener = TcpPeerListener::bind("127.0.0.1:0", MAX_ENVELOPE_BYTES)
        .await
        .expect("bind listener");
    let endpoint = listener.local_addr().expect("read listener address");
    let sender_adapter = TcpPeerAdapter::connect(endpoint, MAX_ENVELOPE_BYTES)
        .await
        .expect("connect sender");
    let (receiver_adapter, _) = listener.accept().await.expect("accept sender");
    let sender_cancel = CancellationToken::new();
    let receiver_cancel = CancellationToken::new();
    let bob_identity = &bob;
    let receiver_store = &mut bob_store;
    let (sent, received) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async {
                let sent = send_courier_once(
                    &sender_adapter,
                    &alice,
                    alice_pins_bob,
                    &mut alice_store,
                    source_id,
                    &sender_cancel,
                )
                .await;
                sender_adapter.stop().await.expect("close sender");
                sent
            },
            async move {
                receive_courier_once(
                    &receiver_adapter,
                    bob_identity,
                    bob_pins_alice,
                    receiver_store,
                    &receiver_cancel,
                )
                .await
            },
        )
    })
    .await
    .expect("courier TCP session stays bounded");
    let sent = sent.expect("send to pinned peer");
    let received = received.expect("authenticated local retention");
    assert_eq!(sent.bytes_sent, source.encode().len());
    assert!(sent.bytes_sent > 60_000);
    assert_eq!(sent.source_local_envelope_id, *source_id.as_bytes());
    assert_eq!(
        alice_store
            .courier_queue_status()
            .expect("sender status")
            .usage
            .items,
        0
    );
    assert_eq!(
        bob_store
            .courier_queue_status()
            .expect("receiver status")
            .usage
            .items,
        1
    );
    assert_eq!(received.bytes_retained, sent.bytes_sent);
    let retained = bob_store
        .read_courier_envelope(LocalEnvelopeId::new(received.local_envelope_id))
        .expect("read retained envelope");
    let forwarded = EnvelopeV1::decode_at(&retained.encrypted_opaque_bytes, unix_millis() / 1000)
        .expect("verify retained envelope");
    assert_eq!(forwarded.event_id(), source.event_id());
    assert_eq!(forwarded.remaining_hop_budget(), 2);
    assert_eq!(forwarded.remaining_copy_budget(), 0);
    drop(alice_store);
    drop(bob_store);
    let _ = std::fs::remove_file(alice_path);
    let _ = std::fs::remove_file(bob_path);
}

#[tokio::test]
async fn pin_mismatch_does_not_consume_source_copy() {
    let alice = DeviceIdentity::generate().expect("generate sender identity");
    let bob = DeviceIdentity::generate().expect("generate receiver identity");
    let mallory = DeviceIdentity::generate().expect("generate wrong pin");
    let alice_pins_mallory =
        PinnedIdentity::from_verified_fingerprint(mallory.public_bundle(), mallory.fingerprint())
            .expect("pin wrong remote identity");
    let bob_pins_alice =
        PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
            .expect("pin actual sender");
    let alice_path = database_path("pin-sender");
    let bob_path = database_path("pin-receiver");
    let mut alice_store = Store::open(&alice_path).expect("open sender store");
    let mut bob_store = Store::open(&bob_path).expect("open receiver store");
    alice_store
        .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
        .expect("enable sender queue");
    bob_store
        .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
        .expect("enable receiver queue");
    let source = envelope(&alice);
    let source_id = queue_envelope(&mut alice_store, &source);

    let listener = TcpPeerListener::bind("127.0.0.1:0", MAX_ENVELOPE_BYTES)
        .await
        .expect("bind listener");
    let endpoint = listener.local_addr().expect("read listener address");
    let sender_adapter = TcpPeerAdapter::connect(endpoint, MAX_ENVELOPE_BYTES)
        .await
        .expect("connect sender");
    let (receiver_adapter, _) = listener.accept().await.expect("accept sender");
    let sender_cancel = CancellationToken::new();
    let receiver_cancel = CancellationToken::new();
    let bob_identity = &bob;
    let receiver_store = &mut bob_store;
    let (sent, received) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async {
                let sent = send_courier_once(
                    &sender_adapter,
                    &alice,
                    alice_pins_mallory,
                    &mut alice_store,
                    source_id,
                    &sender_cancel,
                )
                .await;
                sender_adapter.stop().await.expect("close sender");
                sent
            },
            async move {
                receive_courier_once(
                    &receiver_adapter,
                    bob_identity,
                    bob_pins_alice,
                    receiver_store,
                    &receiver_cancel,
                )
                .await
            },
        )
    })
    .await
    .expect("pinned identity rejection stays bounded");
    assert!(sent.is_err());
    assert!(received.is_err());
    assert_eq!(
        alice_store
            .courier_queue_status()
            .expect("sender status")
            .usage
            .items,
        1
    );
    assert_eq!(
        bob_store
            .courier_queue_status()
            .expect("receiver status")
            .usage
            .items,
        0
    );
    drop(alice_store);
    drop(bob_store);
    let _ = std::fs::remove_file(alice_path);
    let _ = std::fs::remove_file(bob_path);
}
