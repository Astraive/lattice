use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
use lattice_identity::DeviceIdentity;
use lattice_sync::{
    AuthorId, AuthorSummary, EventId as SyncEventId, KnownEvent, ScopeId, ScopeSummary, plan_sync,
};
use lattice_testkit::{DirectedLink, FakeClock, LinkConfig, SendOutcome};

const EVENT_COUNT_PER_AUTHOR: u64 = 10;
const MAX_TICKS: usize = 128;
const EVENT_SPACE: [u8; 16] = [0x42; 16];
const EVENT_GROUP: [u8; 32] = [0x24; 32];

#[derive(Clone, Debug)]
struct WireEvent {
    encoded: Vec<u8>,
    ordinal: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredEvent {
    id: SyncEventId,
    encoded: Vec<u8>,
    ordinal: usize,
}

#[derive(Default)]
struct Replica {
    events: BTreeMap<(AuthorId, u64), StoredEvent>,
}

impl Replica {
    fn receive(&mut self, frame: WireEvent) -> Result<(), String> {
        let event = VerifiedSignatureOnlyEvent::decode_verify(&frame.encoded)
            .map_err(|error| error.to_string())?;
        let author = AuthorId::new(*event.author_fingerprint());
        let sequence = event.author_sequence();
        let id = SyncEventId::new(*event.event_id().as_bytes());
        let key = (author, sequence);
        if let Some(existing) = self.events.get(&key) {
            if existing.id != id || existing.encoded != frame.encoded {
                return Err(format!("conflicting event at author sequence {sequence}"));
            }
            return Ok(());
        }
        self.events.insert(
            key,
            StoredEvent {
                id,
                encoded: frame.encoded,
                ordinal: frame.ordinal,
            },
        );
        Ok(())
    }

    fn summary(&self) -> ScopeSummary {
        let mut summary = ScopeSummary::new(ScopeId::new([0x53; 32]));
        let mut authors = BTreeMap::<AuthorId, AuthorSummary>::new();
        for ((author, sequence), stored) in &self.events {
            authors
                .entry(*author)
                .or_insert_with(|| AuthorSummary::new(*author, 0))
                .known_events
                .push(KnownEvent {
                    sequence: *sequence,
                    event_id: stored.id,
                });
        }
        summary.authors = authors.into_values().collect();
        summary
    }
}

#[derive(Default)]
struct NetworkEffects {
    dropped: usize,
    duplicated: usize,
    delayed: usize,
    reordered: usize,
}

fn enqueue_requested_events(
    peer: &Replica,
    requester: &Replica,
    link: &mut DirectedLink<WireEvent>,
    now: u64,
    effects: &mut NetworkEffects,
) {
    let plan = plan_sync(&requester.summary(), &peer.summary())
        .expect("replica summaries are within the bounded sync profile");
    for request in plan.request_ranges {
        for ((author, sequence), stored) in &peer.events {
            if *author == request.author
                && request.range.start() <= *sequence
                && *sequence <= request.range.end()
            {
                let outcome = link
                    .send(
                        now,
                        WireEvent {
                            encoded: stored.encoded.clone(),
                            ordinal: stored.ordinal,
                        },
                    )
                    .expect("test link has sufficient bounded capacity");
                record_send(outcome, effects);
            }
        }
    }
}

fn record_send(outcome: SendOutcome, effects: &mut NetworkEffects) {
    effects.dropped += usize::from(outcome.dropped);
    effects.duplicated += usize::from(outcome.copies_queued > 1);
}

fn receive_due(
    replica: &mut Replica,
    frames: Vec<WireEvent>,
    seen_ordinals: &mut BTreeSet<usize>,
    last_new_ordinal: &mut Option<usize>,
    effects: &mut NetworkEffects,
) {
    for frame in frames {
        if seen_ordinals.insert(frame.ordinal) {
            if last_new_ordinal.is_some_and(|last| frame.ordinal < last) {
                effects.reordered += 1;
            }
            *last_new_ordinal = Some(frame.ordinal);
        }
        replica
            .receive(frame)
            .expect("replica accepts valid events idempotently");
    }
}

fn make_author_stream(
    identity: &DeviceIdentity,
    start_ordinal: usize,
    count: u64,
) -> Vec<WireEvent> {
    let mut parents = Vec::new();
    let mut events = Vec::with_capacity(usize::try_from(count).expect("small test event count"));
    for sequence in 1..=count {
        let event = VerifiedSignatureOnlyEvent::create(
            identity,
            EventDraft {
                space_id: EVENT_SPACE,
                channel_id: None,
                author_sequence: sequence,
                lamport: sequence,
                wall_time_hint: sequence,
                parents,
                kind: EventKind::Message,
                protected_body: vec![0x80, u8::try_from(sequence).expect("small sequence")],
                mls_group_reference: EVENT_GROUP,
                mls_epoch: 1,
            },
        )
        .expect("fixture event is valid");
        parents = vec![event.event_id()];
        events.push(WireEvent {
            encoded: event.encoded_bytes().to_vec(),
            ordinal: start_ordinal + events.len(),
        });
    }
    events
}

fn run_seeded_convergence(seed: u64) -> NetworkEffects {
    let left_identity = DeviceIdentity::generate().expect("OS random source is available");
    let right_identity = DeviceIdentity::generate().expect("OS random source is available");
    let left_origin = make_author_stream(&left_identity, 0, EVENT_COUNT_PER_AUTHOR);
    let right_origin = make_author_stream(
        &right_identity,
        usize::try_from(EVENT_COUNT_PER_AUTHOR).expect("small event count"),
        EVENT_COUNT_PER_AUTHOR,
    );

    let mut left = Replica::default();
    let mut right = Replica::default();
    for event in left_origin {
        left.receive(event).expect("local signed event verifies");
    }
    for event in right_origin {
        right.receive(event).expect("local signed event verifies");
    }

    let config = LinkConfig {
        capacity: 4096,
        max_delay_ticks: 20,
        drop_per_mille: 200,
        duplicate_per_mille: 250,
    };
    let mut left_to_right =
        DirectedLink::new(seed, config).expect("configured link is within bounds");
    let mut right_to_left =
        DirectedLink::new(seed ^ 0xA5A5_5A5A, config).expect("configured link is within bounds");
    let mut clock = FakeClock::new(1_800_000_000_000);
    let mut effects = NetworkEffects::default();
    let mut left_seen = BTreeSet::new();
    let mut right_seen = BTreeSet::new();
    let mut last_left_ordinal = None;
    let mut last_right_ordinal = None;
    let mut converged = false;

    for _ in 0..MAX_TICKS {
        let now = clock.monotonic_nanos() / 1_000_000_000;
        enqueue_requested_events(&left, &right, &mut left_to_right, now, &mut effects);
        enqueue_requested_events(&right, &left, &mut right_to_left, now, &mut effects);

        receive_due(
            &mut right,
            left_to_right.deliver(now, usize::MAX),
            &mut left_seen,
            &mut last_left_ordinal,
            &mut effects,
        );
        receive_due(
            &mut left,
            right_to_left.deliver(now, usize::MAX),
            &mut right_seen,
            &mut last_right_ordinal,
            &mut effects,
        );
        effects.delayed += left_to_right.queued() + right_to_left.queued();

        if left.events == right.events && left_to_right.queued() == 0 && right_to_left.queued() == 0
        {
            converged = true;
            break;
        }
        clock
            .advance(Duration::from_secs(1))
            .expect("scenario clock remains in range");
    }

    assert!(converged, "replicas failed to converge for seed {seed:#x}");
    assert_eq!(
        left.events.len(),
        usize::try_from(EVENT_COUNT_PER_AUTHOR * 2).unwrap()
    );
    assert_eq!(left.events, right.events);
    effects
}

#[test]
fn signed_replicas_converge_under_seeded_loss_duplication_delay_and_reordering() {
    let mut total = NetworkEffects::default();
    for seed in [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_5eed,
        0x0000_0000_00c0_ffee,
    ] {
        let effects = run_seeded_convergence(seed);
        total.dropped += effects.dropped;
        total.duplicated += effects.duplicated;
        total.delayed += effects.delayed;
        total.reordered += effects.reordered;
    }
    eprintln!(
        "seeded convergence network effects: dropped={}, duplicated={}, delayed={}, reordered={}",
        total.dropped, total.duplicated, total.delayed, total.reordered
    );

    assert!(total.dropped > 0, "corpus exercised packet loss");
    assert!(total.duplicated > 0, "corpus exercised duplicate delivery");
    assert!(total.delayed > 0, "corpus exercised delayed delivery");
    assert!(
        total.reordered > 0,
        "corpus exercised out-of-order delivery"
    );
}

#[test]
fn replicas_reject_malformed_bytes_before_storage() {
    let mut replica = Replica::default();
    assert!(
        replica
            .receive(WireEvent {
                encoded: vec![0xff],
                ordinal: 0,
            })
            .is_err()
    );
    assert!(replica.events.is_empty());
}
