#![no_main]

use lattice_sync::{
    AuthorId, AuthorSummary, EventId, GapReason, KnownEvent, ScopeId, ScopeSummary, SequenceRange,
    UnavailableRange, plan_sync,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let scope = ScopeId::new([0x51; 32]);
    let mut local = ScopeSummary::new(scope);
    let mut peer = ScopeSummary::new(scope);

    for (index, chunk) in data.chunks(48).take(32).enumerate() {
        let mut author_bytes = [0_u8; 32];
        let copied = chunk.len().min(author_bytes.len());
        author_bytes[..copied].copy_from_slice(&chunk[..copied]);
        author_bytes[0] ^= u8::try_from(index).unwrap_or_default();
        let author = AuthorId::new(author_bytes);
        let flags = chunk.first().copied().unwrap_or_default();
        let local_sequence = chunk
            .get(32..40)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or_default();
        let peer_sequence = chunk
            .get(40..48)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or_default();
        let mut local_author = AuthorSummary::new(author, local_sequence);
        let mut peer_author = AuthorSummary::new(author, peer_sequence);

        if local_sequence != 0 {
            local_author.known_events.push(KnownEvent {
                sequence: local_sequence,
                event_id: EventId::new(author_bytes),
            });
            if flags & 4 != 0 {
                local_author.unavailable.push(UnavailableRange {
                    range: SequenceRange::new(1, local_sequence).expect("positive sequence"),
                    reason: GapReason::Retention,
                });
            }
        }
        if peer_sequence != 0 {
            let mut event_bytes = author_bytes;
            event_bytes[31] ^= 1;
            peer_author.known_events.push(KnownEvent {
                sequence: peer_sequence,
                event_id: EventId::new(event_bytes),
            });
            if flags & 8 != 0 {
                peer_author.unavailable.push(UnavailableRange {
                    range: SequenceRange::new(1, peer_sequence).expect("positive sequence"),
                    reason: GapReason::Unknown,
                });
            }
        }
        if flags & 1 != 0 {
            local.missing_dependencies.push(EventId::new(author_bytes));
        }
        if flags & 2 != 0 {
            peer.missing_dependencies.push(EventId::new(author_bytes));
        }
        local.authors.push(local_author);
        peer.authors.push(peer_author);
    }

    let plan = plan_sync(&local, &peer);
    if let Ok(plan) = plan {
        assert!(plan.request_ranges.len() <= 256);
        assert!(plan.dependency_requests.len() <= 256);
        assert!(plan.unresolved_history.len() <= 256);
        if !plan.dependency_requests.is_empty() {
            assert!(plan.request_ranges.is_empty());
        }
        assert_eq!(plan_sync(&local, &peer), Ok(plan));
    }
    while !local.missing_dependencies.is_empty() {
        if let Ok(plan) = plan_sync(&local, &peer) {
            assert!(!plan.dependency_requests.is_empty());
            assert!(plan.request_ranges.is_empty());
            assert_eq!(plan_sync(&local, &peer), Ok(plan));
        }

        local.missing_dependencies.pop();

        if let Ok(plan) = plan_sync(&local, &peer) {
            assert!(plan.dependency_requests.is_empty() || plan.request_ranges.is_empty());
            assert_eq!(plan_sync(&local, &peer), Ok(plan));
        }
    }
    let repair_sequence = data
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(1)
        .max(1);
    let repair_scope = ScopeId::new([0xa1; 32]);
    let repair_author = AuthorId::new([0xa2; 32]);
    let repair_event = EventId::new([0xa3; 32]);
    let mut repair_local = ScopeSummary::new(repair_scope);
    let mut repair_peer = ScopeSummary::new(repair_scope);
    repair_local.missing_dependencies.push(EventId::new([0xa4; 32]));
    let mut peer_author = AuthorSummary::new(repair_author, repair_sequence);
    peer_author.known_events.push(KnownEvent {
        sequence: repair_sequence,
        event_id: repair_event,
    });
    if data.first().is_some_and(|flags| flags & 1 != 0) {
        peer_author.unavailable.push(UnavailableRange {
            range: SequenceRange::new(1, repair_sequence).expect("positive sequence"),
            reason: GapReason::Retention,
        });
    }
    repair_peer.authors.push(peer_author);

    let blocked = plan_sync(&repair_local, &repair_peer).expect("bounded repair summaries");
    assert_eq!(blocked.dependency_requests, repair_local.missing_dependencies);
    assert!(blocked.request_ranges.is_empty());
    repair_local.missing_dependencies.clear();
    let resumed = plan_sync(&repair_local, &repair_peer).expect("bounded repair summaries");
    assert!(resumed.dependency_requests.is_empty());
    if data.first().is_some_and(|flags| flags & 1 != 0) {
        assert!(resumed.request_ranges.is_empty());
        assert_eq!(resumed.unresolved_history.len(), 1);
    } else {
        assert_eq!(resumed.request_ranges.len(), 1);
        assert_eq!(resumed.request_ranges[0].author, repair_author);
        assert_eq!(
            resumed.request_ranges[0].range,
            SequenceRange::new(1, repair_sequence).expect("positive sequence")
        );
        assert!(resumed.unresolved_history.is_empty());
    }
});
