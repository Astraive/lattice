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
});
