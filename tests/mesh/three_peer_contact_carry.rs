use lattice_mesh::{
    CourierCache, CourierLimits, CourierMetadata, EnvelopeId, EventId, PeerId, TrafficClass,
};
use lattice_testkit::{ContactPlan, ContactWindow, PeerId as ScenarioPeerId};

fn cache() -> CourierCache {
    CourierCache::new(CourierLimits::new(1_024, 4_096, 8, 8_192, 16))
        .expect("scenario cache limits are valid")
}

#[test]
fn opaque_event_waits_for_staged_contacts_and_reaches_third_peer() {
    let scenario_a = ScenarioPeerId::new(0);
    let scenario_b = ScenarioPeerId::new(1);
    let scenario_c = ScenarioPeerId::new(2);
    let a = PeerId::new([1; 16]);
    let b = PeerId::new([2; 16]);
    let plan = ContactPlan::new(
        3,
        vec![
            ContactWindow {
                from: scenario_a,
                to: scenario_b,
                starts_at: 0,
                ends_at: 1,
            },
            ContactWindow {
                from: scenario_b,
                to: scenario_c,
                starts_at: 2,
                ends_at: 3,
            },
        ],
    )
    .expect("three-peer contact trace is valid");
    let event_id = EventId::new([9; 32]);
    let opaque = vec![0xA5; 48];
    let mut a_cache = cache();
    let mut b_cache = cache();
    let mut c_cache = cache();

    a_cache
        .admit(
            b,
            CourierMetadata::new(
                EnvelopeId::new([1; 16]),
                event_id,
                100,
                3,
                3,
                TrafficClass::Interactive,
            ),
            opaque.clone(),
            0,
        )
        .expect("A queues the opaque event for B");
    assert!(plan.is_active(scenario_a, scenario_b, 0));
    let (_, at_b, bytes_at_b) = a_cache
        .take_for_relay(EnvelopeId::new([1; 16]), EnvelopeId::new([2; 16]), 0)
        .expect("A transfers the queue item during contact");
    b_cache
        .admit(a, at_b, bytes_at_b.into_vec(), 0)
        .expect("B retains the opaque item");

    assert!(!plan.is_active(scenario_b, scenario_c, 1));
    assert_eq!(b_cache.len(), 1, "B carries the item until contact opens");
    assert!(plan.is_active(scenario_b, scenario_c, 2));
    let (_, at_c, bytes_at_c) = b_cache
        .take_for_relay(EnvelopeId::new([2; 16]), EnvelopeId::new([3; 16]), 2)
        .expect("B transfers the retained item during its next contact");
    c_cache
        .admit(b, at_c, bytes_at_c.into_vec(), 2)
        .expect("C retains the opaque item");

    let received = c_cache
        .get(EnvelopeId::new([3; 16]))
        .expect("C has the newly wrapped envelope");
    assert_eq!(received.metadata().event_id(), event_id);
    assert_eq!(received.encrypted_opaque_bytes(), opaque);
    assert_eq!(received.metadata().remaining_copy_budget(), 1);
    assert!(a_cache.is_empty());
    assert!(b_cache.is_empty());
}
