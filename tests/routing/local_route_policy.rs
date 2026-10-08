use lattice_router::{
    EnergyCost, EnvelopeId, EventId, ForwardingEnvelope, NetworkScope, PathCandidate,
    PathCapabilities, PathId, PathKind, RoutePlan, RoutingOutcome, RoutingPolicy, TrafficClass,
    plan_forward,
};

fn candidate(id: u64, kind: PathKind, scope: NetworkScope) -> PathCandidate {
    PathCandidate {
        id: PathId(id),
        kind,
        network_scope: scope,
        capabilities: PathCapabilities {
            interactive_text: true,
            ..PathCapabilities::default()
        },
        mtu_bytes: 1_200,
        max_payload_bytes: 1_000,
        reachable: true,
        metered: false,
        energy_cost: EnergyCost::Low,
        rtt_ms: Some(10),
        loss_per_mille: 0,
        queued_bytes: 0,
    }
}

#[test]
fn default_policy_uses_local_route_without_fanning_out_to_internet() {
    let candidates = [
        candidate(1, PathKind::Lan, NetworkScope::Local),
        candidate(2, PathKind::InternetRelay, NetworkScope::Internet),
    ];
    let envelope = ForwardingEnvelope {
        event_id: EventId([1; 32]),
        envelope_id: EnvelopeId([2; 16]),
        payload_bytes: 256,
        hops_used: 0,
        hop_limit: 4,
        copies_remaining: 4,
        expires_at_unix_seconds: 100,
    };

    let outcome = plan_forward(
        TrafficClass::InteractiveText,
        &envelope,
        10,
        &candidates,
        &RoutingPolicy::default(),
    )
    .expect("valid local candidates produce a routing outcome");

    let RoutingOutcome::Forward(RoutePlan { paths, counters }) = outcome else {
        panic!("the reachable LAN path should be selected");
    };
    assert_eq!(paths, [PathId(1)]);
    assert_eq!(counters.hops_used, 1);
    assert_eq!(counters.copies_remaining, 3);
}
