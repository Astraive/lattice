use std::collections::BTreeSet;

use lattice_testkit::{
    ContactPlan, ContactWindow, DirectedLink, LinkConfig, LinkError, PeerId, MAX_CONTACT_WINDOWS,
    MAX_LINK_CAPACITY,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationConfig {
    pub nodes: u16,
    pub events_per_node: u32,
    pub seed: u64,
    pub drop_per_mille: u16,
    pub duplicate_per_mille: u16,
    pub max_delay_ticks: u64,
    pub max_ticks: u64,
    pub capacity: usize,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            nodes: 3,
            events_per_node: 4,
            seed: 1,
            drop_per_mille: 0,
            duplicate_per_mille: 100,
            max_delay_ticks: 1,
            max_ticks: 256,
            capacity: 4096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationReport {
    pub seed: u64,
    pub nodes: u16,
    pub events_per_node: u32,
    pub total_events: u64,
    pub converged: bool,
    pub ticks_elapsed: u64,
    pub packets_attempted: u64,
    pub packets_dropped: u64,
    pub queue_full_attempts: u64,
    pub duplicate_packets_queued: u64,
    pub copies_delivered: u64,
    pub duplicate_ingress_copies: u64,
    pub unique_ingress_copies: u64,
    pub delayed_copies: u64,
    pub reordered_unique_copies: u64,
    pub max_queue_depth: usize,
    pub latency_min_ticks: Option<u64>,
    pub latency_p50_ticks: Option<u64>,
    pub latency_p95_ticks: Option<u64>,
    pub latency_max_ticks: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulationError {
    InvalidConfig(&'static str),
    InvalidLinkConfig,
    InvalidContactPlan,
}

impl std::fmt::Display for SimulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid simulation configuration: {reason}"),
            Self::InvalidLinkConfig => f.write_str("invalid directed-link configuration"),
            Self::InvalidContactPlan => f.write_str("invalid generated contact plan"),
        }
    }
}

impl std::error::Error for SimulationError {}

#[derive(Clone, Copy, Debug)]
struct Frame {
    event_id: u64,
    sent_at: u64,
}

struct SimulatedLink {
    from: u16,
    to: u16,
    link: DirectedLink<Frame>,
}

/// Runs a deterministic store-and-forward chain with scripted, bidirectional contacts.
///
/// Events originate on every peer. Each contact sends all events the neighbor is not
/// known to hold; dropped frames are retried at the next contact. The simulator models
/// packet loss, duplication, delay, queue bounds, and receiver-side event deduplication;
/// it does not validate production event signatures or application-level sync policy.
pub fn simulate(config: SimulationConfig) -> Result<SimulationReport, SimulationError> {
    validate_config(config)?;
    let node_count = usize::from(config.nodes);
    let total_events = u64::from(config.nodes) * u64::from(config.events_per_node);
    let mut replicas = vec![BTreeSet::<u64>::new(); node_count];
    for (node, replica) in replicas.iter_mut().enumerate() {
        for sequence in 0..config.events_per_node {
            let event_id = event_id(node as u16, sequence, config.events_per_node);
            replica.insert(event_id);
        }
    }

    let contacts = build_contact_windows(config);
    let contact_plan = ContactPlan::new(config.nodes, contacts)
        .map_err(|_| SimulationError::InvalidContactPlan)?;
    let mut links = Vec::with_capacity((node_count - 1) * 2);
    for left in 0..(node_count - 1) {
        for (from, to) in [
            (left as u16, (left + 1) as u16),
            ((left + 1) as u16, left as u16),
        ] {
            let link_seed =
                config.seed ^ (u64::from(from) << 32) ^ u64::from(to) ^ 0x9e37_79b9_7f4a_7c15;
            let link = DirectedLink::new(
                link_seed,
                LinkConfig {
                    capacity: config.capacity,
                    drop_per_mille: config.drop_per_mille,
                    duplicate_per_mille: config.duplicate_per_mille,
                    max_delay_ticks: config.max_delay_ticks,
                },
            )
            .map_err(|_| SimulationError::InvalidLinkConfig)?;
            links.push(SimulatedLink { from, to, link });
        }
    }

    let mut packets_attempted = 0_u64;
    let mut packets_dropped = 0_u64;
    let mut queue_full_attempts = 0_u64;
    let mut duplicate_packets_queued = 0_u64;
    let mut copies_delivered = 0_u64;
    let mut duplicate_ingress_copies = 0_u64;
    let mut unique_ingress_copies = 0_u64;
    let mut delayed_copies = 0_u64;
    let mut reordered_unique_copies = 0_u64;
    let mut max_queue_depth = 0_usize;
    let mut last_unique_event_by_link = vec![None::<u64>; links.len()];
    let mut latencies = Vec::new();
    let mut ticks_elapsed = 0_u64;
    let mut converged = false;

    for tick in 0..config.max_ticks {
        for path in &mut links {
            if !contact_plan.is_active(PeerId::new(path.from), PeerId::new(path.to), tick) {
                continue;
            }
            for &event_id in &replicas[usize::from(path.from)] {
                if replicas[usize::from(path.to)].contains(&event_id) {
                    continue;
                }
                packets_attempted += 1;
                match path.link.send(
                    tick,
                    Frame {
                        event_id,
                        sent_at: tick,
                    },
                ) {
                    Ok(outcome) => {
                        packets_dropped += u64::from(outcome.dropped);
                        duplicate_packets_queued += u64::from(outcome.copies_queued > 1);
                    }
                    Err(LinkError::QueueFull) => queue_full_attempts += 1,
                    Err(_) => return Err(SimulationError::InvalidLinkConfig),
                }
            }
            max_queue_depth = max_queue_depth.max(path.link.queued());
        }

        for (link_index, path) in links.iter_mut().enumerate() {
            for frame in path.link.deliver(tick, config.capacity) {
                copies_delivered += 1;
                if tick > frame.sent_at {
                    delayed_copies += 1;
                }
                let receiver = &mut replicas[usize::from(path.to)];
                if !receiver.insert(frame.event_id) {
                    duplicate_ingress_copies += 1;
                } else {
                    unique_ingress_copies += 1;
                    latencies.push(tick - frame.sent_at);
                    if last_unique_event_by_link[link_index]
                        .is_some_and(|last| frame.event_id < last)
                    {
                        reordered_unique_copies += 1;
                    }
                    last_unique_event_by_link[link_index] = Some(frame.event_id);
                }
            }
            max_queue_depth = max_queue_depth.max(path.link.queued());
        }

        ticks_elapsed = tick + 1;
        let all_replicas_complete = replicas
            .iter()
            .all(|replica| replica.len() as u64 == total_events);
        let queues_empty = links.iter().all(|path| path.link.queued() == 0);
        if all_replicas_complete && queues_empty {
            converged = true;
            break;
        }
    }

    latencies.sort_unstable();
    Ok(SimulationReport {
        seed: config.seed,
        nodes: config.nodes,
        events_per_node: config.events_per_node,
        total_events,
        converged,
        ticks_elapsed,
        packets_attempted,
        packets_dropped,
        queue_full_attempts,
        duplicate_packets_queued,
        copies_delivered,
        duplicate_ingress_copies,
        unique_ingress_copies,
        delayed_copies,
        reordered_unique_copies,
        max_queue_depth,
        latency_min_ticks: percentile(&latencies, 1),
        latency_p50_ticks: percentile(&latencies, 50),
        latency_p95_ticks: percentile(&latencies, 95),
        latency_max_ticks: percentile(&latencies, 100),
    })
}

fn validate_config(config: SimulationConfig) -> Result<(), SimulationError> {
    if !(2..=16).contains(&config.nodes) {
        return Err(SimulationError::InvalidConfig(
            "nodes must be between 2 and 16",
        ));
    }
    if !(1..=256).contains(&config.events_per_node) {
        return Err(SimulationError::InvalidConfig(
            "events-per-node must be between 1 and 256",
        ));
    }
    if config.drop_per_mille > 1000 || config.duplicate_per_mille > 1000 {
        return Err(SimulationError::InvalidConfig(
            "packet rates must be between 0 and 1000 per mille",
        ));
    }
    if config.max_delay_ticks > 1024 {
        return Err(SimulationError::InvalidConfig(
            "max-delay-ticks must not exceed 1024",
        ));
    }
    if !(1..=4096).contains(&config.max_ticks) {
        return Err(SimulationError::InvalidConfig(
            "max-ticks must be between 1 and 4096",
        ));
    }
    if !(1..=4096).contains(&config.capacity) || config.capacity > MAX_LINK_CAPACITY {
        return Err(SimulationError::InvalidConfig(
            "capacity must be between 1 and 4096",
        ));
    }
    let rounds = config.max_ticks.div_ceil(2 * u64::from(config.nodes - 1));
    let maximum_windows = rounds * 2 * u64::from(config.nodes - 1);
    if maximum_windows > MAX_CONTACT_WINDOWS as u64 {
        return Err(SimulationError::InvalidConfig(
            "generated contact plan exceeds its window limit",
        ));
    }
    Ok(())
}

fn build_contact_windows(config: SimulationConfig) -> Vec<ContactWindow> {
    let node_count = usize::from(config.nodes);
    let period = 2 * (node_count - 1) as u64;
    let rounds = config.max_ticks.div_ceil(period);
    let mut windows = Vec::new();
    for round in 0..rounds {
        let round_start = round * period;
        for left in 0..(node_count - 1) {
            let forward_tick = round_start + (left * 2) as u64;
            let reverse_tick = forward_tick + 1;
            if forward_tick < config.max_ticks {
                windows.push(ContactWindow {
                    from: PeerId::new(left as u16),
                    to: PeerId::new((left + 1) as u16),
                    starts_at: forward_tick,
                    ends_at: forward_tick + 1,
                });
            }
            if reverse_tick < config.max_ticks {
                windows.push(ContactWindow {
                    from: PeerId::new((left + 1) as u16),
                    to: PeerId::new(left as u16),
                    starts_at: reverse_tick,
                    ends_at: reverse_tick + 1,
                });
            }
        }
    }
    windows
}

fn event_id(author: u16, sequence: u32, events_per_node: u32) -> u64 {
    u64::from(author) * u64::from(events_per_node) + u64::from(sequence)
}

fn percentile(sorted: &[u64], percentile: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted.get(rank).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_mesh_reproducibly_converges_and_measures_duplicate_delayed_traffic() {
        let config = SimulationConfig {
            nodes: 3,
            events_per_node: 2,
            seed: 73,
            duplicate_per_mille: 1000,
            max_delay_ticks: 2,
            max_ticks: 64,
            ..SimulationConfig::default()
        };
        let first = simulate(config).unwrap();
        assert_eq!(first, simulate(config).unwrap());
        assert!(first.converged);
        assert_eq!(first.total_events, 6);
        assert!(first.packets_attempted > 0);
        assert!(first.duplicate_packets_queued > 0);
        assert!(first.duplicate_ingress_copies > 0);
        assert!(first.delayed_copies > 0);
        assert!(first.latency_p95_ticks.is_some());
    }

    #[test]
    fn complete_packet_loss_reports_nonconvergence_without_faking_delivery() {
        let report = simulate(SimulationConfig {
            nodes: 2,
            events_per_node: 1,
            drop_per_mille: 1000,
            duplicate_per_mille: 0,
            max_delay_ticks: 0,
            max_ticks: 8,
            ..SimulationConfig::default()
        })
        .unwrap();
        assert!(!report.converged);
        assert_eq!(report.packets_dropped, report.packets_attempted);
        assert_eq!(report.copies_delivered, 0);
        assert_eq!(report.unique_ingress_copies, 0);
    }

    #[test]
    fn simulation_rejects_unbounded_or_invalid_configuration() {
        for config in [
            SimulationConfig {
                nodes: 1,
                ..SimulationConfig::default()
            },
            SimulationConfig {
                events_per_node: 0,
                ..SimulationConfig::default()
            },
            SimulationConfig {
                drop_per_mille: 1001,
                ..SimulationConfig::default()
            },
            SimulationConfig {
                max_ticks: 4097,
                ..SimulationConfig::default()
            },
        ] {
            assert!(matches!(
                simulate(config),
                Err(SimulationError::InvalidConfig(_))
            ));
        }
    }
}
