//! Lattice deterministic clocks and transport fixtures.
//!
//! The pseudorandom stream in this crate is deterministic test machinery only.
//! It is not cryptographically secure and must not be used for production
//! randomness, keys, nonces, or security decisions.

use std::time::Duration;

/// A small deterministic pseudorandom stream for repeatable test scenarios.
///
/// This uses `SplitMix64` and is **not cryptographically secure**. It is only
/// suitable for tests and simulations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Creates a stream from an explicit seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next deterministic pseudorandom value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

/// A fake monotonic and wall clock.
///
/// Monotonic time is measured in nanoseconds and wall time in milliseconds.
/// Wall-clock advances use whole milliseconds; a sub-millisecond remainder is
/// intentionally discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeClock {
    monotonic_nanos: u64,
    wall_time_millis: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockOverflow;

impl FakeClock {
    /// Starts monotonic time at zero with the supplied wall-clock timestamp.
    #[must_use]
    pub const fn new(wall_time_millis: i64) -> Self {
        Self {
            monotonic_nanos: 0,
            wall_time_millis,
        }
    }

    /// Starts both clocks at the supplied values.
    #[must_use]
    pub const fn at(monotonic_nanos: u64, wall_time_millis: i64) -> Self {
        Self {
            monotonic_nanos,
            wall_time_millis,
        }
    }

    #[must_use]
    pub const fn monotonic_nanos(&self) -> u64 {
        self.monotonic_nanos
    }

    #[must_use]
    pub const fn wall_time_millis(&self) -> i64 {
        self.wall_time_millis
    }

    /// Advances both clocks atomically, leaving them unchanged on overflow.
    ///
    /// # Errors
    ///
    /// Returns [`ClockOverflow`] if either clock would overflow.
    pub fn advance(&mut self, duration: Duration) -> Result<(), ClockOverflow> {
        let monotonic_delta = u64::try_from(duration.as_nanos()).map_err(|_| ClockOverflow)?;
        let wall_delta = i64::try_from(duration.as_millis()).map_err(|_| ClockOverflow)?;
        let monotonic_nanos = self
            .monotonic_nanos
            .checked_add(monotonic_delta)
            .ok_or(ClockOverflow)?;
        let wall_time_millis = self
            .wall_time_millis
            .checked_add(wall_delta)
            .ok_or(ClockOverflow)?;

        self.monotonic_nanos = monotonic_nanos;
        self.wall_time_millis = wall_time_millis;
        Ok(())
    }
}

/// Maximum configured queue capacity, preventing accidental unbounded
/// preallocation in test fixtures.
pub const MAX_LINK_CAPACITY: usize = 65_536;

/// Link behavior expressed as per-thousand probabilities and tick bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    /// Maximum number of frame copies retained in memory.
    pub capacity: usize,
    /// Each non-dropped copy receives a deterministic delay in `0..=max`.
    pub max_delay_ticks: u64,
    /// Per-thousand probability that an attempted frame is dropped.
    pub drop_per_mille: u16,
    /// Per-thousand probability that a non-dropped frame is duplicated.
    pub duplicate_per_mille: u16,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            capacity: 256,
            max_delay_ticks: 0,
            drop_per_mille: 0,
            duplicate_per_mille: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkConfigError {
    InvalidCapacity,
    ProbabilityOutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkError {
    QueueFull,
    SequenceOverflow,
    DeliveryTimeOverflow,
}

/// Result of attempting to send one frame through a [`DirectedLink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendOutcome {
    pub dropped: bool,
    pub copies_queued: usize,
}

#[derive(Clone, Debug)]
struct QueuedFrame<T> {
    ready_at: u64,
    sequence: u64,
    frame: T,
}

/// A bounded, in-memory simulation of one directed unreliable link.
///
/// It does not represent a real transport, establish peer identity, or provide
/// authorization. Each send uses the link's explicit seed to choose drop,
/// duplication, and delay outcomes. Differing per-copy delays can reorder
/// frames; equal ready times are delivered in insertion order.
#[derive(Clone, Debug)]
pub struct DirectedLink<T> {
    rng: DeterministicRng,
    config: LinkConfig,
    next_sequence: u64,
    queue: Vec<QueuedFrame<T>>,
}

impl<T: Clone> DirectedLink<T> {
    /// Creates a directed link with explicit deterministic seed and behavior.
    ///
    /// # Errors
    ///
    /// Returns [`LinkConfigError::InvalidCapacity`] if capacity is zero or
    /// exceeds [`MAX_LINK_CAPACITY`], or
    /// [`LinkConfigError::ProbabilityOutOfRange`] if either probability exceeds
    /// 1000 per mille.
    pub fn new(seed: u64, config: LinkConfig) -> Result<Self, LinkConfigError> {
        if config.capacity == 0 || config.capacity > MAX_LINK_CAPACITY {
            return Err(LinkConfigError::InvalidCapacity);
        }
        if config.drop_per_mille > 1000 || config.duplicate_per_mille > 1000 {
            return Err(LinkConfigError::ProbabilityOutOfRange);
        }
        Ok(Self {
            rng: DeterministicRng::new(seed),
            config,
            next_sequence: 0,
            queue: Vec::with_capacity(config.capacity),
        })
    }

    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Attempts to enqueue a frame at `now`. A full queue rejects the send
    /// without changing the queue. A dropped frame is reported and not queued.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::QueueFull`] if the queue is full,
    /// [`LinkError::SequenceOverflow`] if assigning copy sequence numbers
    /// would overflow, or [`LinkError::DeliveryTimeOverflow`] if a copy's
    /// delivery time would overflow.
    pub fn send(&mut self, now: u64, frame: T) -> Result<SendOutcome, LinkError> {
        if self.queue.len() >= self.config.capacity {
            return Err(LinkError::QueueFull);
        }
        if self.roll(self.config.drop_per_mille) {
            return Ok(SendOutcome {
                dropped: true,
                copies_queued: 0,
            });
        }

        let duplicate = self.roll(self.config.duplicate_per_mille);
        let requested_copies = if duplicate { 2 } else { 1 };
        let copies = requested_copies.min(self.config.capacity - self.queue.len());
        let sequence_after = self
            .next_sequence
            .checked_add(u64::try_from(copies).map_err(|_| LinkError::SequenceOverflow)?)
            .ok_or(LinkError::SequenceOverflow)?;
        let mut ready_times = [0; 2];
        for ready_at in ready_times.iter_mut().take(copies) {
            let delay = self.delay();
            *ready_at = now
                .checked_add(delay)
                .ok_or(LinkError::DeliveryTimeOverflow)?;
        }

        for (offset, ready_at) in ready_times.iter().copied().take(copies).enumerate() {
            let sequence = self
                .next_sequence
                .checked_add(u64::try_from(offset).map_err(|_| LinkError::SequenceOverflow)?)
                .ok_or(LinkError::SequenceOverflow)?;
            self.queue.push(QueuedFrame {
                ready_at,
                sequence,
                frame: frame.clone(),
            });
        }
        self.next_sequence = sequence_after;

        Ok(SendOutcome {
            dropped: false,
            copies_queued: copies,
        })
    }

    /// Delivers at most `max_count` due copies, ordered by ready time and then
    /// insertion order. Frames with a later ready time remain queued.
    pub fn deliver(&mut self, now: u64, max_count: usize) -> Vec<T> {
        let mut delivered = Vec::with_capacity(max_count.min(self.queue.len()));
        while delivered.len() < max_count {
            let next = self
                .queue
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.ready_at <= now)
                .min_by_key(|(_, entry)| (entry.ready_at, entry.sequence))
                .map(|(index, _)| index);
            let Some(index) = next else {
                break;
            };
            delivered.push(self.queue.swap_remove(index).frame);
        }
        delivered
    }

    fn roll(&mut self, per_mille: u16) -> bool {
        per_mille == 1000 || (per_mille != 0 && self.rng.next_u64() % 1000 < u64::from(per_mille))
    }

    fn delay(&mut self) -> u64 {
        if self.config.max_delay_ticks == u64::MAX {
            self.rng.next_u64()
        } else {
            self.rng.next_u64() % (self.config.max_delay_ticks + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_streams_are_repeatable_and_seed_sensitive() {
        let mut first = DeterministicRng::new(42);
        let mut same = DeterministicRng::new(42);
        let mut different = DeterministicRng::new(43);
        let trace: Vec<_> = (0..16).map(|_| first.next_u64()).collect();
        let same_trace: Vec<_> = (0..16).map(|_| same.next_u64()).collect();
        let different_trace: Vec<_> = (0..16).map(|_| different.next_u64()).collect();
        assert_eq!(trace, same_trace);
        assert_ne!(trace, different_trace);
    }

    #[test]
    fn clock_advance_is_atomic_at_both_boundaries() {
        let mut monotonic = FakeClock::at(u64::MAX - 1, 10);
        assert_eq!(
            monotonic.advance(Duration::from_nanos(2)),
            Err(ClockOverflow)
        );
        assert_eq!(monotonic, FakeClock::at(u64::MAX - 1, 10));

        let mut wall = FakeClock::new(i64::MAX);
        assert_eq!(wall.advance(Duration::from_millis(1)), Err(ClockOverflow));
        assert_eq!(wall, FakeClock::new(i64::MAX));

        let mut ordinary = FakeClock::new(-2);
        ordinary.advance(Duration::from_micros(1_500)).unwrap();
        assert_eq!(ordinary.monotonic_nanos(), 1_500_000);
        assert_eq!(ordinary.wall_time_millis(), -1);
    }

    #[test]
    fn link_drops_duplicates_delays_and_bounds_delivery() {
        let mut dropping = DirectedLink::<u8>::new(
            1,
            LinkConfig {
                drop_per_mille: 1000,
                ..LinkConfig::default()
            },
        )
        .unwrap();
        assert_eq!(
            dropping.send(0, 7).unwrap(),
            SendOutcome {
                dropped: true,
                copies_queued: 0
            }
        );
        assert_eq!(dropping.deliver(0, 10), Vec::<u8>::new());

        let mut duplicating = DirectedLink::new(
            2,
            LinkConfig {
                capacity: 4,
                max_delay_ticks: 3,
                duplicate_per_mille: 1000,
                ..LinkConfig::default()
            },
        )
        .unwrap();
        let outcome = duplicating.send(10, 9).unwrap();
        assert_eq!(outcome.copies_queued, 2);
        assert!(duplicating.deliver(10, 4).is_empty());
        let first = duplicating.deliver(13, 1);
        assert_eq!(first, vec![9]);
        assert_eq!(duplicating.queued(), 1);
        assert_eq!(duplicating.deliver(13, 8), vec![9]);
    }

    #[test]
    fn link_trace_repeats_for_seed_and_delay_can_reorder() {
        fn trace(seed: u64) -> Vec<(u64, u8)> {
            let mut link = DirectedLink::new(
                seed,
                LinkConfig {
                    capacity: 32,
                    max_delay_ticks: 10,
                    ..LinkConfig::default()
                },
            )
            .unwrap();
            for frame in 0..12 {
                link.send(0, frame).unwrap();
            }
            let mut result = Vec::new();
            for tick in 0..=10 {
                result.extend(
                    link.deliver(tick, 32)
                        .into_iter()
                        .map(|frame| (tick, frame)),
                );
            }
            result
        }
        let first = trace(5);
        assert_eq!(first, trace(5));
        assert_ne!(first, trace(6));
        assert_ne!(
            first.iter().map(|(_, frame)| *frame).collect::<Vec<_>>(),
            (0..12).collect::<Vec<_>>()
        );
    }

    #[test]
    fn link_capacity_is_strictly_bounded() {
        for capacity in [0, MAX_LINK_CAPACITY + 1] {
            assert_eq!(
                DirectedLink::<u8>::new(
                    0,
                    LinkConfig {
                        capacity,
                        ..LinkConfig::default()
                    }
                )
                .err(),
                Some(LinkConfigError::InvalidCapacity)
            );
        }
    }
    #[test]
    fn link_rejects_over_capacity_and_limits_each_delivery_call() {
        let mut link = DirectedLink::new(
            0,
            LinkConfig {
                capacity: 2,
                duplicate_per_mille: 1000,
                ..LinkConfig::default()
            },
        )
        .unwrap();
        assert_eq!(link.send(0, 1).unwrap().copies_queued, 2);
        assert_eq!(link.send(0, 2), Err(LinkError::QueueFull));
        assert_eq!(link.deliver(0, 1), vec![1]);
        assert_eq!(link.queued(), 1);
        assert_eq!(link.deliver(0, 10), vec![1]);
    }
}
