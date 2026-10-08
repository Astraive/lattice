# Mesh simulator and benchmark

`lattice-mesh-simulator` is a bounded, seeded packet-level store-and-forward simulator backed by the shared `lattice-testkit::DirectedLink` and `ContactPlan`. Events originate on each peer and propagate over a bidirectional chain of scripted, one-tick contacts. Each contact retries events the neighbor does not yet hold. Receiver event-ID deduplication models duplicate arrivals; signatures and production application-level sync policy are outside the simulator's scope.

Run from the repository root:

```sh
cargo run -p lattice-mesh-simulator -- simulate --nodes 4 --events-per-node 8 --seed 42 --drop-per-mille 100 --duplicate-per-mille 200 --max-delay-ticks 3
cargo run --release -p lattice-mesh-simulator -- benchmark --nodes 4 --events-per-node 8 --iterations 25 --seed 42
```

Both commands emit JSON to stdout. `simulate` reports convergence, packet drops, queue-full attempts, duplicate and delayed copies, reordering, queue depth, and min/p50/p95/max packet latency in simulation ticks. A non-converged simulation still emits its report and exits with status 2. Invalid arguments emit usage on stderr and exit with status 64. `benchmark` runs successive seeds and reports wall-clock duration, runs per second, total simulated ticks, attempted packets, and unique ingresses; timings are machine-dependent and are not deterministic.

Bounds: 2-16 peers, 1-256 events per peer, packet loss and duplication 0-1000 per mille, delay up to 1024 ticks, up to 4096 simulation ticks, and per-link capacity 1-4096. Reproducible simulation reports require identical arguments, seed, and binary version.

Focused checks:

```sh
cargo test -p lattice-mesh-simulator
cargo run -p lattice-mesh-simulator -- simulate --nodes 3 --events-per-node 2 --seed 7
```
