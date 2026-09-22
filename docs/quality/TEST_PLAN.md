# Verification and test plan

**Status:** test design. Passing a simulator does not establish physical-radio or security properties. Evidence attaches to IDs in [REQUIREMENTS.md](../REQUIREMENTS.md) and release milestones in [PLAN.md](../PLAN.md).

## Matrix and test method

| Suite | Scenario | Required result | IDs |
| --- | --- | --- | --- |
| Canonical wire | Same object in Rust/Kotlin/Swift, malformed duplicate key and bad length | Same bytes/ID; malformed rejected before allocation | LAT-002–003, NET-003 |
| Auth/policy | Forged admin, wrong genesis, stale member, blocked channel | Never enters valid projection | IDN-004–005, SPC-003–011 |
| MLS race | Two authorized commits from same epoch, missing proposal/Welcome, delayed merge | Defined ADR-001 branch choice and recovery; no silent insecure winner | SPC-006–007 |
| Event convergence | Random event permutations with edits/deletes/reactions | Identical valid projections after dependencies | LAT-007, MSG-002/006–008 |
| Mesh | 3-device chain, partitions, churn, limited batteries/queues | Bounded work and repaired gaps under reachable-contact assumption | NET-004–005/008 |
| Storage | Kill during event/MLS commit, migration, corrupt DB | No half-projection, recovery/error visible | LAT-004, LAT-018 |
| Files | Chunk corruption, path upgrade, restart, quota/traversal | Verified final hash or explicit failure | FIL-001–007 |
| Relays | Two independent relays, duplicates/drop/reorder/retention | Same event ID; withheld content pending; metadata documented | NET-009–013 |
| Voice | LAN, heterogeneous NAT, TURN, no TURN, small rooms | Correct connected/failure state and bounded measured quality | VOC-001–008 |
| Privacy | BLE capture, relay capture, log export | No unintended plaintext/key; residual metadata disclosed | LAT-010/019 |
| Accessibility | VoiceOver/TalkBack, keyboard, scale, reduced motion | All critical states and actions usable | LAT-013, MOB-009 |

## Physical devices and measurements

Test Android↔Android, iOS↔iOS and Android↔iOS with supported/unsupported Wi-Fi Aware hardware. Capture exact model, OS/build, radios, permissions, foreground/locked/background/restarted states and environmental factors. Measure discovery/connection success, useful BLE throughput, end-to-end latency, delivery fraction, duplicated bytes, battery/power, large-sync duration, file resume, voice setup success/jitter/loss and TURN fraction. Use multiple independent trials with uncertainty intervals; separate simulated energy proxy from battery measurement. Never substitute one success on a simulator for cross-platform interoperability.

## Automated gates

M0: canonical vectors and property tests. M1/M2: offline physical-device test. M3: membership/key and policy conflict suite. M4: file and path-upgrade tests. M5: malicious relay suite. M6: voice connectivity matrix. M8: fuzz corpus/coverage budget, database migrations, clean-room wire decoder, repeatable benchmarks, privacy capture, external security review, accessibility and reproducible release artifacts.

## Completion rule

An ID becomes **verified** only with implementation revision, test command/scenario, result, device/environment where applicable, and reviewer. Metrics cannot be retrofitted to a target after results are seen. A failed test opens a defect/ADR and keeps the ID proposed or implemented, not verified. [ACM artifact guidance](https://www.acm.org/publications/policies/artifact-review-and-badging-current) is useful when later preparing reproducible results; research publication is outside this build gate.

## Protocol and state-machine campaigns

Generate small histories across 2–6 members, with random signed message, edit, permission, invite, ban, MLS proposal and Commit operations. Permute deliveries, duplicates, pauses, clock jumps, reconnections and adversarial relays. At each prefix assert: no unauthorized projection; identical accepted sets plus chosen branch policy produce identical views; removed members do not obtain later epoch secrets; no event ID changes on path change; and every pending object has a bounded recovery/failure reason. Exhaustively enumerate very small branch histories where practical, then fuzz longer ones with fixed seeds and shrinking.

Parser fuzzing targets canonical CBOR, envelope headers, BLE fragment assembly, invite URI, MLS wrapper, relay JSON, file manifest and voice signaling. Track corpus, sanitizer mode, runtime budget, crash/panic and memory peaks. A zero-crash run on one budget is not proof of security; all reproducible crashes become release blockers until triaged.

## Network laboratory

Model contact graph with time-varying links, asymmetrical drop, MTU, duty cycles, stale summaries, partitions, storage quotas and malicious couriers. Baselines: no forwarding; limited flood; bounded spray; spray plus anti-entropy; relay assistance. For each fixed contact trace report delivered fraction by deadline, distribution of delay, bytes/transmissions per delivered event, cache eviction, missing-history rate and fairness across destinations. The simulator does not claim real battery drain; power must be measured on named hardware.

## Mobile test matrix

| Axis | Required cases |
| --- | --- |
| Pairs | Android/Android, iPhone/iPhone, Android/iPhone; mix Wi-Fi Aware capable/incapable |
| App state | Both foreground, one background, both locked, process restart, OS termination and reboot |
| Permission | Granted, denied, revoked, Bluetooth off, Wi-Fi off, local-network denied |
| Link | Good nearby signal, edge/weak signal, moving contact, LAN, no Internet, metered Internet |
| Operation | Discovery, invite, direct text, multi-hop relay, missed-history catch-up, file upgrade, voice |

Record phone model, radio capabilities, OS/build, battery optimization settings, app build, test geometry, temperature/power conditions, scenario duration and timestamps. Keep packet captures with sensitive IDs removed from publishable artifacts. Device-level results are presented separately from simulator numbers.

## Reliability and user-experience cases

Test local disk full immediately before send; crash between MLS change and log commit; relay `OK` without recipient; courier accepts and drops; one member retains old epoch; file manifest arrives after message; transfer switches links; source deletes file; clock advances backward; duplicate display nickname; QR from wrong Space; voice offer after room incarnation expires; TURN-required NAT with no configured TURN; unread badge after delayed sync. Verify both core result and user-facing wording. A status that is technically true internally but misleading in UI fails acceptance.

## Release evidence record

Each run stores requirement IDs, test source revision, seed/fixture, expected invariant, actual result, environment, logs/artifact hash, limitations and reviewer. A v1 release report includes known failed/unsupported platform paths, key migration results, independent protocol review scope, packet-capture privacy findings, and battery/voice measures. No “works on iOS” statement can be based solely on a simulator.
