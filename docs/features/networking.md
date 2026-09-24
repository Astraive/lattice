# Networking, routing and synchronization — NET

The same event can cross direct or optional indirect routes. Paths supply bytes and health metrics; they never mint authority. Details in [PROTOCOL.md](../protocol/PROTOCOL.md).

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| NET-001 | Active devices shall discover compatible nearby peers without publishing stable identity or Space name in BLE advertisements. | Passive capture across token rotations finds no stable app key/name. | M1 |
| NET-002 | BLE GATT shall exchange bounded authenticated control/text envelopes. | Two Android devices transfer/reassemble under negotiated MTU and loss. | M1 |
| NET-003 | A device shall deduplicate signed events even when received via multiple envelopes or paths. | One event row and one visible message after duplicates/re-envelopment. | M0 |
| NET-004 | Direct forwarding shall enforce hop, byte, expiry and copy bounds. | Churn/flood simulation stays within declared quotas. | M1 |
| NET-005 | Peers shall exchange scoped summaries and request missing ranges/dependencies. | Partition merge repairs gaps without replaying entire history. | M2 |
| NET-006 | Capability negotiation shall select supported Wi-Fi Aware/P2P/LAN for eligible bulk traffic. | Supported pair upgrades; unsupported hardware remains functional via BLE. | M4 |
| NET-007 | Router shall choose paths by class, availability, metered cost, energy and observed health. | Voice prefers viable low-latency IP; bulk does not overwhelm BLE. | M4 |
| NET-008 | Courier shall hold opaque deferred envelopes within explicit opt-in/quotas. | Non-member courier cannot decrypt; expiry/eviction limits survive restart. | M4 |
| NET-009 | User shall configure and disable optional relays independently of Space state. | No relay configured: nearby chat unaffected; disabling stops new relay traffic. | M5 |
| NET-010 | Relay adapter shall transport opaque Lattice envelopes under a versioned retrieval profile. | Two independent compatible relays deliver same event; receiver dedupes. | M5; ADR-003 |
| NET-011 | Relay acceptance shall be a transport receipt only. | Next-hop accepted and recipient absent: message remains forwarded. | M5 |
| NET-012 | Sync shall prioritize MLS/policy dependencies before dependent ciphertext. | Out-of-order epoch test transitions from pending to valid after missing Commit. | M3/M5 |
| NET-013 | Every path shall expose health/failure state without implying exact physical distance or global presence. | Permission off, peer asleep, relay down and high packet loss produce truthful UI. | M5 |

**Boundary conditions:** all relevant phones suspended means no local courier work; Internet relay can log size/timing/IP and retain ciphertext; Nostr events are not a file store; BLE is not a continuous audio medium. [Bitchat's whitepaper](https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md) is implementation precedent, while [DTN RFC 4838](https://www.rfc-editor.org/rfc/rfc4838) frames opportunistic storage.

## Path lifecycle and separation

`discovered → link opening → authenticated → active → degraded → closed` is per path, not per person. One pair may have BLE and LAN simultaneously. Path metrics include last successful receive, smoothed latency, available payload size, queue pressure, recent failures and metered/power context. An adapter gives capabilities and opaque send receipts; the router chooses where to send; the core validates received events. GATT enqueue, WebSocket `OK`, and courier deposit each have different receipt scopes and must not be translated into destination delivery.

BLE advertises an app service and rotating token, then exchanges capability/version and an authenticated session before sensitive scope discovery. It fragments an encrypted envelope into bounded connection-local frames with aggregate/per-peer reassembly limits, timeout, sender pacing and protection against duplicate connection storms. It is a low-volume baseline, not a promise of bandwidth or continuous background scanning. A supported faster path is negotiated only after peer authentication; failure returns to a viable smaller path without changing event identity.

`lattice-transport::TcpPeerAdapter` provides bounded 4-byte big-endian framing over a connected TCP stream; `connect` opens an outbound stream and `TcpPeerListener` binds a caller-selected endpoint and accepts inbound streams with the same envelope cap. The adapter checks lengths before allocation, treats cancellation during an incomplete send as a fault, and reports only local OS queue acceptance. Neither API authenticates peers, discovers LAN devices, nor provides retry/delivery semantics. These remain transport primitives, not evidence that NET-006 capability negotiation or an authenticated LAN path is complete.
lattice-router supplies a deterministic bounded planner; it keeps Presence off persistent Courier/InternetRelay routes and Voice on one direct realtime-IP route. It is not yet connected to authenticated path lifecycle, outbox scheduling, or transport receipts.

## Routing classes and queues

| Class | Priority/persistence | Routing behavior |
| --- | --- | --- |
| Security dependencies | Highest, bounded | MLS proposal/Commit/Welcome, membership and required policy before dependent data. |
| Interactive text | High, durable sender outbox | Direct path first, eligible courier/relay under policy. |
| Deferred history | Medium, resumable | Anti-entropy in batches, prefer fast path. |
| Files | Low/bulk, chunk-resumable | Direct IP preferred, explicit BLE small-file policy. |
| Presence/typing | Volatile | Never persistent courier or backfilled after expiry. |
| Voice media | Real-time only | WebRTC IP path; never stored/flooded as event traffic. |

Sender outbox persists locally and retries on contact discovery with exponential/jittered backoff; a new viable path may wake it early. Courier cache accepts only opaque bounded envelopes, with expiry, per-depositor/global quotas and copy-budget accounting. “Spray and wait” cannot guarantee delivery when encounters do not occur, and a malicious courier may drop copies. Local broadcast uses hop limit, duplicate cache and controlled fanout, not unrestricted epidemic flooding.

## Synchronization details

Authenticated peers establish common authorized scope without listing all memberships, exchange per-author contiguous sequence and sparse gaps, request missing dependencies, and transfer bounded canonical event batches. Validate before commit; then exchange updated summaries. Probabilistic recent-item filters are hints and may false-positive, so exact range reconciliation repairs a missing item. If a retained snapshot replaces ancient events, the proof/validation policy in ADR-004 is required. Never mark a replica fully up-to-date merely because a peer lacks older retained events.
`lattice-sync::plan_sync` performs bounded per-scope range reconciliation and rejects conflicting known event IDs at a shared author sequence. It returns missing dependencies separately from sequence ranges but does not schedule dependencies ahead of dependent ciphertext; NET-012 remains an integration requirement.

## Remote bridge and privacy

The candidate [`13-relay.md`](../../protocol/specs/13-relay.md) defines an opaque Nostr envelope event, relay-only outer key, opaque mailbox tag, expiry, bounds, and best-effort backfill under [ADR-003](../decisions/ADR-003-nostr-envelope-relay-profile.md). The Rust relay crate validates NIP-01/NIP-40 event tags, expiry, canonical envelope and inner event, and NIP-11 thresholds. Its bounded `RelayClient` fetches compatible relay metadata over HTTPS, publishes only after a positive matching NIP-01 `OK`, and retrieves a capped exact-mailbox subscription over `wss://`. This is not two-relay interoperability evidence, recipient delivery, or app integration. Relays are chosen locally and may disagree on acceptance or retention. Encryption does not hide client IP, relay subscriptions, timing, or payload lengths. A relay outage leaves local Space state intact.
