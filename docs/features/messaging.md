# Messaging and history — MSG

Messages are immutable authenticated creation events. Edits, tombstones, reactions and receipts are separate events. UI ordering is stable but does not assert a global physical timeline.

The Rust reducer projects authorized messages and updates in memory. Core caches up to 4,096 authorized local text records (outgoing and received), bounded to 16 MiB, encrypted with the protected MLS storage key and separate from the outbox. After restart, history returns the latest 100 records per channel; offline search scans the bounded full retained cache. Desktop and Android provide recent-history views; UniFFI also exposes full-cache search. Cache remains local and includes only text accepted and retained on this device. Restart restores only unchanged Genesis policy, not later policy changes or the full message/edit-version projection. Before another local author edit, Core can rehydrate that authored base message from authenticated cache when it is among the latest 100 records; this does not restore its complete version chain.

## Implemented local send boundary

`Client::queue_text_message` accepts a restored local Space and credential; `queue_text_message_from_x509_credential` revalidates a bounded OS-trusted device certificate and restores only a valid, unchanged local Genesis generation. Both paths re-check channel policy, encrypt with MLS, and atomically commit the signed message, outbox envelope, encrypted local history record, author sequence, and sender state. `Client::queue_text_message_edit` similarly commits a locally authorized Edit event referencing an authored message, updates the in-memory version projection, and atomically replaces that message's encrypted cached content. After restart, another local author edit can use the authenticated cached base message to re-establish the authorization target, within the latest-100 history bound. This does not restore the full edit-version chain. `MobileClient` exposes local send and edit queueing with bounded identifier, credential, and text inputs. A successful return means **queued locally**, not forwarded or delivered. A later MLS membership transition invalidates the currently supported one-member messaging generation.

## Implemented two-device MLS groups

`lattice_mls::api::DirectMessageGroup` creates an MLS group for one local device and one explicitly pinned peer fingerprint. It checks that the peer fingerprint matches the X.509 identity in the recipient KeyPackage before creating group state, and returns the Add Commit and Welcome for authenticated delivery. Welcome import and persisted-group load accept only the exact two-device membership; application encrypt/decrypt is limited to those fingerprints. Either device can issue a removal, which rekeys the group and permanently closes this pairwise context. The caller remains responsible for establishing trust in the peer fingerprint and routing the opaque MLS messages. Core event-log/outbox integration for DMs is not implemented by this MLS boundary.

## Implemented stable mentions and local mute policy

`Client::queue_text_message_with_mentions` places a sorted, unique list of full device fingerprints and Space role IDs in the encrypted message payload. Role targets must exist in the event policy and require the existing broad-mention permission; legacy v1 messages still decode with no targets. The reducer exposes validated targets through its message projection. `Client::set_mention_muted` stores per-device mute preferences as a protected local record; `should_notify_for_mentions` suppresses notifications when no locally resolved targets remain unmuted. Callers resolve recipient/role membership at the selected event policy context and still own notification dispatch.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| MSG-001 | An authorized user shall compose and commit text while disconnected. | Restart after local send retains event with queued status. | M1 |
| MSG-002 | A text channel shall show messages in deterministic order and repair gaps on contact. | Reordered/duplicated batch yields identical view on replicas. | M1 |
| MSG-003 | Sender shall see queued, forwarded, delivered-to-device and optional read-local states separately. | Relay/courier ACK cannot appear as recipient delivery; read opt-out works. | M1 |
| MSG-004 | Direct messages shall use an end-to-end protected two-device/group context. | Non-member transport relay cannot decrypt; add/remove changes keys appropriately. | M3 |
| MSG-005 | Replies shall reference immutable event IDs; threads shall retain parent Space/channel policy. | Parent arrives after reply, UI repairs thread without duplicate. | M3 |
| MSG-006 | Author edit shall create a new event preserving previous versions under retention policy. | The deterministic in-memory view chooses the greatest `(Lamport, author fingerprint, author sequence, event ID)` version while retaining all accepted versions. | M3 |
| MSG-007 | Author/moderator delete shall be an authenticated tombstone, not remote erasure. | Offline peer sees tombstone after sync; malicious retained copy remains possible. | M3 |
| MSG-008 | Reactions and pins shall use element-tagged add/remove semantics. | Opposite orders of same valid events converge without oscillation. | M3 |
| MSG-009 | Mentions shall resolve identity/role IDs rather than display-name text. | Rename/collision cannot redirect mention; local mute policy suppresses notification. | M3 |
| MSG-010 | Presence and typing shall be expiring hints and never durable truth. | Disconnected peer expires and does not remain globally online. | M3 |
| MSG-011 | Locally retained history shall be searchable offline within key/retention constraints. | Search old authorized messages with network paths off. | M3 |
| MSG-012 | Sending rich text shall use constrained semantic content, never raw executable HTML. | Malicious markup renders as safe text; desktop/mobile results agree. | M3 |

Messages reference attachments by authenticated manifest IDs. Local storage may retain less history under pressure, but loss of cryptographic dependencies or inability to decrypt must be shown explicitly. The outbox and local event log are different: dropping an expired envelope must not delete the authored message. See [DATA_MODEL.md](../data/DATA_MODEL.md).

`Client::search_local_text_messages` decrypts and searches the full locally retained channel cache with a case-insensitive Unicode lowercase substring query. It scans only the selected local Space generation, rejects empty queries and queries over 256 UTF-8 bytes, and returns the 100 newest matches with the exact match and scan counts. Storage bounds the scan to the store-wide 4,096-message and 16 MiB encrypted-content limits; returned matches are rebound to verified signed events. No network history is fetched.

## Send, receive and display

Composer action first validates local role/channel state and draft size, creates canonical event bytes, commits event and outbox atomically, then returns an event ID. It must not block on a radio link. The router chooses a path and may make multiple envelopes for the same event. A recipient authenticates/decrypts, checks parent and permission context, persists once, projects once, and optionally returns a destination receipt. The sender may remain queued/forwarded for a long time if acknowledgments cannot return through a partition.

**Message identity:** event ID, not a timestamp, is the reference for replies, edits, delete, reactions, pins, receipts and notifications. Sequence numbers detect missing messages; Lamport order plus stable tie breaks produces a consistent display without inventing real-time order. A local optimistic bubble shows its actual queued status. If local commit fails, show failure and keep a recoverable draft rather than pretending it was sent.

## Update semantics

| User action | Event rule | Remote/offline behavior |
| --- | --- | --- |
| Edit own text | Create authenticated replacement referencing original; preserve versions until retention removes them. | The current view retains every accepted version and selects by `(Lamport, author fingerprint, author sequence, event ID)`; a device without the original keeps dependency pending. |
| Delete own text | Create an authenticated tombstone for the author's own message. | Honoring clients hide the message after receiving it; cannot erase exports or malicious copies. |
| Moderator removal | Create a distinct reason-bearing tombstone with `MESSAGE_MODERATE`. | Validate role at causal context; present the moderator action and reason separately from author deletion. |
| React | Add uses its immutable event ID as a tag; remove references one ancestor tag from the same author, target and token. | Concurrent additions commute; duplicate delivery cannot toggle state. |
| Pin | Add uses its immutable event ID; removal names one ancestor pin-add tag and requires `MESSAGE_PIN`. | Concurrent adds converge; duplicate delivery does not toggle state. |
| Reply/thread | Immutable parent/root ID and inherited Space policy. | Child arriving before parent stays in a recoverable pending/placeholder view. |

## DMs, mentions and history

DMs have their own two-member encrypted context under the chosen MLS profile; changing device participation implies key and history rules. A displayed human name is never a routing or authorization target. Mentions carry stable identity/role references inside encrypted content, with notification delivery controlled by recipient settings; role membership can change between authoring and receipt, so notification semantics are evaluated against an explicitly chosen event context. Search operates on locally decrypted, retained authorized content; an offline search cannot retrieve unavailable remote history. Retention and key disposal can make an old message permanently undecryptable. A quoted snippet must not bypass a source channel’s access rules when forwarded or exported.

## Delivery and notification edge cases

Relay accepted → **forwarded**, not delivered. Courier has three copies → still **forwarded**, not delivered. Destination persisted but receipt lost → sender may remain forwarded despite actual receipt; duplicate retry is idempotent. Read receipts are optional, per-device and end-to-end, not a global “everyone read” indicator. Typing/presence are volatile with short expiries; they do not survive reconnect as durable history. Notifications fire from locally validated/decrypted messages only, never raw relay events. An unread badge is local projection state and may be corrected after delayed synchronization.
