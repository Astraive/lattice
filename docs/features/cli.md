# Command-line client and volunteer node — CLI

The production CLI is native Rust. It uses the same core and local identity format, not a separate daemon-backed account service. Destructive/key-export commands require an explicit local interaction or flag appropriate to the action.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| CLI-001 | `lattice identity show` shall display fingerprint and protection/capability state without exposing private keys. | Output redaction test and mobile fingerprint parity. | M7 |
| CLI-002 | `lattice space create\|join\|leave` shall use the same genesis/invite/MLS rules as clients. | CLI-mobile join vectors agree; unauthorized join fails. | M7 |
| CLI-003 | `lattice send` shall commit text locally, returning event ID and honest queue status. | Offline CLI send persists across restart and later sync. | M7 |
| CLI-004 | `lattice sync status` shall report missing ranges, pending epochs and queue state. | Fixture with a withheld Commit shows actionable pending state. | M7 |
| CLI-005 | `lattice relay add\|list\|test` shall edit only local relay settings. | Space operation unaffected after removing every relay. | M7 |
| CLI-006 | `lattice peer scan` shall show current path capabilities with privacy-safe default output. | No unrelated Space IDs or private keys in scan output. | M7 |
| CLI-007 | `lattice node run` shall opt into bounded persistent peer/courier behavior. | Stop/restart, disk quota, untrusted packet and privilege tests. | M7 |
| CLI-008 | `lattice doctor` shall inspect DB, keys, versions, permissions and transport without exposing secrets. | Corrupt DB, revoked permission and incompatible wire version are distinguished. | M7 |
| CLI-009 | `lattice space list` shall verify and enumerate local Genesis snapshots in bounded pages. | All snapshots are returned across exclusive keyset cursors; corrupt event or snapshot integrity fails closed and JSON/human output never claims membership. | M7 |
| CLI-010 | `lattice identity pin` shall persist an exact public bundle only when its full fingerprint matches. | Wrong fingerprints and conflicting bundle bytes fail without replacing the existing pin; lookup after reopen returns the exact stored bundle. | M7 |
| CLI-011 | `lattice identity csr` shall export a PKCS#10 request for the device's Ed25519 key and exact full-fingerprint URI SAN without exporting private material. | The request signature, SPKI key and fingerprint SAN verify; `--output` refuses to overwrite an existing file. | M7 |

CLI output should support human and machine-readable modes with stable error classes. It may facilitate test harnesses, but its existence does not imply a globally reachable node or centralized administration.

`space list` restores at most 32 local Genesis records per call and returns the next exclusive cursor as 96 hexadecimal characters (16-byte Space ID followed by 32-byte MLS group reference). Use `lattice space list --after <cursor>` to continue. Each result is a verified local snapshot, not a claim of current membership.

`lattice space create` and `lattice space list` expose each channel's random 16-byte ID, name, type, and archived status so callers can target a channel. `lattice send --space-id <hex> --group-reference <hex> --credential <path> --channel-id <hex> --text <text>` uses a bounded RFC 9420 X.509 credential vector and routes through Core authorization to commit a text event, encrypted local cache entry, and durable local outbox record. It makes no network request and success does not mean forwarding or delivery. `lattice space edit` accepts the same identifiers plus `--target-message-id <hex>` and commits an authorized immutable Edit event while updating the encrypted local message cache. `lattice space history` reads one channel's bounded encrypted text cache, which may include events accepted through `sync fetch-once` but is not a complete transcript. These Space commands make no network requests and make no recipient-delivery claim.

`lattice space restore --space-id <hex> --group-reference <hex>` revalidates one locally persisted signed Genesis and protected MLS snapshot, then reports its channels. It does not check remote membership or contact the network.

`lattice space recover --space-id <hex> --group-reference <hex> --credential <path>` restores that locally retained generation and creates a new one-member root after validating the RFC 9420 X.509 credential vector. It preserves supported channel descriptors, resets membership to the local administrator, and does not rejoin prior members or contact the network.

The CLI implements `about`, `status`, identity initialization/CSR/pinning, local Space create/list/restore/recover/edit/history, top-level `send`, `space join`, `sync status`, `sync fetch-once`, `sync serve-once`, local relay settings/probes, and `doctor`. `space join --package <path> --inviter-fingerprint <hex> --credential <path>` imports a bounded signed Welcome bootstrap from an exact pre-pinned inviter into the protected local profile. The CLI still does not perform general event-history replay, send invitations, contact a relay, or run ongoing synchronization; the full invite/leave lifecycle remains unavailable.

`sync status` counts locally committed event records through bounded keyset pages and reports each bounded local pending event's Space, group, signed event and author IDs, sequence, MLS epoch, and missing dependency IDs. JSON sets `pending_mls_epochs_available` to `true`; `missing_ranges` remains unavailable because status has no peer summary. These are local records, not evidence of peer synchronization or authorization of pending events.

`sync serve-once --listen <addr> --space-id <hex> --group-reference <hex> --peer-fingerprint <hex>` accepts one TCP peer only when its exact fingerprint is pinned. It serves committed, signature-verified events for the selected Space generation after Noise transcript identity proof and scope authorization. `space_generation_scope_id` provides the generation-bound scope ID for a compatible initiator. The server does not apply received events, exchange summaries, select router paths, or claim recipient delivery.

`sync fetch-once --connect <addr> --space-id <hex> --group-reference <hex> --peer-fingerprint <hex> --event-id <hex>` requests one exact event ID from a previously pinned TCP peer over Noise. It verifies the signed event's ID, author, sequence, and selected generation, then passes application events through the Core MLS and Space-authorization transaction. Events with missing signed parents enter the bounded pending store. This command does not process MLS Commits or provide a summary exchange, full-history sync, or recipient-delivery proof.

## Command behavior and output

`space_create` and each `space_list` row include `channels`, whose entries contain lowercase hexadecimal `id`, `name`, `type`, and `archived`. `send` and `space_edit` return `state: "queued"`, the lowercase hexadecimal `event_id`, and explicit `forwarded: false`, `delivered: false`, and `network_contacted: false` fields. `send` commits the event, encrypted cache entry, and durable outbox record locally before reporting success. `space_history` returns the requested IDs, `source: "encrypted_local_text_cache"`, `network_contacted: false`, and a `messages` array containing event, channel, author, sequence, Lamport, content, and optional outbox-state fields.

`space_restore` returns `state: "local_snapshot_restored"`, the verified generation identifiers and channel summaries, `remote_membership: "not_checked"`, and `network_contacted: false`.

`space_join` returns `state: "local_welcome_imported"`, the imported Space/group/root event IDs and channel summaries, `local_state_persisted: true`, and explicit `network_contacted`, `peer_delivery`, and `general_history_replayed` false values.

`space_recover` returns `state: "one_member_recovery_generation_created"`, the prior and new group references, supported channels, `prior_members_rejoined: false`, and `network_contacted: false`. This reports only a local generation change; it does not establish current or remote membership.

All commands operate on an explicitly selected local profile/data directory, preventing accidental overlap between two identities. Read-only commands (`identity show`, `space list`, `space restore`, `space history`, `sync status`, `doctor`) must not mutate network membership. `space list` verifies local Genesis records only and does not establish current membership. `space restore` verifies a named local snapshot, not current or remote membership. `space history` returns the bounded local text cache, not a synchronized transcript. Mutating commands show the event ID and accurate local/destination state; `--json` returns versioned field names and stable error code, while human output may be reformatted. Secret export or reset, if implemented, requires a separate explicit confirmation and protected destination; a normal diagnostic never prints secret bytes.
JSON output uses `schema_version: 1`. `identity` returns lowercase hexadecimal `fingerprint` and `public_bundle` fields plus `private_key_exposed: false` and `capabilities` (`message_authoring: true` for the local outbox only; `authenticated_spaces` and `network_delivery` remain false); `identity_csr` returns PEM when no output path is supplied or the created path after `--output`; `status` returns the identity state and explicit unavailable capability booleans; `about` separates `available` from `unavailable` capability names. `space_list` returns at most 32 `{space_id, group_reference, channels}` records and a nullable `next_cursor`; each channel record contains lowercase hexadecimal `id`, `name`, `type`, and `archived`. `space_restore` includes `state: "local_snapshot_restored"`, verified `channels`, and `network_contacted: false`.

The JSON `about.available` array includes `local_space_one_member_recovery` and `local_pinned_welcome_bootstrap_import`; full invitation/leave and ongoing membership management and network delivery remain unavailable.

`identity pin` requires an initialized profile. It accepts a 65-byte public bundle and its expected 32-byte fingerprint as hexadecimal, recomputes the fingerprint, then stores the exact bundle bytes. Repeating an identical pin is idempotent. A different bundle for an existing fingerprint is rejected without overwrite. `identity pinned` looks up a record by its full fingerprint. A stored pin does not prove that a person compared fingerprints out of band, authenticate a session, validate an MLS credential, or grant Space membership.

`identity csr` requires an initialized profile. It returns a PEM-wrapped PKCS#10 request on stdout, or writes to a new `--output` file without replacing existing data. The request's Ed25519 SPKI matches the local identity and its URI SAN requests `urn:lattice:identity:v1:<lowercase-full-fingerprint>`; the issuer must preserve this SAN. The CSR alone is not a trusted MLS credential.

| Command | Success signal | Common failure |
| --- | --- | --- |
| `identity show` | Full device fingerprint and storage tier | Locked/unavailable key store |
| `identity csr` | PKCS#10 PEM for the local public key and fingerprint SAN | Missing identity, encoding failure, or existing output file |
| `space list` | Verified local Space IDs and an optional next-page cursor | Missing identity, corrupt Genesis event or failed snapshot authentication |
| `space restore` | Revalidated local signed Genesis and protected MLS snapshot | Missing identity/snapshot or failed integrity check |
| `space recover` | New authorized one-member local recovery generation | Untrusted credential, missing snapshot or denied recovery permission |
| `peer scan` | Ephemeral path/capability observations | Permission denied or radio unavailable |
| `space join` | Pinned-inviter Welcome checkpoint imported locally | Invalid package or credential, inviter not pinned, or rejected MLS Welcome |
| `send` | Durable event ID and queued/delivery status | Storage full, denied permission, invalid draft |
| `relay test` | Transport connectivity/compatibility result | Relay unreachable, incompatible profile, rate limit |
| `node run` | Opt-in active mode with queue/quota report | Invalid DB, key unavailable, port/path conflict |
| `doctor` | Check report with remediation categories | Integrity issue, missing epoch, unsupported transport |

## Node lifecycle

The long-running node starts with a validated identity/config/schema, opens only explicitly enabled transports, restores bounded outbox/courier queues, schedules reconciliation, reacts to termination signals by flushing metadata transactionally and closes paths. Restart never grants it owner privileges or rewrites event IDs. Its log has no default content plaintext; metrics count queue/delivery categories without dumping peers’ message bodies.
