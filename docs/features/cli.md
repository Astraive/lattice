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

`lattice space create` and `lattice space list` expose each channel's random 16-byte ID, name, type, and archived status so callers can target a channel. `lattice space message --space-id <hex> --group-reference <hex> --credential <path> --channel-id <hex> --text <text>` uses a bounded RFC 9420 X.509 credential vector and queues an authorized text event in the local outbox. A successful result reports `queued` and its event ID only; it does not forward or deliver the message and makes no network request.

The current CLI implements `about`, `status`, `identity init|show|csr|pin|pinned`, `space create|list|message`, `sync status`, `relay add|list|remove|test`, and `doctor`. `space create` commits a local Genesis with the supplied RFC 9420 X.509 credential vector; it does not issue credentials, join another Space, or establish an authenticated membership lifecycle. `space message` queues a locally authorized text event only and makes no network request. `identity csr` exports a PKCS#10 request only; certificate import remains unavailable. `sync status` reports local queue counts, not missing ranges or pending MLS epochs. Relay commands store local `wss://` URLs; `relay test` probes NIP-11 metadata over HTTPS and does not deliver events over WebSocket. `doctor` opens SQLite read-only, reports schema/integrity state, and never applies migrations. Space join/leave, peer scan, scheduled synchronization, and node mode remain unavailable.

## Command behavior and output

`space_create` and each `space_list` row include `channels`, whose entries contain lowercase hexadecimal `id`, `name`, `type`, and `archived`. `space_message` returns `state: "queued"`, the lowercase hexadecimal `event_id`, and explicit `forwarded: false`, `delivered: false`, and `network_contacted: false` fields.

All commands operate on an explicitly selected local profile/data directory, preventing accidental overlap between two identities. Read-only commands (`identity show`, `space list`, `sync status`, `doctor`) must not mutate network membership. `space list` verifies local Genesis records only and does not establish current membership. Mutating commands show the event ID and accurate local/destination state; `--json` returns versioned field names and stable error code, while human output may be reformatted. Secret export or reset, if implemented, requires a separate explicit confirmation and protected destination; a normal diagnostic never prints secret bytes.
JSON output uses `schema_version: 1`. `identity` returns lowercase hexadecimal `fingerprint` and `public_bundle` fields plus `private_key_exposed: false` and `capabilities` (`message_authoring: true` for the local outbox only; `authenticated_spaces` and `network_delivery` remain false); `identity_csr` returns PEM when no output path is supplied or the created path after `--output`; `status` returns the identity state and explicit unavailable capability booleans; `about` separates `available` from `unavailable` capability names. `space_list` returns at most 32 `{space_id, group_reference, channels}` records and a nullable `next_cursor`; each channel record contains lowercase hexadecimal `id`, `name`, `type`, and `archived`.

`identity pin` requires an initialized profile. It accepts a 65-byte public bundle and its expected 32-byte fingerprint as hexadecimal, recomputes the fingerprint, then stores the exact bundle bytes. Repeating an identical pin is idempotent. A different bundle for an existing fingerprint is rejected without overwrite. `identity pinned` looks up a record by its full fingerprint. A stored pin does not prove that a person compared fingerprints out of band, authenticate a session, validate an MLS credential, or grant Space membership.

`identity csr` requires an initialized profile. It returns a PEM-wrapped PKCS#10 request on stdout, or writes to a new `--output` file without replacing existing data. The request's Ed25519 SPKI matches the local identity and its URI SAN requests `urn:lattice:identity:v1:<lowercase-full-fingerprint>`; the issuer must preserve this SAN. The CSR alone is not a trusted MLS credential.

| Command | Success signal | Common failure |
| --- | --- | --- |
| `identity show` | Full device fingerprint and storage tier | Locked/unavailable key store |
| `identity csr` | PKCS#10 PEM for the local public key and fingerprint SAN | Missing identity, encoding failure, or existing output file |
| `space list` | Verified local Space IDs and an optional next-page cursor | Missing identity, corrupt Genesis event or failed snapshot authentication |
| `peer scan` | Ephemeral path/capability observations | Permission denied or radio unavailable |
| `space join` | Pending/active membership bound to genesis | Invite invalid, expired, policy denied, missing Welcome |
| `send` | Durable event ID and queued/delivery status | Storage full, denied permission, invalid draft |
| `relay test` | Transport connectivity/compatibility result | Relay unreachable, incompatible profile, rate limit |
| `node run` | Opt-in active mode with queue/quota report | Invalid DB, key unavailable, port/path conflict |
| `doctor` | Check report with remediation categories | Integrity issue, missing epoch, unsupported transport |

## Node lifecycle

The long-running node starts with a validated identity/config/schema, opens only explicitly enabled transports, restores bounded outbox/courier queues, schedules reconciliation, reacts to termination signals by flushing metadata transactionally and closes paths. Restart never grants it owner privileges or rewrites event IDs. Its log has no default content plaintext; metrics count queue/delivery categories without dumping peers’ message bodies.
