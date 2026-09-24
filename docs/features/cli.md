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

CLI output should support human and machine-readable modes with stable error classes. It may facilitate test harnesses, but its existence does not imply a globally reachable node or centralized administration.

`space list` restores at most 32 local Genesis records per call and returns the next exclusive cursor as 96 hexadecimal characters (16-byte Space ID followed by 32-byte MLS group reference). Use `lattice space list --after <cursor>` to continue. Each result is a verified local snapshot, not a claim of current membership.

## Command behavior and output

All commands operate on an explicitly selected local profile/data directory, preventing accidental overlap between two identities. Read-only commands (`identity show`, `space list`, `sync status`, `doctor`) must not mutate network membership. `space list` verifies local Genesis records only and does not establish current membership. Mutating commands show the event ID and accurate local/destination state; `--json` returns versioned field names and stable error code, while human output may be reformatted. Secret export or reset, if implemented, requires a separate explicit confirmation and protected destination; a normal diagnostic never prints secret bytes.
JSON output uses `schema_version: 1`. `identity` returns lowercase hexadecimal `fingerprint` and `public_bundle` fields plus `private_key_exposed: false`; `status` returns the identity state and explicit unavailable capability booleans; `about` separates `available` from `unavailable` capability names. `space_list` returns at most 32 `{space_id, group_reference}` rows and a nullable `next_cursor`.

| Command | Success signal | Common failure |
| --- | --- | --- |
| `identity show` | Full device fingerprint and storage tier | Locked/unavailable key store |
| `space list` | Verified local Space IDs and an optional next-page cursor | Missing identity, corrupt Genesis event or failed snapshot authentication |
| `peer scan` | Ephemeral path/capability observations | Permission denied or radio unavailable |
| `space join` | Pending/active membership bound to genesis | Invite invalid, expired, policy denied, missing Welcome |
| `send` | Durable event ID and queued/delivery status | Storage full, denied permission, invalid draft |
| `relay test` | Transport connectivity/compatibility result | Relay unreachable, incompatible profile, rate limit |
| `node run` | Opt-in active mode with queue/quota report | Invalid DB, key unavailable, port/path conflict |
| `doctor` | Check report with remediation categories | Integrity issue, missing epoch, unsupported transport |

## Node lifecycle

The long-running node starts with a validated identity/config/schema, opens only explicitly enabled transports, restores bounded outbox/courier queues, schedules reconciliation, reacts to termination signals by flushing metadata transactionally and closes paths. Restart never grants it owner privileges or rewrites event IDs. Its log has no default content plaintext; metrics count queue/delivery categories without dumping peers’ message bodies.
