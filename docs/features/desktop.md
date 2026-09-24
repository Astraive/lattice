# Desktop client — DSK

Tauri v2 embeds the same Rust core; React/TypeScript/Vite present state through a narrow command and event API. The frontend is not a privileged key or packet authority.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| DSK-001 | Desktop shall create/import local identity and join Spaces using Rust core. | Desktop and mobile agree on fingerprint, wire vectors and Space state. | M7 |
| DSK-002 | Desktop shall support text, threads, local search, files and voice per the same accepted requirements. | Feature interop scenarios with Android/iOS; unsupported path shown. | M7 |
| DSK-003 | Desktop shall discover local peers and expose optional configured relays. | LAN path and two relay settings tested; no project service required. | M7 |
| DSK-004 | Desktop shall keep secrets in Rust/platform storage with minimal Tauri commands and strict CSP. | XSS/command-ACL review shows UI cannot fetch raw secret or arbitrary file. | M7 |
| DSK-005 | Desktop shall be able to opt into persistent courier/peer behavior with quotas. | On/off toggle, restart-safe queue and no Space privilege elevation. | M7 |
| DSK-006 | Desktop builds shall be reproducible enough to compare generated bindings and protocol vectors. | Clean build matches committed vector outputs on supported OS matrix. | M8 |
| DSK-007 | Desktop shall export an Ed25519 PKCS#10 request bound to the full identity fingerprint without exposing private material. | Generate and display/copy the CSR as PEM; its signature, SPKI and URI SAN verify, and an issued certificate must preserve the SAN. | M7 |

The desktop prototype protects device identity, creates local one-member Genesis snapshots from a supplied RFC 9420 TLS X.509 credential vector, and browses verified local snapshots. Create/list responses expose initial channel IDs, names, types, and archived state. A local composer revalidates the device certificate and queues authorized text to the durable outbox; its cached-message view offers author edits as immutable events and updates the encrypted cached body transactionally. The latest 100 locally cached outgoing messages are listed per channel. The recovery form validates the supplied credential and asks Rust to restore a named snapshot before creating a one-member recovery generation; it reports the new group reference and explicitly says prior members did not rejoin and no network was contacted. Recovery preserves supported channel descriptors, drops custom-role definitions, and resets membership to the local administrator. The cache is encrypted with the protected MLS storage key and is not a synced transcript; incoming messages and later policy changes are not replayed. Certificate issuance/import, remote joins, and network delivery remain unavailable.

Tauri security boundary and local content rendering are reviewed separately from Rust protocol correctness. A persistent desktop helps availability but never becomes mandatory for a Space.

The Windows host Tauri build (`bun run tauri build --no-bundle`) succeeds and the executable starts. `bun run tauri build` produced the configured MSI and NSIS installer bundles. End-to-end recovery submission against an initialized profile remains unverified.

## Process and security boundary

The React WebView receives prepared view models, not raw keys, MLS states or unrestricted filesystem access. Tauri commands expose named actions with input validation and minimal capabilities. Rich message content is escaped/sanitized; remote HTML, executable attachment previews and arbitrary URLs cannot obtain local protocol privileges. The Rust side owns SQLite transaction, crypto and network adapter lifecycle. A second desktop window uses the same single core instance and does not race two authors with one local `author_seq`.

## Persistent peer mode

With user opt-in, desktop can remain online for a Space it belongs to and hold authorized history under retention, or act as courier of opaque envelopes without membership. These are different modes: courier-only holds no Space keys; member mode can decrypt according to membership and local storage policy. The operator sees byte quota, queue depth, uptime, relay connections and power/network impact. If it disappears, other peers keep valid history and reconcile on another path when available.

## Desktop release matrix

Test clean install, key locked, database migration, suspend/resume, network change, firewall restriction, local discovery and relay fallback on each supported desktop OS. Bundle pinning and Tauri command ACL/CSP review are separate release gates from protocol vector parity. An update must not silently run two incompatible versions against one writable SQLite database.
