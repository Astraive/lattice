# Desktop client — DSK

Tauri v2 embeds the same Rust core; React/TypeScript/Vite present state through a narrow command and event API. The frontend is not a privileged key or packet authority.

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| DSK-001 | Desktop shall create/import local identity and join Spaces using Rust core. | Desktop and mobile agree on fingerprint, wire vectors and Space state. | M7 |
| DSK-002 | Desktop shall support text, threads, local search, files and voice per the same accepted requirements. | Desktop search scans the full locally retained authorized channel cache offline, returns the 100 newest matches with the total count, and includes received messages; unavailable remote history is not searched. | M7 |
| DSK-003 | Desktop shall discover local peers and expose optional configured relays. | LAN path and two relay settings tested; no project service required. | M7 |
| DSK-004 | Desktop shall keep secrets in Rust/platform storage with minimal Tauri commands and strict CSP. | XSS/command-ACL review shows UI cannot fetch raw secret or arbitrary file. | M7 |
| DSK-005 | Desktop shall be able to opt into persistent courier/peer behavior with quotas. | On/off toggle, restart-safe queue and no Space privilege elevation. | M7 |
| DSK-006 | Desktop builds shall be reproducible enough to compare generated bindings and protocol vectors. | Clean build matches committed vector outputs on supported OS matrix. | M8 |
| DSK-007 | Desktop shall export an Ed25519 PKCS#10 request bound to the full identity fingerprint without exposing private material. | Generate and display/copy the CSR as PEM; its signature, SPKI and URI SAN verify, and an issued certificate must preserve the SAN. | M7 |

The desktop prototype protects device identity, creates local one-member Genesis snapshots from a supplied RFC 9420 TLS X.509 credential vector, and browses verified local snapshots with channel IDs, names, types, and archived state. Its local composer revalidates the device certificate and queues authorized text to the durable outbox; immutable author edits update the encrypted cached body transactionally. The latest 100 cached messages per channel are listed, including received messages after local authorization and projection. The encrypted local message cache is not a synchronized transcript; remote history is not fetched. Recovery restores a named snapshot before creating a one-member root, preserves supported channels, drops custom-role definitions, and does not rejoin prior members.
For MSG-011, desktop offline search invokes Core to scan every locally retained message in the selected channel, including authorized incoming projections, with case-insensitive content-substring matching. It returns up to 100 newest matches and the exact local match count without contacting the network; remote history remains unavailable.

The Spaces browser also imports a versioned Welcome bootstrap through `import_local_space_welcome_bootstrap`. It accepts a bounded hexadecimal package, exact inviter fingerprint, and X.509 credential, and requires that inviter to be pinned in the protected profile. The result is local signed policy-checkpoint state; no relay is contacted, and general historical-event replay or delivery is not claimed.

The Connectivity panel reports only whether the host exposes a non-loopback IP address; it does not enumerate interfaces, scan peers, or test reachability. Optional `wss://` relay URLs are validated and persisted in the same profile settings used by the CLI. Adding or removing a URL does not contact the relay or activate relay transport.

The local file composer opens the operating-system picker, retains a profile-local content-addressed source copy (128 MiB per file, 512 MiB and 64 sources total), and queues the authorized encrypted manifest in the local outbox. The cache UI lists and removes source copies; removing one does not remove its queued manifest. Source bytes are ordinary files and are not encrypted at rest by this feature. No attachment network transfer, incoming acceptance, or recipient delivery is available in this client.

Tauri security boundary and local content rendering are reviewed separately from Rust protocol correctness. A persistent desktop helps availability but never becomes mandatory for a Space.

The Windows host Tauri build (`bun run tauri build --no-bundle`) succeeds and the executable starts. `bun run tauri build` produced the configured MSI and NSIS installer bundles. End-to-end recovery submission against an initialized profile remains unverified.

## Process and security boundary

The React WebView receives prepared view models, not raw keys, MLS states or unrestricted filesystem access. Tauri commands expose named actions with input validation and minimal capabilities. Rich message content is escaped/sanitized; remote HTML, executable attachment previews and arbitrary URLs cannot obtain local protocol privileges. The Rust side owns SQLite transaction, crypto and network adapter lifecycle. A second desktop window uses the same single core instance and does not race two authors with one local `author_seq`.

## Persistent peer mode

Desktop persistent peer mode is courier-only. Opt-in settings persist a TCP listen address and one exact pinned peer fingerprint, and the listener resumes on application startup. It accepts authenticated opaque courier envelopes serially with bounded sessions and stores them in the existing queue under default 16 MiB/4,096-item total limits; the panel reports queue bytes and items. Disabling the mode stops listening and clears retained courier envelopes. It does not join a Space, decrypt or authorize Space content, automatically forward envelopes, use configured relays, or claim recipient delivery. The default loopback address is local-only; selecting another interface does not prove reachability or bypass firewall policy.

## Desktop release matrix

The current main-window CSP blocks inline styles, base-URL changes, object embeds, framing, and form submissions; its capability grants only `core:default`. This configuration is not a substitute for the DSK-004 XSS and command-ACL review.

Test clean install, key locked, database migration, suspend/resume, network change, firewall restriction, local discovery and relay fallback on each supported desktop OS. Bundle pinning and Tauri command ACL/CSP review are separate release gates from protocol vector parity. An update must not silently run two incompatible versions against one writable SQLite database.
