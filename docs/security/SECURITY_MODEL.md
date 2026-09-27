# Security and privacy model

**Status:** design target, not an audit. Protection claims apply only to defined actors and validated software. Core IDs: LAT-003/009/010/015/019, IDN-004–008, SPC-004–011, NET-001/010, VOC-002.

## Assets and adversaries

| Asset | Primary threat | Boundary |
| --- | --- | --- |
| Device signing/DH and MLS secrets | Stolen/compromised installation | Secure storage, key deletion and local access policy |
| Space content | Radio observer, courier, relay, non-member | MLS/application AEAD and authenticated event validation |
| Membership/roles | Malicious member, inconsistent branch | Causal policy, signed events, valid MLS epoch |
| Availability | Relay withholding, courier drop, OS suspension | Alternate paths and honest status; no absolute guarantee |
| Metadata | Radio tracking, relay correlation | Rotating app token, minimal tags; no anonymity claim |

Adversaries include passive local radio sniffer; active frame injector/replayer; malicious authorized member; malicious or colluding relays/couriers; remote parser attacker; Sybil identities; stolen locked/unlocked device; and buggy clients. A global passive observer and physically compromised unlocked endpoint are outside anonymity/content-confidentiality guarantees. All users entitled to decrypt a message can retain it, screenshots included.

## Cryptographic layers

1. Device identity: Ed25519 public verification and X25519 pairwise key; profile mutable separately. Platform-protected wrapping where supported. Never reveal private material to the WebView or diagnostics.
2. Authenticated direct sync: one-shot Snow Noise XX with the fixed `lattice:direct-sync:noise-xx:v1\0` prologue. Each side signs the final handshake hash, signer role, and exact initiator/responder identity bundles; the peer signature must match the caller's pin. Sync frames use Noise's ordered transport state, and callers must authorize scope before planning or serving it. Discovery-token binding, capability negotiation, and other nearby adapters are not connected to this path. Link confidentiality and identity proof do not authorize Space actions.
3. Space/DM: MLS 1.0 group membership/epochs. Removed member does not receive future valid epoch keys; confidentiality of prior plaintext is not retroactively restored.
4. Local data: protected keys plus encrypted sensitive blobs, while documenting any plaintext indexing metadata. “Encrypted database” is not claimed unless measured true for the shipped schema.
5. Voice: WebRTC media path with current Space/session authorization. TURN routes packets but is not Space authority.
6. MLS credential trust: RFC 9420 X.509 credential chains must validate to operating-system roots, and the leaf Ed25519 SPKI and exactly one canonical URI SAN must match the device's Ed25519 key and full identity fingerprint. The URI format is `urn:lattice:identity:v1:<64 lowercase hex characters>`. CSR generation does not issue, import, or validate a certificate.

## Non-negotiable security checks

- A signature proves key possession, not `ROLE_MANAGE` or other permission. Policy evaluation is causal and client-consistent; missing prerequisites are pending, not guessed.
- An MLS X.509 certificate is not identity proof by itself: require a valid OS-rooted path, exact device signing-key SPKI and one canonical full-fingerprint URI SAN. Do not treat a generated CSR as a trusted certificate.
- A Space-wide MLS exporter cannot give private-channel secrecy against another member who can derive it. ADR-002 selects per-channel cryptographic isolation or explicitly restricts “private” to write/join policy.
- Peer-to-peer MLS delivery can fork on simultaneous Commits. ADR-001 accepts fail-closed handling: a non-current valid branch is not applied, conflicting successors block mutation, and recovery requires a new MLS group by explicit invitation. It does not define a winning branch, reissue Welcome messages, or promise old-branch secret deletion; [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750#section-5.2) describes the applicable design space.
- Member ban/removal and moderation are prospective. Clients can refuse new valid epoch content to removed users; they cannot erase what others already know.
- Relay expiry hints do not imply server deletion. Relay IP/time/size/tags can remain visible despite E2EE.
- Rotating BLE tokens avoid an obvious stable app identifier but do not prove untraceability in the presence of timing, RF or correlated handshake observations.

## Abuse controls and review gates

Reject duplicate CBOR keys, noncanonical signed bytes, oversized allocation claims and replayed sessions; rate-limit pre-auth expensive work; cap per-peer fragments, courier entries, CPU and disk. Invalid authenticated objects may be quarantined in bounded diagnostics but never projected. Invite-first Spaces reduce public Sybil abuse, not eliminate it. Desktop Tauri commands have minimal capabilities, strict CSP and escaped message rendering.

Before stable v1: public protocol vectors; parser fuzzing; MLS/key lifecycle review; multi-device secure-storage tests; BLE and relay packet captures; key/reset/recovery review; threat model reconciled with implementation and UI copy; high/critical issues closed. Reference [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) and [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750).

## Trust by protocol phase

| Phase | Peer may learn | Check before advancing | Remaining exposure |
| --- | --- | --- | --- |
| BLE advertisement | Generic Lattice service and rotating token | Bounds and radio scheduling; no identity trust | RF/timing correlation and service presence |
| Pairwise handshake | Identity bundle, version, capabilities after protection | Noise transcript/key pin or first-contact verification | A first-time unverified human identity can be mistaken |
| Space invite/join | Genesis, inviter, rendezvous, KeyPackage | Signature, genesis fingerprint, current policy and MLS Welcome | Invite sharing/metadata and offline stale policy |
| Event forwarding | Opaque size, class, expiry/routing hints | Quotas, replay/expiry, then final end-to-end validation | Timing/size and courier denial of service |
| Content projection | Message and author to authorized member | Epoch and operation permission at causal context | Authorized recipients can copy plaintext |
| Voice | SDP/ICE candidates, session members, media | Voice permission, WebRTC fingerprint and current incarnation | Call peer/topology metadata; TURN sees flow metadata |

## Specific attacks and checks

- **Sybil and spam:** Unauthenticated radio contacts must get tiny processing budgets. Public discovery cannot imply unlimited guest deposits. Invite-first Spaces and per-key/per-radio quotas reduce cost but cannot prove one person per identity.
- **Replay and equivocation:** A copied event is idempotent by ID; an author sequence reused with different valid bytes is an equivocation alert. Session handshake counters/nonces reject link replay. Relay deletion or duplicated publication cannot edit authenticated event bytes.
- **Downgrade:** Protocol version/ciphersuite/capabilities belong in an authenticated transcript. Unsupported mandatory features fail closed; no silent fallback to plaintext transport or weaker group suite.
- **Fork and membership:** A malicious or partitioned delivery service can show members different Commits. Compare authenticated epoch state; ADR-001 fixes branch selection, old-state deletion and recovery. The threat includes a malicious *member*, not only a relay.
- **Key-package misuse:** One-time packages should be consumed once. Last-resort reuse, if supported, is labeled and followed by key update; availability must not quietly override secrecy requirements.
- **At-rest theft:** Separate locked-device filesystem access from an unlocked compromised app. The latter can read its legitimately decrypted content; app encryption cannot claim to protect against code executing with the same privileges.
- **WebView/XSS:** A malicious message is untrusted display data. Escaping, CSP and minimum Tauri capability ACL ensure that rendering it cannot invoke identity export or arbitrary local commands.
- **Traffic analysis:** Rotating app beacons are a narrow mitigation. A relay sees connection/source network metadata and subscriptions, and an observer may correlate sessions by timing, radio characteristics and size.

## Security property matrix

| Property | Mechanism | Verification | Explicit limitation |
| --- | --- | --- | --- |
| Content confidentiality | MLS/application encryption and reviewed primitives | Non-member and relay capture/decryption tests | Authorized members and compromised endpoints retain content |
| Authenticity | Device signatures, MLS credentials, pinning | Forgery, wrong-key and changed-key tests | First-contact verification depends on user action |
| Authorization | Causal permission reducer tied to MLS transitions | Concurrent admin/model tests | ADR-001 and ADR-002 block full claim |
| Forward secrecy/post-compromise security | MLS deletion/update schedule | Key-compromise simulation and state audit | Depends on correct update and deletion; retained old state increases exposure |
| Availability | Multiple paths, anti-entropy, bounded courier/relay | Partition/mobility and relay failure tests | No path or retained copy means no delivery |
| Metadata privacy | Minimal beacon and relay tags | Passive capture correlation study | No anonymity guarantee |

Security incident handling must describe which epochs may be affected, whether a device key or member was compromised, how to issue valid removal/rekey, and how to notify users that previously received data remains exposed. Never call the app “audited” until an identified independent review of a specific release exists.
