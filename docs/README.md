# Lattice documentation

**Project:** Lattice, local-first community communication. **Status:** draft with bounded component implementations; no interoperability release or security audit is implied. **Updated:** 24 September 2026.

## Start here

| If you need… | Read | Owns |
| --- | --- | --- |
| Goal, constraints and document map | This file | Navigation and precedence |
| Full existing engineering specification | [spec.md](spec.md) | Broad product scope and draft wire appendices |
| Architectural boundaries and flows | [architecture.md](architecture.md) | Components, runtime, deployment, decisions |
| Indexed, testable requirements | [REQUIREMENTS.md](REQUIREMENTS.md) | IDs, status, scope and cross-cutting requirements |
| Actual user-visible features | [features/README.md](features/README.md) and its nine area files | Functional requirements and acceptance criteria |
| Technology and interfaces | [TECH_STACK.md](TECH_STACK.md) | Stack, ownership, integration contract |
| Exact draft protocol concerns | [protocol/PROTOCOL.md](protocol/PROTOCOL.md) | Wire, transport, sync and compatibility |
| Trust and keys | [security/SECURITY_MODEL.md](security/SECURITY_MODEL.md) | Threats, MLS, authorization and privacy |
| Storage and records | [data/DATA_MODEL.md](data/DATA_MODEL.md) | Durable model, transactions, retention |
| Build order | [PLAN.md](PLAN.md) | Milestones, gates and dependencies |
| Unfinished work | [TODO.md](TODO.md) | ID-linked execution queue |
| Verification | [quality/TEST_PLAN.md](quality/TEST_PLAN.md) | Matrix and release gates |
| Optional infrastructure | [ops/DEPLOYMENT.md](ops/DEPLOYMENT.md) | Local/relay/node/voice deployment |
| Unsettled choices | [decisions/DECISIONS.md](decisions/DECISIONS.md) | ADR queue and temporary safe behavior |

## Precedence and change rules

1. For approved product behavior, use an identified requirement in `REQUIREMENTS.md` or `features/*`; unimplemented requirements remain proposed.
2. For component boundaries, use `architecture.md` and accepted ADRs. For exact interoperable bytes, future versioned `protocol/specs/*` and vectors supersede examples in `spec.md` and this bundle.
3. `spec.md` is the original integrated engineering baseline, not proof that every draft profile is frozen. Its citation-preserving version is included here for completeness.
4. A change to behavior updates its ID, acceptance criteria, related protocol/security/data document, `PLAN.md` milestone, `TODO.md` item, and tests. Never reuse a retired ID.
5. Three-letter prefixes are registry entries, not team names. See [REQUIREMENTS.md](REQUIREMENTS.md#id-registry).

## Product boundary

Devices store their own authenticated event log. BLE enables nearby text/control; supported local IP paths upgrade bulk and media; optional user-selected relays extend reach. Voice uses WebRTC/Opus and may need separately supplied TURN. “No mandatory project cloud” does not guarantee communication without reachable peers or infrastructure in every topology. [Bitchat](https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md), [Briar](https://briarproject.org/how-it-works/), and the [MLS architecture](https://www.rfc-editor.org/rfc/rfc9750) are relevant prior work, not protocols with which Lattice automatically interoperates.

## Current maturity

Implemented code is still a set of bounded candidates, not an end-to-end
communication product or an interoperability release. Current components cover
canonical encoding and event signatures, device identity protection and local
storage, OpenMLS state operations, signature-to-MLS ciphertext binding, bounded
routing/courier accounting, attachment verification, voice signaling, and
platform adapter contracts, including bounded TCP stream framing. The core
exposes candidate offline Space Genesis creation: one `SQLite` transaction
commits the local MLS generation, exact signed event, and AEAD-protected
initial policy snapshot. `restore_space` and `restore_space_page` rebuild that
initial projection after restart; the latter enumerates local snapshots in
bounded 32-entry keyset pages. Neither restores later policy events. The
caller-supplied opaque X.509 credential is not trust-validated. The relay crate
validates candidate NIP-01/NIP-40 tags, expiry, envelope encoding, and
inner-event signatures. Its bounded `RelayClient` fetches NIP-11 and exchanges
NIP-01 events over secure HTTP/WebSocket, but does not establish
independent-relay interoperability.

Later policy replay, conflict-state recovery, and message projection remain
incomplete. The CLI and desktop expose protected device identity and bounded,
read-only local Space Genesis listing; neither can create or join Spaces yet.
Android exposes the protected local identity snapshot alongside
permission-aware generic BLE discovery and fragment framing.

Space join, membership validation and commit coupling, message-state projection,
voice authorization, durable MLS conflict recovery, native BLE GATT exchange,
authenticated LAN discovery, relay interoperability and core/app wiring, and
end-to-end message workflows remain incomplete.

The OpenMLS API still relies on the caller to verify external credentials and
persist protected group state and recovery metadata. ADR-001 and ADR-002 record
the conflict and channel-read decisions; their full operational workflows and
acceptance evidence remain open. Treat all performance numbers in `spec.md` as
design targets until measured on named devices and networks. No interoperability
or secure-Space claim follows from component-level tests.
