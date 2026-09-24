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

Implemented code remains a set of bounded candidates, not an end-to-end
communication product or an interoperability release. Components cover
canonical event encoding/signatures, device identity protection and local
storage, OpenMLS state operations, MLS-bound event identity/ciphertext checks,
OS-rooted X.509 credential validation for incoming KeyPackages, staged Commits
and Welcome members, bounded routing/courier accounting, attachment
verification, voice signaling, and adapter contracts including bounded TCP
framing. The core creates a local Space Genesis in one `SQLite` transaction
with its MLS generation, exact signed event, and AEAD-protected initial policy
snapshot. `restore_space` and `restore_space_page` restore that initial
projection after restart in bounded 32-entry pages. They do not restore later
policy events. The Space reducer has conflict checks, retained common-policy
recovery authorization, exact MLS Commit-to-control-event binding for member
transitions, and in-memory message/edit/tombstone/reaction/pin projections.
Durable policy replay, transactional MLS merge after policy admission, and
durable conflict recovery remain open.
The relay crate validates candidate NIP-01/NIP-40 tags, expiry, envelope
encoding, and inner-event signatures. Its bounded `RelayClient` fetches NIP-11
and exchanges NIP-01 events over secure HTTP/WebSocket, but independent-relay
interoperability is unverified.

The CLI exposes protected identity init/show, exact peer pins, CSR export,
local Space Genesis create/list, queue-only sync status, local relay URL
settings/NIP-11 tests, and a non-mutating storage doctor. Desktop can create
local one-member Genesis snapshots from a system-trusted X.509 credential
vector, browse local snapshots, pin peers, and export a CSR. Android exposes a
protected identity snapshot, exact peer pins, CSR export, permission-aware BLE
discovery/fragment framing, bounded local Space creation from an OS-trusted
X.509 vector, and local Genesis listing. Space creation creates only a local
one-member candidate; it does not establish remote membership or contact a
network. CSR export does not issue certificates.

Core now has an atomic membership-transition entry point that binds the exact
MLS Commit to its signed parent-epoch control event and MemberTransition
application event, applies the reducer policy, stores both events, and merges
the Commit in one rollback-capable transaction. A focused integration test
proves successful admission and rollback on an invalid control author. Client
workflows do not yet integrate this API or restore the later policy reducer.
Durable conflict recovery, durable messaging, voice authorization/media,
native BLE GATT exchange, authenticated LAN discovery, independent-relay
interoperability, and end-to-end app workflows remain incomplete. Certificate
issuance and profile-wide credential installation are unavailable; the
supplied X.509 vector is consumed only during local Space creation. Joined-group
membership is unavailable. ADR-001 and ADR-002 record the conflict and
channel-read decisions, but operational workflows and acceptance evidence remain
open. Treat performance numbers in `spec.md` as design targets until measured on
named devices and networks. No
interoperability or secure-Space claim follows from component-level tests.
