# Deployment and operations

**Status:** proposed. Lattice does not ship a mandatory authoritative backend. Optional nodes and outside services have distinct trust/availability roles. See [architecture.md](../architecture.md#10-deployment-platform-policy-and-availability).

| Mode | Components | Can work without Internet? | Operator responsibility |
| --- | --- | --- | --- |
| Nearby local | Two active mobile/desktop clients; BLE and permissions | Yes | Device radio/retention/battery |
| Nearby fast | Clients with compatible Wi-Fi Aware/P2P or same LAN | Yes | Capability and local network permissions |
| Courier | Opted-in peers holding bounded ciphertext | Yes, during later encounters | Quota and retention, no delivery guarantee |
| Remote mailbox | User-chosen compatible Nostr relay(s) | No | Relay availability, policy, logging, retention |
| Volunteer node | CLI/desktop installed as persistent peer | Its local side can | Disk quota, uptime, updates, own keys |
| Remote voice | ICE-selected peer path; optional STUN/TURN | On LAN yes; across Internet no | Traversal service where needed |

## Installation configuration

Each device configures identity/key storage, local DB path, transport permissions, optional relay URLs, optional proxy, disk/courier quotas, retention and battery mode. The invite may recommend endpoints but cannot override device policy. No canonical relay list or volunteer node is required for Space correctness. A public relay may refuse events or retain ciphertext indefinitely; the app displays `forwarded` only when it has a path acceptance and not `delivered` until recipient acknowledgment.

## Volunteer peer

An opt-in node runs the same validation and storage model. It can join Spaces normally or hold opaque envelopes as courier; courier-only mode has no Space content keys. It enforces per-peer/global byte budgets, expiry, rate limits, update policy, and local log redaction. Losing the node may reduce availability but not transfer authority. Multiple nodes may coexist and clients need no single bootstrap node to keep existing local Spaces usable.

## Release/upgrade operations

Pin protocol major and tested dependencies. Upgrades preserve canonical event bytes and migrate derived projections; the previous stable schema must be read or migrated. Backups protect a device-local identity only through an explicit encrypted export/recovery design. Do not silently upload private keys or logs. Key reset produces a new identity requiring authorized re-add. Monitor optional relay/voice path via local diagnostics; no mandatory telemetry service. The incident procedure for a compromised member is to remove/rekey and tell users earlier plaintext cannot be recalled.

## Deployment checks

- DNS/Internet blocked: nearby text still works.
- All relays offline: local queue and network status are honest.
- TURN absent behind restrictive NAT: voice fails clearly.
- Phone background restricted: forwarding availability is marked degraded.
- Volunteer node removed: no Space state becomes invalid solely because that node is gone.

Primary references: [Android foreground service restrictions](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start) and [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656). iOS deployment is outside current delivery scope.

## First installation and network modes

Install a signed client build; initialize keys and database locally; grant only needed permissions; create or join a Space. For a fully local path, enable BLE on both active devices and exchange signed invite out-of-band or over local radio. Configure no DNS, relay, STUN, TURN or vendor account: text must still work after authenticated contact. To connect separated users, each participant selects compatible relay endpoints and accepts their metadata/availability tradeoffs; invites may carry suggestions but not mandatory project-controlled URLs. To call across NATs, enable allowed ICE candidates and an optional TURN service, with clear relay cost and failure display.

## Configuration ownership

| Parameter | Owner | Effect |
| --- | --- | --- |
| Radio and foreground-mode permission | OS and local user | Controls whether nearby path can run |
| Relay URLs/proxy and metered policy | Local user/device | Controls Internet publication/subscriptions |
| Space role/channel/retention defaults | Authenticated Space events | Defines valid operations, subject to device storage policy |
| Courier max bytes/TTL/copy budget | Local user and protocol upper bounds | Limits third-party disk/radio work |
| STUN/TURN endpoints | Local/community operator | Permits selected voice network paths |
| Key protection/storage path | Platform client | Controls local secret and database behavior |

Persist configuration with schema/version, validate endpoints before using them, and never treat a received URL as a trusted source of executable policy. A change to relay set does not rewrite events or MLS membership. Turning off Internet relay stops new publication and may strand already queued remote delivery; local history remains intact.

## Operational states and failures

Volunteer node can be a trusted Space member with content keys or an opaque courier without them. It needs opt-in quotas, startup integrity checks, patching, shutdown flush and local redacted logs. If a node is lost, clients contact one another or other nodes later; if no peer retains a missing item, the history gap is irrecoverable without an authorized backup/snapshot. A relay outage causes `queued`/`forwarded` uncertainty, not Space deletion. A restrictive NAT without TURN causes a voice connection failure, not text data corruption. OS radio suspension defers local contacts; no background guarantee is advertised.

## Release and incident playbooks

Before shipping: run clean install and migration, verify signed release package, confirm new protocol capability handshake, review dependency advisories, inspect BLE/relay captures, compare privacy copy with actual traffic, and publish supported device matrix. For compromised device/member: identify affected identity and epochs, publish valid member removal/rekey from an authorized state, revoke old invites where possible, warn recipients about prior plaintext and instruct affected installation to reset/rejoin. For corrupt local DB: preserve diagnostic evidence without keys in logs, avoid auto-accepting a relay’s replacement history, recover from verified peers or an approved snapshot profile.
