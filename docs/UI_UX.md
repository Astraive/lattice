# Lattice interaction and interface architecture

**Status:** proposed product behavior. Android and desktop clients share semantic states and design tokens, while respecting each shipped surface’s controls and accessibility APIs. iOS is out of current delivery scope and is not a design or acceptance target. This is not a fixed visual theme or pixel spec.

## Navigation and screens

| Area | Primary screens | State/action relationship |
| --- | --- | --- |
| Onboarding | Welcome, create/import identity, profile, permissions, optional relay, create/join | No vendor login or forced relay; verification before join |
| Communities | Space list, channels, channel messages, threads, members/roles/settings | Show member/permission/pending state from Rust projections |
| Conversation | DM list, DM thread, composer, message actions | Offline composer always available if local commit possible |
| Voice | Room, members, microphone/device, mute/deafen, path state | Join and speaking rights are distinct |
| Transfers | Queue, accept/reject, progress, resume/failure | Bytes verified and completion distinguished |
| System | Invite QR, identity/verification, local retention, relay/network, diagnostics | Explain actual paths and residual metadata |

## Connectivity and delivery language

| State | Display meaning | Never imply |
| --- | --- | --- |
| `queued` | Durable on this device, awaiting path | Another device has it |
| `forwarded` | Next hop/relay accepted bytes | Destination received/read |
| `delivered` | Destination device authenticated receipt | Human read content |
| `read` | Optional recipient-generated read receipt | Every member in Space read it |
| `syncing` | Dependencies/history still arriving | State is globally complete |
| `conflict` | Security-sensitive concurrent state unresolved | A random branch won safely |
| `mesh unavailable` | Radio/permission/OS restriction prevents path | Account lost or Space deleted |

Message history may be partial; use an explicit gap indicator. Presence is a recently observed hint, not a universally correct online indicator. A deleted message and removed member cannot erase copies already received. Voice join should explain direct/TURN/failure path only as far as users need to act. Advanced diagnostics can show path class, queue depth, last sync, permissions and relay health.

## Accessibility and design tokens

Canonical color, type, spacing, radius, elevation, and motion tokens live in `packages/theme/src/index.ts`; the visual surfaces use zero-radius corners, while status indicators may remain circular. Shared React primitives live in `packages/ui/shared`; Desktop and Web page shells live in `packages/ui/desktop` and `packages/ui/web`. React implementations are organized into feature-oriented files, and each package `index.ts`/`index.tsx` is a re-export-only public barrel. Android Compose implementations are split by theme, brand, workspace, identity, spaces, nearby, and messaging under `packages/ui/android`; app-specific destination content and domain state remain in each app. Respect system text scaling and reduced motion; no color-only delivery or mute state. TalkBack and desktop screen-reader/keyboard behavior, semantic labels and announcement of call state are release gates. Theme changes cannot bypass security/protocol states.

### Iconography

Navigation uses Phosphor regular-weight glyphs with visible labels across React and Compose surfaces. Every icon-only action has an accessible semantic name.

## Cross-platform workspace surfaces

Desktop uses a destination rail and a Space/channel sidebar where applicable. At narrow widths the sidebar collapses; the Direct Messages conversation list, selected thread/composer, and Pairing & setup pane stack. Web keeps its profile-creation/open flow ahead of workspace navigation; after unlock, compact navigation uses a bottom bar and a drawer for spaces and channels. Android uses a navigation rail on expanded windows and a bottom bar on compact windows, with destination state preserved while switching.

Desktop Direct Messages keeps the conversation list, selected thread/composer, and Pairing & setup pane in the main workspace. Current conversations, pending invitations, KeyPackage/credential details, and authenticated exchange open only from labeled dialogs; they do not take space as persistent panels below the inbox. Android exposes setup through an action sheet. Web supports Space/channel messaging and has no separate Direct Messages destination. On Desktop conversation changes, only the active conversation's history is shown; stale history remains hidden while matching history loads. Closing a dialog or sheet does not accept or decline an invitation; those transitions require an explicit action. Queued or peer-ingress state must not be presented as destination delivery.

## Edge-case interactions

Offline creation and send; wrong QR fingerprint; no BLE permission; unsupported Wi-Fi Aware; pending MLS epoch; conflicting membership; insufficient disk; rejected file; relay-only delivery; stale presence; ICE/TURN failure; key reset. Every case needs an understandable state and next action. Feature acceptance lives in `features/*`, not in mockups.

## End-to-end flows

**First launch:** explain device-local identity and that nearby operation requires radio permissions. Create identity locally; offer verification explanation, then request BLE permissions only when discovery begins. Relay selection is optional and editable. Creating a Space immediately opens an offline-capable text channel, after which an invite QR shows a genesis fingerprint and expiration.

**Join an invitation:** preview Space name and cryptographic fingerprint, distinguish unverified display data from verified inviter, show local radio/relay paths available, then represent `connecting`, `awaiting approval`, `awaiting MLS Welcome`, or `joined`. If two Spaces share a name but have different genesis fingerprints, never auto-merge them. An expired invite shows an explicit retry request rather than a generic network error.

**Send offline:** composer commits locally and retains draft if storage fails. The bubble moves queued → forwarded → delivered only on the matching evidence. Reconnecting with a peer may update many bubbles without jarring order changes; a history gap has a visible loading/partial-history marker. Deleting a sent bubble generates a tombstone, never claims a remote recall.

**Voice:** join button first checks local Space policy, microphone permission and available IP path. Negotiation shows room participant and connection state; mute actually affects media capture. On restrictive NAT without TURN, display a call setup failure and explain optional path configuration. Text channel remains usable if its own route works.

## Information hierarchy and components

Space rail/list → selected Space’s channels → channel content/threads → right-side details on wide layouts. On mobile use native navigation rather than forcing a desktop pane stack. Common semantic components: member verification badge, connection indicator, message delivery marker, pending/conflict banner, attachment accept/progress, voice participant tile, invite summary, retention control and diagnostic detail sheet. Avoid a universal green “online” dot; use observed recently or path-specific status. Admin controls expose scope, target and security consequence before a removal/rekey.

## Content and safety language

Use “stored on this device,” “sent to a relay,” “received by device,” and “read receipt received” only when those events occur. Explain that relays and nearby observers may learn metadata despite E2EE, and that a removed member may retain earlier content. Do not claim anonymous, always-on, globally online, or audited until matching evidence exists. Error text should give a concrete next action: allow Bluetooth, unlock keys, free storage, reconnect for missing epoch, or configure optional TURN.
