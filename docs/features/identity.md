# Identity and onboarding — IDN

One installation equals one v1 cryptographic device identity. Multi-device user accounts are deferred. The human-readable profile is mutable; the full key fingerprint is stable until reset. See [SECURITY_MODEL.md](../security/SECURITY_MODEL.md).

| ID | Requirement | Acceptance criterion | Gate |
| --- | --- | --- | --- |
| IDN-001 | First launch shall create signing/DH keys and a local protected secret without a vendor account. | With Internet blocked, generate and reopen an identity after restart. | M0 |
| IDN-002 | The app shall show a full identity fingerprint and a human comparison format. | Two peers can compare QR/full digest; short display text alone never passes verification. | M1 |
| IDN-003 | Profile name/avatar shall be signed mutable metadata, never authentication input. | Rename preserves fingerprint; name collision cannot impersonate pinned key. | M1 |
| IDN-004 | Invite shall bind Space genesis hash, inviter identity/signature, expiry, nonce and untrusted rendezvous hints. | Tampered, expired and wrong-genesis invites fail; relay hint never grants membership. | M3 |
| IDN-005 | A user shall be able to pin a verified peer after QR or session-bound code comparison. | Key substitution after pin prompts mismatch and rejects silent trust rollover. | M3 |
| IDN-006 | Identity reset shall clearly create a new member identity and require authorized re-add to Spaces. | Old key cannot sign new member actions; recovery path is explicit. | M3 |
| IDN-007 | Secret storage shall use Keychain/Keystore wrapping where supported and report hardware protection accurately. | Test locked/unlocked/reinstalled app cases; no plaintext key in SQLite. | M3 |
| IDN-008 | MLS KeyPackages shall have explicit lifecycle, consumption and replenishment behavior. | Reused non-last-resort package is rejected; lost package yields recoverable join state. | M3 |

Onboarding screens: introduction → create/import device identity → profile → nearby permissions → optional relay choice → create/join Space. Never force relay consent. Backup/export is a future separate profile; no password-reset claim in v1. [MLS architecture](https://www.rfc-editor.org/rfc/rfc9750) describes authentication and KeyPackage delivery responsibilities.

## Complete identity lifecycle

1. **Provision:** Generate random secrets on the device; produce a signed public identity bundle with explicit version and key types. Store secret material behind platform protection before reporting successful onboarding. If persistence fails, discard the provisional identity and show a retry state.
2. **Represent:** Show a full fingerprint derived from exact canonical public bytes. Human-friendly Base32/word/checksum text is only an aid; comparison and pinned trust use the full digest. A nickname, avatar or phone contact may change without rotating identity.
3. **Discover:** A BLE beacon uses a rotating, installation-local token. It identifies a compatible radio service for contact scheduling, not an authenticated person. Only an encrypted and authenticated handshake binds the radio peer to a device key.
4. **Verify:** On first contact, present the key fingerprint or a short authentication string bound to the current session transcript. A user may leave a peer unverified, but the UI must not silently upgrade an unverified nickname into trusted identity. A changed key on a previously pinned contact triggers a blocking warning and an explicit new verification flow.
5. **Join:** Scan/import a signed invite, verify expiry, signer and genesis fingerprint, reach an authorized member, provide a fresh KeyPackage, receive a valid Welcome for the accepted Commit, and persist membership/keys transactionally. A successful scan or relay lookup alone is not a join.
6. **Rotate/reset:** Profile rename is a normal event; key rotation requires a defined signed transition while old key is usable. Loss of the signing root creates a new device identity, and each Space must re-add it through authorized membership. Do not invent account recovery through an untrusted relay.

## Key state and failures

| Situation | Required behavior |
| --- | --- |
| Keychain/Keystore unavailable or locked | Do not send/authenticate; display locked-key state and retry after unlock. |
| KeyPackage stale or consumed | Fetch/advertise a fresh package; reject reuse that would weaken expected secrecy. |
| Wrong Space genesis for an invite | Reject the invite and show the conflicting fingerprint; never substitute a similarly named Space. |
| Expired invite while offline | Locally warn; final authorization occurs on connection with a member under current policy. |
| Two devices claiming same display name | Display verification state/fingerprint; never merge identities by name. |
| Local reinstall with preserved platform key | Restore only if secure-state and DB identity match; otherwise use an explicit repair/reset path. |

The first release deliberately treats two devices owned by one human as two Space members. A later multi-device design must specify device binding, removal, partial compromise and synchronized recovery before claiming user-level identity. The UI should name the actual installation being verified.
