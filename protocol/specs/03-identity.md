# Candidate 1 — device identity bundle

**Status:** local implementation candidate; not an interoperable or independently reviewed credential profile. Rust code is in `crates/lattice-identity` and uses maintained Ed25519/X25519 implementations.

## Device key material

A device generates independent 32-byte Ed25519 signing seed and X25519 static secret from the operating-system CSPRNG. Private keys remain in non-serializable Rust secret types and are zeroized by their underlying types on drop. The crate defines an opaque `PrivateKeyProtector` contract and protected generate/load operations. Desktop builds provide an OS credential-store adapter, and Android supplies an AndroidKeyStore AES-GCM wrapper. Host tests use injected credential stores and fake Android keys; they do not exercise native key stores. A target is production-ready only after fresh-process reopen and locked or revoked key behavior are tested. A successful local profile open reports key availability, not independent identity verification or a durability guarantee.

A signature proves possession of the Ed25519 key only. It does not prove a profile name, Space role, current membership, sender authorization, or human verification. A derived X25519 shared secret is not an encryption key until passed through an appropriate KDF and authenticated protocol transcript; the device-identity API does not define a key schedule or Noise handshake.

## Candidate public bundle bytes

Version 1 has one fixed-width 65-byte encoding:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 1 | version, `0x01` |
| 1 | 32 | Ed25519 verification public key |
| 33 | 32 | X25519 public key |

Unknown bundle versions and byte lengths other than 65 are rejected. The candidate intentionally omits creation time and extensions; any future extensible format requires a new reviewed version. Private keys MUST NOT be included in this encoding.

The identity fingerprint is the full 32-byte digest:

```text
SHA-256(UTF8("lattice:identity-bundle:v1") || 0x00 || exact_65_bundle_bytes)
```

The fingerprint binds both public keys and version. Short human comparison strings, if added, remain display aids; trust and pinning use the full digest.

## X25519 behavior

Bundle parsing and shared-secret derivation reject non-contributory X25519 inputs that yield an all-zero result. Bundle parsing applies this check before a value can be pinned. The derived secret is pairwise material only and is not a Noise session, Space key, MLS epoch secret, authorization token, or finished application cipher.

## Test vectors and outstanding validation

The identity crate verifies the fixed bundle/fingerprint vector in [`../vectors/identity-bundle.json`](../vectors/identity-bundle.json), built from established primitive public-key examples. A Python `cryptography`/`hashlib` cross-check reproduces the public bundle and fingerprint; this is a local cross-check, not independent product interoperability evidence. Additional required evidence: another production implementation, fresh-process secure persistence/reload, locked/revoked platform key behavior, and explicit pinned-key-change handling. None of those platform or interop claims are implied by the local Rust tests.
