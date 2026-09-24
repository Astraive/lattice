# Candidate 1 — MLS group state and event binding

**Status:** executable candidate, not an interoperability release. The production API uses OpenMLS, but callers must verify external credentials, protect and persist provider state, and persist/recover the application conflict metadata before enabling Space membership workflows.

## Event-visible MLS group reference

The 32-byte group reference in event key `10` is derived from the exact MLS `GroupId` bytes:

```text
SHA-256(UTF8("lattice:mls-group-reference:v1") || 0x00 || group_id_bytes)
```

This digest is a stable opaque reference, not a credential, membership proof, secret, or authorization grant. An event consumer compares the signed reference with the reference of the MLS group that authenticated and decrypted the exact protected body. A mismatch rejects the event before plaintext is exposed through an event-bound result.

| Input group ID bytes | Group reference (hex) |
| --- | --- |
| UTF-8 `test-group` | `bfc58fc32f3a43d8f8b20ed9fa480ab8ec456d90877e486ccf3c0e0e0e344a02` |

## Application binding requirements

An MLS application result carries the authenticated member's Ed25519 key when the sender is an MLS member, the exact input ciphertext digest, the MLS epoch, and the event-visible group reference. The event binding layer requires all of the following before it returns plaintext together with a verified signed event:

1. The event's identity bundle Ed25519 key equals the authenticated MLS member key.
2. The event's protected-body bytes hash to the exact ciphertext processed by MLS.
3. The event MLS epoch equals the authenticated message epoch.
4. The event group reference equals the reference derived from the MLS group that processed it.

External senders without a member key cannot pass this binding. Passing it proves neither credential trust nor Space/channel permission; those require independent credential verification and a deterministic policy reducer at the event's causal context.

## State and conflict boundary

MLS Commit validation is independent from application membership authorization. Commits are staged against the locally current parent epoch and require explicit exact-byte acceptance before merge. Competing valid successors are quarantined as conflict evidence and stop group mutation under [ADR-001](../../docs/decisions/ADR-001-membership-commit-conflicts.md). Staged-Commit and conflict metadata is currently process-local; a provider/database reload must not be treated as a recoverable operational group until authenticated durable recovery metadata is implemented.

## Credential and persistence boundary

The caller supplies an OpenMLS provider and an X.509 credential. The API binds the local signing key to that credential object but does not parse an X.509 certificate, validate a chain, establish a trust anchor, or map its subject to a human identity. Credential verification policy remains a required caller prerequisite. Provider storage may contain group secrets and must be protected by the application. The test fixture deliberately uses a non-certificate and makes no production trust assertion.
