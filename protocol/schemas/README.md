# Candidate protocol schemas

- `candidate-event-v1.cddl` describes the integer-keyed signed-event envelope and unsigned preimage; `candidate-envelope-v1.cddl` describes the opaque delivery envelope. Both are machine-readable field/type schemas, not replacements for the normative encoding rules in [`../specs/02-encoding.md`](../specs/02-encoding.md), signed-event semantics in [`../specs/05-events.md`](../specs/05-events.md), or delivery-envelope rules in [`../specs/09-envelope.md`](../specs/09-envelope.md).

The event implementation additionally requires exact map keys and field count, sorted unique parent IDs (maximum 64), a valid event kind, a non-empty protected body, and byte-for-byte signing of the encoded preimage under the documented signature domain. The envelope implementation also validates exact keys, expiry ordering and limits, and the embedded event ID. Both rely on canonical CBOR (shortest forms, definite lengths, ordered integer keys, and no trailing bytes). CDDL captures bounded field shapes; cross-field, canonical-byte, cryptographic, and signature-domain conditions remain implementation-level validation and must not be inferred from schema conformance alone.

The schema is candidate protocol documentation. Production interoperability remains governed by the source specifications, implementation, and protocol vectors under `protocol/`.
