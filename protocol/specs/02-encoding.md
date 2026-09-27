# Candidate 1 — canonical CBOR encoding

**Status:** executable implementation candidate; not a frozen interoperability contract. The Rust implementation is `crates/lattice-protocol/src/lib.rs`. Byte vectors are in [`protocol/vectors/canonical-cbor.json`](../vectors/canonical-cbor.json).

## Encoding subset

Use CBOR as specified by [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949), restricted to one definite-length item consisting only of:

- unsigned integers in `0..=2^64-1`;
- negative integers in `-2^63..=-1`;
- definite byte strings and UTF-8 text strings;
- definite arrays;
- definite maps whose keys are unsigned integers in strictly increasing numeric order;
- `false`, `true`, and `null`.

Floating point, other simple values, tags, non-integer map keys, and all indefinite-length items are unsupported. Event schemas define which keys and value types are valid at each path; this encoding document does not make arbitrary maps valid events.

## Canonical requirements

Encoders MUST use the shortest additional-information width. Arrays, maps, and strings MUST use definite lengths. Decoders MUST reject non-minimal integer or length encodings, reserved additional-information values, duplicate or descending map keys, malformed UTF-8, unsupported major/simple types, truncation, and any bytes after the single decoded item. For integer map keys, ascending numeric order is also deterministic CBOR encoded-key order.

Implementations MUST check the declared event, string, collection, and nesting limits before allocating based on an encoded length. The limits are 1,048,576 bytes per preimage, 262,144 bytes per byte/text string, 4,096 elements per array/map, and 32 container nesting levels.

## Event identifier candidate

Given the exact complete canonical unsigned event preimage bytes `P`, candidate identifier bytes are:

```text
SHA-256(UTF8("lattice:event:v1") || P)
```

The hash excludes the detached author signature and any transport envelope. Rewrapping one canonical event on another route MUST preserve its event ID. The `EventId::from_preimage` implementation first validates exactly one canonical CBOR value and hashes the original bytes; it MUST NOT decode and re-encode historical input before hashing.

## Error mapping

Rust exposes typed encoding failures (`Truncated`, `TrailingBytes`, `NonCanonicalInteger`, `IndefiniteLength`, `UnsupportedType`, `InvalidUtf8`, duplicate/unsorted map key, and bound-specific errors). Applications map errors to a stable outer error class; never accept an object after a parser error.

## Vectors

Required examples include shortest integer encodings, nested values, ordered integer-key maps, and the fixed event-ID vector in `canonical-cbor.json`. Negative vectors include non-minimal integer, indefinite array, duplicate and descending map keys, invalid UTF-8, trailing bytes, excessive depth, and over-limit collections/strings. A vector run proves this Rust implementation, not cross-platform interoperability.
