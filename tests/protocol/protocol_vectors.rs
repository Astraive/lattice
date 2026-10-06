use lattice_events::{EventError, EventKind, VerifiedSignatureOnlyEvent};
use lattice_protocol::{Value, decode_canonical, encode_canonical};
use serde_json::Value as JsonValue;

const CANONICAL_VECTORS: &str = include_str!("../../protocol/vectors/canonical-cbor.json");

fn vectors() -> JsonValue {
    serde_json::from_str(CANONICAL_VECTORS).expect("published vector file is valid JSON")
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex vector has an odd length");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hexadecimal vector byte: {byte}"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn vector_bytes(vector: &JsonValue) -> Vec<u8> {
    decode_hex(
        vector["hex"]
            .as_str()
            .expect("vector has a hexadecimal byte string"),
    )
}

#[test]
fn published_canonical_vectors_roundtrip_and_reject_malformed_bytes() {
    let vectors = vectors();
    let positive = vectors["encoding"]["positive"]
        .as_array()
        .expect("positive vectors are an array");
    for vector in positive {
        let bytes = vector_bytes(vector);
        let value = decode_canonical(&bytes).expect("positive vector decodes");
        assert_eq!(
            encode_canonical(&value).expect("decoded vector re-encodes"),
            bytes,
            "{}",
            vector["name"].as_str().unwrap_or("unnamed positive vector")
        );
    }

    let negative = vectors["encoding"]["negative"]
        .as_array()
        .expect("negative vectors are an array");
    for vector in negative {
        let bytes = vector_bytes(vector);
        assert!(
            decode_canonical(&bytes).is_err(),
            "{}",
            vector["name"].as_str().unwrap_or("unnamed negative vector")
        );
    }
}

#[test]
fn published_signed_event_verifies_and_unknown_mandatory_kind_fails_closed() {
    let vectors = vectors();
    let event_bytes = decode_hex(
        vectors["signed_event"]["outer_hex"]
            .as_str()
            .expect("signed event vector has outer bytes"),
    );
    let event = VerifiedSignatureOnlyEvent::decode_verify(&event_bytes)
        .expect("published signed event verifies");
    assert_eq!(event.author_sequence(), 1);
    assert_eq!(event.kind(), EventKind::Message);
    assert_eq!(event.encoded_bytes(), event_bytes);

    let mut outer = decode_canonical(&event_bytes).expect("published event is canonical CBOR");
    let Value::Map(outer_fields) = &mut outer else {
        panic!("published event outer value is a map");
    };
    let preimage_index = outer_fields
        .iter()
        .position(|(key, _)| *key == 1)
        .expect("outer event contains its signed preimage");
    let Value::Bytes(preimage_bytes) = &outer_fields[preimage_index].1 else {
        panic!("outer event preimage is a byte string");
    };
    let mut preimage = decode_canonical(preimage_bytes).expect("signed preimage is canonical");
    let Value::Map(preimage_fields) = &mut preimage else {
        panic!("signed event preimage is a map");
    };
    let kind = preimage_fields
        .iter_mut()
        .find(|(key, _)| *key == 8)
        .map(|(_, value)| value)
        .expect("preimage has a mandatory event kind");
    *kind = Value::Unsigned(255);
    outer_fields[preimage_index].1 = Value::Bytes(
        encode_canonical(&preimage).expect("unknown kind remains canonically encoded"),
    );
    let unknown_kind_event = encode_canonical(&outer).expect("outer event remains canonical");

    assert_eq!(
        VerifiedSignatureOnlyEvent::decode_verify(&unknown_kind_event),
        Err(EventError::UnknownMandatoryEventKind(255))
    );
    assert!(VerifiedSignatureOnlyEvent::decode_verify(&[0xff]).is_err());
}
