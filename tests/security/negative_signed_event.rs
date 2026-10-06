use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_protocol::{Value, decode_canonical, encode_canonical};
use serde_json::Value as JsonValue;

const VECTORS: &str = include_str!("../../protocol/vectors/canonical-cbor.json");

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex vector has an odd length");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            let high = digit(pair[0]).expect("vector contains hexadecimal digits");
            let low = digit(pair[1]).expect("vector contains hexadecimal digits");
            high << 4 | low
        })
        .collect()
}

#[test]
fn canonical_signed_event_with_tampered_signature_fails_verification() {
    let vectors: JsonValue =
        serde_json::from_str(VECTORS).expect("published vectors are valid JSON");
    let encoded = vectors["signed_event"]["outer_hex"]
        .as_str()
        .expect("signed-event vector has outer bytes");
    let mut outer = decode_canonical(&decode_hex(encoded)).expect("published event is canonical");
    let Value::Map(fields) = &mut outer else {
        panic!("published event outer value is a map");
    };
    let signature = fields
        .iter_mut()
        .find(|(key, _)| *key == 3)
        .map(|(_, value)| value)
        .expect("outer event contains its signature");
    let Value::Bytes(signature) = signature else {
        panic!("event signature is a byte string");
    };
    signature[0] ^= 1;
    let tampered = encode_canonical(&outer).expect("tampered event remains canonical");

    assert!(VerifiedSignatureOnlyEvent::decode_verify(&tampered).is_err());
}
