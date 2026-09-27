#![no_main]

use lattice_protocol::{decode_canonical, encode_canonical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = decode_canonical(data) {
        assert_eq!(
            encode_canonical(&value).expect("decoded CBOR re-encodes"),
            data
        );
    }
});
