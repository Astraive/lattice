#![no_main]

use lattice_relay::EnvelopeV1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = EnvelopeV1::decode(data) {
        assert_eq!(envelope.encode(), data);
    }
});
