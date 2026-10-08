#![no_main]

use lattice_relay::nip11::{
    LATTICE_PROFILE_MIN_MESSAGE_LENGTH, MAX_NIP11_BYTES, Nip11Error, parse_nip11,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = parse_nip11(data);
    if data.len() > MAX_NIP11_BYTES {
        assert!(matches!(
            parsed,
            Err(Nip11Error::InputTooLarge {
                actual,
                maximum: MAX_NIP11_BYTES,
            }) if actual == data.len()
        ));
        return;
    }

    if let Ok(capabilities) = parsed {
        if let Some(nips) = &capabilities.supported_nips {
            assert!(nips.len() <= data.len());
            assert!(nips.iter().all(|nip| *nip > 0));
        }

        let expects_profile = capabilities
            .supported_nips
            .as_ref()
            .is_some_and(|nips| nips.contains(&40))
            && capabilities
                .max_message_length
                .is_some_and(|length| length >= LATTICE_PROFILE_MIN_MESSAGE_LENGTH);
        assert_eq!(capabilities.supports_lattice_profile(), expects_profile);
    }
});
