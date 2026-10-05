#![no_main]

use lattice_crypto::{
    MAX_NOISE_PACKET_SIZE, NoiseHandshakeStep, NoiseRole, NoiseSession,
};
use libfuzzer_sys::fuzz_target;

const PROLOGUE: &[u8] = b"lattice:ble-exp0:fuzz:v1";

fuzz_target!(|packet: &[u8]| {
    let Ok(mut session) = NoiseSession::new(NoiseRole::Responder, PROLOGUE) else {
        return;
    };

    let result = session.read_message(packet);
    match result {
        Ok(payload) => {
            assert!(packet.len() <= MAX_NOISE_PACKET_SIZE);
            assert!(payload.len() <= MAX_NOISE_PACKET_SIZE);
            assert_eq!(session.step(), NoiseHandshakeStep::ResponderSendMessage2);
        }
        Err(_) => assert_eq!(session.step(), NoiseHandshakeStep::Failed),
    }
});
