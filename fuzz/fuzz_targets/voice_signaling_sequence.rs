#![no_main]

use std::time::Duration;

use lattice_voice::{
    MediaStatus, VoiceFailure, VoicePermission, VoicePermissions, VoiceSession,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut session) = VoiceSession::new(
        "fuzz-room",
        Duration::ZERO,
        Duration::from_secs(30),
    ) else {
        return;
    };
    let incarnation = session.incarnation();
    let signaling = String::from_utf8_lossy(data);
    let mut now = Duration::ZERO;

    for (index, command) in data.iter().copied().take(64).enumerate() {
        now = now.saturating_add(Duration::from_millis(u64::from(command & 0x0f) * 1_000));
        let sequence = match command >> 6 {
            0 => session.next_sequence(),
            1 => session.next_sequence().saturating_sub(1),
            2 => session.next_sequence().saturating_add(1),
            _ => u64::from(command),
        };
        let permissions = VoicePermissions::new(command & 0x20 != 0, command & 0x10 != 0);
        let before = session.next_sequence();
        let result = match command % 12 {
            0 => session.join(incarnation, sequence, now, permissions),
            1 => session.send_offer(incarnation, sequence, now, permissions, &signaling),
            2 => session.receive_offer(incarnation, sequence, now, permissions, &signaling),
            3 => session.send_answer(incarnation, sequence, now, permissions, &signaling),
            4 => session.receive_answer(incarnation, sequence, now, permissions, &signaling),
            5 => session.add_candidate(incarnation, sequence, now, permissions, &signaling),
            6 => session.mark_signaling_connected(incarnation, sequence, now, permissions),
            7 => session.fail(
                incarnation,
                sequence,
                now,
                permissions,
                VoiceFailure::NoUsablePath,
            ),
            8 => session.revoke_permission(
                incarnation,
                sequence,
                now,
                VoicePermission::Join,
            ),
            9 => session.leave(incarnation, sequence, now, permissions),
            10 => session.authorize_speaking(incarnation, now, permissions),
            _ if index % 2 == 0 => session.advance_time(now).map(|_| ()),
            _ => session.advance_time(now.saturating_sub(Duration::from_millis(1))).map(|_| ()),
        };

        if command % 12 <= 9 {
            assert_eq!(
                session.next_sequence(),
                if result.is_ok() { before + 1 } else { before }
            );
        } else {
            assert_eq!(session.next_sequence(), before);
        }
        assert_eq!(session.media_status(), MediaStatus::NotImplemented);
        assert!(session.next_sequence() <= u64::try_from(index + 2).unwrap_or(u64::MAX));
    }
});
