use lattice_core::SpaceGenesisCursor;

pub(crate) fn parse_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let expected_hex_len = N * 2;
    if value.len() != expected_hex_len {
        return Err(format!(
            "{label} must contain exactly {expected_hex_len} hexadecimal characters"
        ));
    }
    let input = value.as_bytes();
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_value(input[index * 2])
            .ok_or_else(|| format!("{label} contains a non-hexadecimal character"))?;
        let low = hex_value(input[index * 2 + 1])
            .ok_or_else(|| format!("{label} contains a non-hexadecimal character"))?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

pub(crate) fn parse_space_cursor(value: &str) -> Result<SpaceGenesisCursor, String> {
    if value.len() != 96 {
        return Err("Space cursor must contain exactly 96 hexadecimal characters".to_owned());
    }
    let input = value.as_bytes();
    let mut bytes = [0_u8; 48];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_value(input[index * 2])
            .ok_or_else(|| "Space cursor contains a non-hexadecimal character".to_owned())?;
        let low = hex_value(input[index * 2 + 1])
            .ok_or_else(|| "Space cursor contains a non-hexadecimal character".to_owned())?;
        *byte = (high << 4) | low;
    }
    let mut space_id = [0_u8; 16];
    space_id.copy_from_slice(&bytes[..16]);
    let mut group_reference = [0_u8; 32];
    group_reference.copy_from_slice(&bytes[16..]);
    Ok(SpaceGenesisCursor {
        space_id,
        group_reference,
    })
}

pub(crate) fn space_cursor_hex(cursor: SpaceGenesisCursor) -> String {
    let mut bytes = [0_u8; 48];
    bytes[..16].copy_from_slice(&cursor.space_id);
    bytes[16..].copy_from_slice(&cursor.group_reference);
    hex(&bytes)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_fixed_hex, parse_space_cursor, space_cursor_hex};
    use lattice_core::SpaceGenesisCursor;

    #[test]
    fn fixed_hex_parser_checks_exact_ascii_bytes() {
        assert_eq!(parse_fixed_hex::<2>("aB01", "value"), Ok([0xab, 1]));
        assert!(parse_fixed_hex::<2>("aB0", "value").is_err());
        assert!(parse_fixed_hex::<2>("aB0z", "value").is_err());
        assert!(parse_fixed_hex::<1>("ＦＦ", "value").is_err());
    }

    #[test]
    fn space_cursor_round_trips_exact_bytes() {
        let cursor = SpaceGenesisCursor {
            space_id: [0x01; 16],
            group_reference: [0xab; 32],
        };
        let encoded = space_cursor_hex(cursor);
        assert_eq!(parse_space_cursor(&encoded), Ok(cursor));
        assert!(parse_space_cursor("00").is_err());
        assert!(parse_space_cursor(&format!("{}z", &encoded[..95])).is_err());
    }
}
