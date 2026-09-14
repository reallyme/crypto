// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    append_der_len, der_integer, der_len_encoded_len, trim_unsigned_integer, ASN1_INTEGER_TAG,
};

fn decode_der_len(bytes: &[u8]) -> Option<(usize, usize)> {
    match bytes.first().copied()? {
        first @ 0..=0x7f => Some((usize::from(first), 1)),
        0x81 => bytes.get(1).map(|&len| (usize::from(len), 2)),
        0x82 => {
            let hi = bytes.get(1).copied()?;
            let lo = bytes.get(2).copied()?;
            Some((usize::from(u16::from_be_bytes([hi, lo])), 3))
        }
        _ => None,
    }
}

fn assert_bounded_content_matches(content: &[u8], offset: usize, trimmed: &[u8]) {
    let expected_len = match offset.checked_add(trimmed.len()) {
        Some(value) => value,
        None => {
            assert!(false);
            return;
        }
    };
    assert!(content.len() == expected_len);
    assert!(trimmed.len() >= 1);
    assert!(trimmed.len() <= 3);

    assert!(content[offset] == trimmed[0]);
    if trimmed.len() >= 2 {
        let index = match offset.checked_add(1) {
            Some(value) => value,
            None => {
                assert!(false);
                return;
            }
        };
        assert!(content[index] == trimmed[1]);
    }
    if trimmed.len() >= 3 {
        let index = match offset.checked_add(2) {
            Some(value) => value,
            None => {
                assert!(false);
                return;
            }
        };
        assert!(content[index] == trimmed[2]);
    }
}

#[kani::proof]
fn der_len_round_trips() {
    let len: usize = kani::any();
    kani::assume(len <= 65_535);
    let mut out = Vec::new();
    // Bounded domain guarantees success.
    let _ = append_der_len(&mut out, len);
    let encoded_len = der_len_encoded_len(len).unwrap_or(0);
    assert!(out.len() == encoded_len);
    match decode_der_len(&out) {
        Some((decoded, header)) => {
            assert!(decoded == len);
            assert!(header == out.len());
        }
        None => assert!(false, "length prefix must decode"),
    }
}

#[kani::proof]
fn der_integer_is_well_formed() {
    let value: [u8; 3] = kani::any();
    let encoded = match der_integer(&value) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    // Tag is INTEGER.
    assert!(encoded[0] == ASN1_INTEGER_TAG);
    let trimmed = trim_unsigned_integer(&value);
    let high_bit = trimmed[0] & 0x80 != 0;
    // Content follows a single-byte length in this bounded domain.
    let content = &encoded[2..];
    let positive_prefix_len = usize::from(high_bit);
    let expected_content_len = match trimmed.len().checked_add(positive_prefix_len) {
        Some(value) => value,
        None => {
            assert!(false);
            return;
        }
    };
    assert!(usize::from(encoded[1]) == expected_content_len);
    assert!(content.len() == expected_content_len);
    if high_bit {
        // A single 0x00 sign prefix precedes the trimmed magnitude.
        assert!(content[0] == 0x00);
        assert_bounded_content_matches(content, 1, trimmed);
    } else {
        assert_bounded_content_matches(content, 0, trimmed);
    }
}
