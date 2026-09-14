// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    append_der_len, der_integer, der_len_encoded_len, ecdsa_signature_der, sec1_uncompressed_point,
    AuditError,
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

fn expect(actual: &[u8], expected: &[u8]) -> Result<(), AuditError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AuditError::Mismatch)
    }
}

#[test]
fn der_len_short_and_long_forms() -> Result<(), AuditError> {
    let cases: &[(usize, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (127, &[0x7f]),
        (128, &[0x81, 0x80]),
        (255, &[0x81, 0xff]),
        (256, &[0x82, 0x01, 0x00]),
        (65_535, &[0x82, 0xff, 0xff]),
    ];
    for (len, encoded) in cases {
        let mut out = Vec::new();
        append_der_len(&mut out, *len)?;
        expect(&out, encoded)?;
        if der_len_encoded_len(*len)? != out.len() {
            return Err(AuditError::Shape);
        }
    }
    Ok(())
}

#[test]
fn der_len_rejects_out_of_range() -> Result<(), AuditError> {
    // A value beyond the two-byte long form must be rejected, not truncated.
    let mut out = Vec::new();
    if append_der_len(&mut out, 65_536).is_ok() || der_len_encoded_len(65_536).is_ok() {
        return Err(AuditError::Shape);
    }
    Ok(())
}

#[test]
fn der_integer_minimal_and_sign_prefix() -> Result<(), AuditError> {
    // No high bit: no prefix, minimal length.
    expect(&der_integer(&[0x00, 0x7f])?, &[0x02, 0x01, 0x7f])?;
    // High bit set: a 0x00 sign prefix is inserted.
    expect(&der_integer(&[0x80])?, &[0x02, 0x02, 0x00, 0x80])?;
    expect(
        &der_integer(&[0xff, 0x01])?,
        &[0x02, 0x03, 0x00, 0xff, 0x01],
    )?;
    // All-zero collapses to a single zero byte.
    expect(&der_integer(&[0x00, 0x00])?, &[0x02, 0x01, 0x00])?;
    // Ordinary multi-byte value.
    expect(&der_integer(&[0x01, 0x02])?, &[0x02, 0x02, 0x01, 0x02])?;
    Ok(())
}

#[test]
fn der_integer_rejects_empty() -> Result<(), AuditError> {
    if der_integer(&[]).is_ok() {
        return Err(AuditError::Shape);
    }
    Ok(())
}

#[test]
fn ecdsa_signature_wraps_two_integers() -> Result<(), AuditError> {
    // r = 0x10, s = 0x80 (s needs the sign prefix).
    expect(
        &ecdsa_signature_der(&[0x10], &[0x80])?,
        &[0x30, 0x07, 0x02, 0x01, 0x10, 0x02, 0x02, 0x00, 0x80],
    )
}

#[test]
fn sec1_point_layout() -> Result<(), AuditError> {
    expect(
        &sec1_uncompressed_point(&[0xaa, 0xbb], &[0xcc, 0xdd])?,
        &[0x04, 0xaa, 0xbb, 0xcc, 0xdd],
    )?;
    if sec1_uncompressed_point(&[0x01], &[0x02, 0x03]).is_ok() {
        return Err(AuditError::Shape);
    }
    Ok(())
}

#[test]
fn der_len_round_trips_through_decoder() -> Result<(), AuditError> {
    for len in [0usize, 1, 127, 128, 255, 256, 4096, 65_535] {
        let mut out = Vec::new();
        append_der_len(&mut out, len)?;
        match decode_der_len(&out) {
            Some((decoded, header)) if decoded == len && header == out.len() => {}
            _ => return Err(AuditError::Shape),
        }
    }
    Ok(())
}
