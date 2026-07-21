// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Reference DER / SEC1 encoder used only by the external-vector audit.
//!
//! # Deliberate independence
//!
//! This module is an **intentionally independent** re-implementation of the
//! small amount of ASN.1 DER and SEC1 encoding needed to turn upstream vector
//! fields (raw `r`/`s` integers, `qx`/`qy` coordinates, RSA `n`/`e`) into the
//! byte forms the public ReallyMe primitives accept.
//!
//! It does **not** call the production encoders. A conformance oracle that
//! reused the library's own encoder could not detect a bug in that encoder:
//! both sides would agree on the same wrong bytes. Keeping this encoder
//! separate means an encoding regression in production is observable as an
//! external-vector mismatch rather than being silently masked.
//!
//! Independence only adds assurance if the reference encoder is itself correct,
//! so its edge cases — DER minimal-integer form, the `0x80` high-bit sign
//! prefix, and multi-byte length prefixes — are pinned by the unit tests in
//! this module and by the `#[cfg(kani)]` proof harnesses at the bottom of the
//! file. This encoder is audit tooling; it is never compiled into a shipped
//! artifact.

use crate::support::AuditError;

/// ASN.1 `INTEGER` tag.
pub const ASN1_INTEGER_TAG: u8 = 0x02;
/// ASN.1 `SEQUENCE` (constructed) tag.
pub const ASN1_SEQUENCE_TAG: u8 = 0x30;
/// SEC1 uncompressed-point prefix byte.
pub const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// Returns the number of bytes [`append_der_len`] emits for `len`.
pub fn der_len_encoded_len(len: usize) -> Result<usize, AuditError> {
    match len {
        0..=127 => Ok(1),
        128..=255 => Ok(2),
        256..=65_535 => Ok(3),
        _ => Err(AuditError::Shape),
    }
}

/// Appends a DER definite-length encoding of `len` to `output`.
///
/// Supports the short form and the one- and two-byte long forms, which cover
/// every length produced by the vendored vector adapters.
pub fn append_der_len(output: &mut Vec<u8>, len: usize) -> Result<(), AuditError> {
    match len {
        0..=127 => output.push(u8::try_from(len).map_err(|_| AuditError::Shape)?),
        128..=255 => {
            output.push(0x81);
            output.push(u8::try_from(len).map_err(|_| AuditError::Shape)?);
        }
        256..=65_535 => {
            output.push(0x82);
            output.extend_from_slice(
                &u16::try_from(len)
                    .map_err(|_| AuditError::Shape)?
                    .to_be_bytes(),
            );
        }
        _ => return Err(AuditError::Shape),
    }
    Ok(())
}

/// Strips leading zero bytes from a big-endian unsigned integer, keeping a
/// single zero byte for a value that is entirely zero.
pub fn trim_unsigned_integer(value: &[u8]) -> &[u8] {
    match value.iter().position(|byte| *byte != 0) {
        Some(index) => &value[index..],
        None => &[0],
    }
}

/// Appends a DER `INTEGER` encoding of the big-endian unsigned `value`.
///
/// Applies the DER minimal-integer rule and inserts a `0x00` sign prefix when
/// the high bit of the leading content byte is set, so the value is never
/// misread as negative.
pub fn append_der_integer(output: &mut Vec<u8>, value: &[u8]) -> Result<(), AuditError> {
    if value.is_empty() {
        return Err(AuditError::Shape);
    }
    let trimmed = trim_unsigned_integer(value);
    output.push(ASN1_INTEGER_TAG);
    let needs_positive_prefix = trimmed.first().is_some_and(|byte| byte & 0x80 != 0);
    let encoded_len = trimmed
        .len()
        .checked_add(usize::from(needs_positive_prefix))
        .ok_or(AuditError::Shape)?;
    append_der_len(output, encoded_len)?;
    if needs_positive_prefix {
        output.push(0);
    }
    output.extend_from_slice(trimmed);
    Ok(())
}

/// Encodes a big-endian unsigned integer as a standalone DER `INTEGER`.
pub fn der_integer(value: &[u8]) -> Result<Vec<u8>, AuditError> {
    let mut output = Vec::new();
    append_der_integer(&mut output, value)?;
    Ok(output)
}

/// Wraps `body` in a DER `SEQUENCE`.
pub fn der_sequence(body: &[u8]) -> Result<Vec<u8>, AuditError> {
    let capacity = body
        .len()
        .checked_add(der_len_encoded_len(body.len())?)
        .and_then(|value| value.checked_add(1))
        .ok_or(AuditError::Shape)?;
    let mut der = Vec::with_capacity(capacity);
    der.push(ASN1_SEQUENCE_TAG);
    append_der_len(&mut der, body.len())?;
    der.extend_from_slice(body);
    Ok(der)
}

/// Builds a DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature from the
/// raw big-endian `r` and `s` integers supplied by an upstream vector.
pub fn ecdsa_signature_der(r: &[u8], s: &[u8]) -> Result<Vec<u8>, AuditError> {
    let mut body = Vec::new();
    append_der_integer(&mut body, r)?;
    append_der_integer(&mut body, s)?;
    der_sequence(&body)
}

/// Builds a PKCS#1 `RSAPublicKey ::= SEQUENCE { INTEGER n, INTEGER e }` from the
/// raw big-endian modulus and exponent supplied by an upstream vector.
pub fn rsa_pkcs1_public_key_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, AuditError> {
    let mut body = Vec::new();
    append_der_integer(&mut body, modulus)?;
    append_der_integer(&mut body, exponent)?;
    der_sequence(&body)
}

/// Assembles a SEC1 uncompressed point (`0x04 || x || y`) from equal-length
/// big-endian coordinates.
pub fn sec1_uncompressed_point(x: &[u8], y: &[u8]) -> Result<Vec<u8>, AuditError> {
    if x.is_empty() || x.len() != y.len() {
        return Err(AuditError::Shape);
    }
    let capacity = x
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(AuditError::Shape)?;
    let mut point = Vec::with_capacity(capacity);
    point.push(SEC1_UNCOMPRESSED_PREFIX);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Ok(point)
}

/// Decodes a DER definite-length prefix, returning `(length, header_len)`.
///
/// Shared by the unit tests and the Kani proofs to check round-trip behaviour.
#[cfg(any(test, kani))]
pub(crate) fn decode_der_len(bytes: &[u8]) -> Option<(usize, usize)> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

/// Bounded formal proofs of the reference encoder's DER invariants.
///
/// Compiled only under the Kani model checker (`cargo kani`); inert for normal
/// builds. These prove properties that examples can only sample: length-prefix
/// round-tripping and the minimal-integer / sign-prefix rules for every input
/// in the bounded domain.
#[cfg(kani)]
mod proofs {
    use super::*;

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
}
