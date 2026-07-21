// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};

/// Length in bytes of an ES256 JOSE signature (`r || s`).
pub const P256_ECDSA_JOSE_SIGNATURE_LEN: usize = 64;

const SCALAR_LEN: usize = 32;
const DER_SEQUENCE_TAG: u8 = 0x30;
const DER_INTEGER_TAG: u8 = 0x02;
const DER_LONG_FORM_MASK: u8 = 0x80;
const DER_LONG_FORM_LEN_MASK: u8 = 0x7f;
const DER_MAX_LEN_OCTETS: usize = 2;
// The P-256 subgroup order from FIPS 186-5. JOSE transcoding remains available
// without a native provider feature, so scalar validation cannot depend on the
// optional `p256` backend. Signature scalars are public, making an ordinary
// big-endian comparison appropriate here.
const P256_CURVE_ORDER: [u8; SCALAR_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Converts a DER-encoded P-256 ECDSA signature to JOSE `r || s` form.
///
/// This parser requires canonical DER and valid nonzero scalars below the
/// P-256 subgroup order. Non-canonical encodings such as redundant positive
/// INTEGER padding or long-form lengths for short values are rejected.
pub fn p256_ecdsa_der_to_jose_signature(
    der: &[u8],
) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], CryptoError> {
    der_to_jose_signature(der)
}

/// Converts a JOSE `r || s` P-256 ECDSA signature to DER form.
///
/// Both scalars must be nonzero and below the P-256 subgroup order.
pub fn p256_ecdsa_jose_signature_to_der(raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    jose_signature_to_der(raw)
}

fn signature_encoding_error() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    }
}

fn read_len(input: &[u8], offset: &mut usize) -> Result<usize, CryptoError> {
    let b = *input.get(*offset).ok_or_else(signature_encoding_error)?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(signature_encoding_error)?;

    if b & DER_LONG_FORM_MASK == 0 {
        return Ok(usize::from(b));
    }

    let len_octets = usize::from(b & DER_LONG_FORM_LEN_MASK);
    let end = (*offset)
        .checked_add(len_octets)
        .ok_or_else(signature_encoding_error)?;
    if len_octets == 0 || len_octets > DER_MAX_LEN_OCTETS || end > input.len() {
        return Err(signature_encoding_error());
    }
    if len_octets > 1 && input.get(*offset) == Some(&0x00) {
        return Err(signature_encoding_error());
    }

    let mut len = 0usize;
    for byte in &input[*offset..end] {
        len = len
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or_else(signature_encoding_error)?;
    }
    *offset = end;
    if len < usize::from(DER_LONG_FORM_MASK) {
        return Err(signature_encoding_error());
    }
    Ok(len)
}

fn strip_leading_zero(mut bytes: &[u8]) -> &[u8] {
    while bytes.len() > 1 && bytes[0] == 0x00 {
        bytes = &bytes[1..];
    }
    bytes
}

fn validate_scalar(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() != SCALAR_LEN
        || bytes.iter().all(|byte| *byte == 0)
        || bytes >= P256_CURVE_ORDER.as_slice()
    {
        return Err(signature_encoding_error());
    }
    Ok(())
}

fn left_pad_scalar(bytes: &[u8]) -> Result<[u8; SCALAR_LEN], CryptoError> {
    if bytes
        .first()
        .is_some_and(|first| (first & DER_LONG_FORM_MASK) != 0)
    {
        return Err(signature_encoding_error());
    }
    if bytes.len() > 1 && bytes[0] == 0x00 && (bytes[1] & DER_LONG_FORM_MASK) == 0 {
        return Err(signature_encoding_error());
    }

    let bytes = strip_leading_zero(bytes);
    if bytes.len() > SCALAR_LEN {
        return Err(signature_encoding_error());
    }

    let mut out = [0u8; SCALAR_LEN];
    let start = SCALAR_LEN
        .checked_sub(bytes.len())
        .ok_or_else(signature_encoding_error)?;
    out[start..].copy_from_slice(bytes);
    validate_scalar(&out)?;
    Ok(out)
}

fn der_integer_bytes(bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let bytes = strip_leading_zero(bytes);
    if !bytes.is_empty() && (bytes[0] & DER_LONG_FORM_MASK) != 0 {
        let capacity = bytes
            .len()
            .checked_add(1)
            .ok_or_else(signature_encoding_error)?;
        let mut out = Vec::with_capacity(capacity);
        out.push(0x00);
        out.extend_from_slice(bytes);
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), CryptoError> {
    if len < usize::from(DER_LONG_FORM_MASK) {
        out.push(u8::try_from(len).map_err(|_| signature_encoding_error())?);
        return Ok(());
    }

    if len <= usize::from(u8::MAX) {
        out.push(0x81);
        out.push(u8::try_from(len).map_err(|_| signature_encoding_error())?);
        return Ok(());
    }

    if len <= usize::from(u16::MAX) {
        let len16 = u16::try_from(len).map_err(|_| signature_encoding_error())?;
        out.push(0x82);
        out.extend_from_slice(&len16.to_be_bytes());
        return Ok(());
    }

    Err(signature_encoding_error())
}

fn read_der_integer<'a>(der: &'a [u8], offset: &mut usize) -> Result<&'a [u8], CryptoError> {
    if der.get(*offset) != Some(&DER_INTEGER_TAG) {
        return Err(signature_encoding_error());
    }
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(signature_encoding_error)?;
    let len = read_len(der, offset)?;
    let end = (*offset)
        .checked_add(len)
        .ok_or_else(signature_encoding_error)?;
    if len == 0 || end > der.len() {
        return Err(signature_encoding_error());
    }

    let bytes = &der[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn der_to_jose_signature(der: &[u8]) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], CryptoError> {
    let mut offset = 0usize;
    if der.get(offset) != Some(&DER_SEQUENCE_TAG) {
        return Err(signature_encoding_error());
    }
    offset = offset.checked_add(1).ok_or_else(signature_encoding_error)?;

    let seq_len = read_len(der, &mut offset)?;
    let seq_end = offset
        .checked_add(seq_len)
        .ok_or_else(signature_encoding_error)?;
    if seq_end != der.len() {
        return Err(signature_encoding_error());
    }

    let r = left_pad_scalar(read_der_integer(der, &mut offset)?)?;
    let s = left_pad_scalar(read_der_integer(der, &mut offset)?)?;
    if offset != der.len() {
        return Err(signature_encoding_error());
    }

    let mut out = [0u8; P256_ECDSA_JOSE_SIGNATURE_LEN];
    out[..SCALAR_LEN].copy_from_slice(&r);
    out[SCALAR_LEN..].copy_from_slice(&s);
    Ok(out)
}

fn jose_signature_to_der(raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if raw.len() != P256_ECDSA_JOSE_SIGNATURE_LEN {
        return Err(signature_encoding_error());
    }

    validate_scalar(&raw[..SCALAR_LEN])?;
    validate_scalar(&raw[SCALAR_LEN..])?;
    let r = der_integer_bytes(&raw[..SCALAR_LEN])?;
    let s = der_integer_bytes(&raw[SCALAR_LEN..])?;
    let capacity = r
        .len()
        .checked_add(s.len())
        .and_then(|len| len.checked_add(6))
        .ok_or_else(signature_encoding_error)?;
    let mut seq = Vec::with_capacity(capacity);
    seq.push(DER_INTEGER_TAG);
    write_len(&mut seq, r.len())?;
    seq.extend_from_slice(&r);
    seq.push(DER_INTEGER_TAG);
    write_len(&mut seq, s.len())?;
    seq.extend_from_slice(&s);

    let mut out = Vec::with_capacity(
        seq.len()
            .checked_add(4)
            .ok_or_else(signature_encoding_error)?,
    );
    out.push(DER_SEQUENCE_TAG);
    write_len(&mut out, seq.len())?;
    out.extend_from_slice(&seq);
    Ok(out)
}
