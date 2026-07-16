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

/// Converts a DER-encoded P-256 ECDSA signature to JOSE `r || s` form.
///
/// This parser requires canonical DER. Non-canonical encodings such as
/// redundant positive INTEGER padding or long-form lengths for short values are
/// rejected.
pub fn p256_ecdsa_der_to_jose_signature(
    der: &[u8],
) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], CryptoError> {
    der_to_jose_signature(der, true)
}

/// Converts a DER-encoded P-256 ECDSA signature to JOSE `r || s` form while
/// accepting legacy non-canonical DER accepted by older ReallyMe envelopes.
///
/// Use this only at compatibility boundaries. New code should prefer
/// [`p256_ecdsa_der_to_jose_signature`].
pub fn p256_ecdsa_der_to_jose_signature_permissive(
    der: &[u8],
) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], CryptoError> {
    der_to_jose_signature(der, false)
}

/// Converts a JOSE `r || s` P-256 ECDSA signature to DER form.
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

fn read_len(input: &[u8], offset: &mut usize, strict: bool) -> Result<usize, CryptoError> {
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
    if strict && len_octets > 1 && input.get(*offset) == Some(&0x00) {
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
    if strict && len < usize::from(DER_LONG_FORM_MASK) {
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

fn left_pad_scalar(bytes: &[u8], strict: bool) -> Result<[u8; SCALAR_LEN], CryptoError> {
    if bytes
        .first()
        .is_some_and(|first| (first & DER_LONG_FORM_MASK) != 0)
    {
        return Err(signature_encoding_error());
    }
    if strict && bytes.len() > 1 && bytes[0] == 0x00 && (bytes[1] & DER_LONG_FORM_MASK) == 0 {
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
    Ok(out)
}

fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let bytes = strip_leading_zero(bytes);
    if !bytes.is_empty() && (bytes[0] & DER_LONG_FORM_MASK) != 0 {
        let mut out = Vec::with_capacity(bytes.len() + 1);
        out.push(0x00);
        out.extend_from_slice(bytes);
        out
    } else {
        bytes.to_vec()
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

fn read_der_integer<'a>(
    der: &'a [u8],
    offset: &mut usize,
    strict: bool,
) -> Result<&'a [u8], CryptoError> {
    if der.get(*offset) != Some(&DER_INTEGER_TAG) {
        return Err(signature_encoding_error());
    }
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(signature_encoding_error)?;
    let len = read_len(der, offset, strict)?;
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

fn der_to_jose_signature(
    der: &[u8],
    strict: bool,
) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], CryptoError> {
    let mut offset = 0usize;
    if der.get(offset) != Some(&DER_SEQUENCE_TAG) {
        return Err(signature_encoding_error());
    }
    offset = offset.checked_add(1).ok_or_else(signature_encoding_error)?;

    let seq_len = read_len(der, &mut offset, strict)?;
    let seq_end = offset
        .checked_add(seq_len)
        .ok_or_else(signature_encoding_error)?;
    if seq_end != der.len() {
        return Err(signature_encoding_error());
    }

    let r = left_pad_scalar(read_der_integer(der, &mut offset, strict)?, strict)?;
    let s = left_pad_scalar(read_der_integer(der, &mut offset, strict)?, strict)?;
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

    let r = der_integer_bytes(&raw[..SCALAR_LEN]);
    let s = der_integer_bytes(&raw[SCALAR_LEN..]);
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
