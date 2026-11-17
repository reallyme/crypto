// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const DER_SEQUENCE_TAG: u8 = 0x30;
const DER_INTEGER_TAG: u8 = 0x02;
const DER_LONG_LENGTH: u8 = 0x81;
const DER_PADDED_LONG_LENGTH: u8 = 0x82;
const BER_INDEFINITE_LENGTH: u8 = 0x80;
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
const SEC1_HYBRID_EVEN_TAG: u8 = 0x06;
const SEC1_HYBRID_ODD_TAG: u8 = 0x07;

fn ecdsa_invalid_encodings(
    signature: &[u8],
    public_key: &[u8],
) -> Result<EcdsaInvalidEncodings, VectorGenError> {
    let body = ecdsa_sequence_body(signature)?;
    let body_length = u8::try_from(body.len()).map_err(|_| VectorGenError::EcdsaEncoding)?;
    let mut nonminimal_sequence = vec![DER_SEQUENCE_TAG, DER_PADDED_LONG_LENGTH, 0, body_length];
    nonminimal_sequence.extend_from_slice(body);
    let mut indefinite_sequence = vec![DER_SEQUENCE_TAG, BER_INDEFINITE_LENGTH];
    indefinite_sequence.extend_from_slice(body);
    indefinite_sequence.extend_from_slice(&[0, 0]);

    // Every supported curve's INTEGER length fits the short DER form. Adding
    // a long-form length changes only the representation of the same scalar.
    let (integer_tag, rest) = body.split_first().ok_or(VectorGenError::EcdsaEncoding)?;
    let (integer_length, integer_tail) = rest.split_first().ok_or(VectorGenError::EcdsaEncoding)?;
    if *integer_tag != DER_INTEGER_TAG || *integer_length >= BER_INDEFINITE_LENGTH {
        return Err(VectorGenError::EcdsaEncoding);
    }
    let mut nonminimal_integer_body = vec![DER_INTEGER_TAG, DER_LONG_LENGTH, *integer_length];
    nonminimal_integer_body.extend_from_slice(integer_tail);
    let changed_length =
        u8::try_from(nonminimal_integer_body.len()).map_err(|_| VectorGenError::EcdsaEncoding)?;
    let mut nonminimal_integer = vec![DER_SEQUENCE_TAG];
    if changed_length >= BER_INDEFINITE_LENGTH {
        nonminimal_integer.push(DER_LONG_LENGTH);
    }
    nonminimal_integer.push(changed_length);
    nonminimal_integer.extend_from_slice(&nonminimal_integer_body);

    let (tag, coordinates) = public_key
        .split_first()
        .ok_or(VectorGenError::EcdsaEncoding)?;
    if *tag != SEC1_UNCOMPRESSED_TAG || coordinates.is_empty() {
        return Err(VectorGenError::EcdsaEncoding);
    }
    let mut hybrid_even = vec![SEC1_HYBRID_EVEN_TAG];
    hybrid_even.extend_from_slice(coordinates);
    let mut hybrid_odd = vec![SEC1_HYBRID_ODD_TAG];
    hybrid_odd.extend_from_slice(coordinates);
    Ok(EcdsaInvalidEncodings {
        signature_der_nonminimal_sequence_length: b64u(&nonminimal_sequence),
        signature_der_indefinite_sequence_length: b64u(&indefinite_sequence),
        signature_der_nonminimal_integer_length: b64u(&nonminimal_integer),
        public_key_hybrid_even: b64u(&hybrid_even),
        public_key_hybrid_odd: b64u(&hybrid_odd),
    })
}

fn ecdsa_sequence_body(signature: &[u8]) -> Result<&[u8], VectorGenError> {
    let (tag, rest) = signature
        .split_first()
        .ok_or(VectorGenError::EcdsaEncoding)?;
    let (length, rest) = rest.split_first().ok_or(VectorGenError::EcdsaEncoding)?;
    if *tag != DER_SEQUENCE_TAG {
        return Err(VectorGenError::EcdsaEncoding);
    }
    let (length, body) = if *length == DER_LONG_LENGTH {
        let (length, body) = rest.split_first().ok_or(VectorGenError::EcdsaEncoding)?;
        if *length < BER_INDEFINITE_LENGTH {
            return Err(VectorGenError::EcdsaEncoding);
        }
        (*length, body)
    } else if *length < BER_INDEFINITE_LENGTH {
        (*length, rest)
    } else {
        return Err(VectorGenError::EcdsaEncoding);
    };
    if usize::from(length) != body.len() {
        return Err(VectorGenError::EcdsaEncoding);
    }
    Ok(body)
}
