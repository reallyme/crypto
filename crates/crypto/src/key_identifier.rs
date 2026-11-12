// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 5280 §4.2.1.2 method (1) legacy key identifiers only.
//! This feature does not enable SHA-1 signatures, MACs or document digests.

use sha1::{Digest, Sha1};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the method-(1) subject key identifier.
pub const SUBJECT_KEY_IDENTIFIER_LEN: usize = 20;
/// Local upper bound for subjectPublicKey BIT STRING value bytes.
pub const SUBJECT_PUBLIC_KEY_MAX_LEN: usize = 16_384;

/// Clearing key-identifier owner; its output is an identifier, not a signature.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubjectKeyIdentifier {
    bytes: [u8; SUBJECT_KEY_IDENTIFIER_LEN],
}

impl SubjectKeyIdentifier {
    /// Borrow the 20-byte key identifier.
    pub fn as_bytes(&self) -> &[u8; SUBJECT_KEY_IDENTIFIER_LEN] {
        &self.bytes
    }
}

/// Fixed, secret-free key-identifier input failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum KeyIdentifierError {
    /// No subjectPublicKey value was supplied.
    #[error("empty subject public key")]
    EmptyInput,
    /// The subjectPublicKey value exceeds the local bound.
    #[error("subject public key exceeds bound")]
    InputTooLong,
}

/// Hash the exact subjectPublicKey BIT STRING value, excluding ASN.1 tag,
/// length and unused-bit-count octet. ASN.1 extraction and validation are the
/// caller's responsibility; this function never hashes or parses SPKI for it.
/// Retain any SEC1 point prefix in the extracted payload. Compressed and
/// uncompressed encodings are hashed as received, without point normalization.
pub fn subject_key_identifier_sha1(
    subject_public_key_bits: &[u8],
) -> Result<SubjectKeyIdentifier, KeyIdentifierError> {
    if subject_public_key_bits.is_empty() {
        return Err(KeyIdentifierError::EmptyInput);
    }
    if subject_public_key_bits.len() > SUBJECT_PUBLIC_KEY_MAX_LEN {
        return Err(KeyIdentifierError::InputTooLong);
    }
    let mut identifier = SubjectKeyIdentifier {
        bytes: [0; SUBJECT_KEY_IDENTIFIER_LEN],
    };
    let mut hasher = Sha1::new();
    hasher.update(subject_public_key_bits);
    hasher.finalize_into((&mut identifier.bytes).into());
    Ok(identifier)
}
