// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 5280 §4.2.1.2 method (1) legacy key identifiers only.
//! This feature does not enable SHA-1 signatures, MACs or document digests.

use crypto_core::CryptoError;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the method-(1) subject key identifier.
pub const SUBJECT_KEY_IDENTIFIER_LEN: usize =
    crypto_core::contract_constants::key_identifier::SUBJECT_KEY_IDENTIFIER_LEN;
/// Local upper bound for subjectPublicKey BIT STRING value bytes.
pub const SUBJECT_PUBLIC_KEY_MAX_LEN: usize =
    crypto_core::contract_constants::key_identifier::SUBJECT_PUBLIC_KEY_MAX_LEN;

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

/// Canonical schema-defined error returned by key-identifier validation.
pub use crypto_core::CryptoError as KeyIdentifierError;

/// Hash the exact subjectPublicKey BIT STRING value, excluding ASN.1 tag,
/// length and unused-bit-count octet. ASN.1 extraction and validation are the
/// caller's responsibility; this function never hashes or parses SPKI for it.
/// Retain any SEC1 point prefix in the extracted payload. Compressed and
/// uncompressed encodings are hashed as received, without point normalization.
pub fn subject_key_identifier_sha1(
    subject_public_key_bits: &[u8],
) -> Result<SubjectKeyIdentifier, CryptoError> {
    if subject_public_key_bits.len()
        < crypto_core::contract_constants::key_identifier::SUBJECT_PUBLIC_KEY_MIN_LEN
    {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    if subject_public_key_bits.len() > SUBJECT_PUBLIC_KEY_MAX_LEN {
        return Err(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED);
    }
    let mut identifier = SubjectKeyIdentifier {
        bytes: [0; SUBJECT_KEY_IDENTIFIER_LEN],
    };
    let mut hasher = Sha1::new();
    hasher.update(subject_public_key_bits);
    hasher.finalize_into((&mut identifier.bytes).into());
    Ok(identifier)
}
