// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};

/// Verifies canonical DER over a SHA-256/384/512 digest with PKI ECDSA
/// semantics. Both high-S and low-S are valid; protocol replay defenses must
/// bind the message rather than treating signature bytes as a unique identity.
pub fn verify_p256_digest_der_interoperable(
    public_key_sec1: &[u8],
    digest: &[u8],
    signature_der: &[u8],
) -> Result<(), CryptoError> {
    const SHA256_DIGEST_BYTES: usize = 32;
    const SHA384_DIGEST_BYTES: usize = 48;
    const SHA512_DIGEST_BYTES: usize = 64;
    if !matches!(
        digest.len(),
        SHA256_DIGEST_BYTES | SHA384_DIGEST_BYTES | SHA512_DIGEST_BYTES
    ) {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    let public_key = super::encoding::parse_public_key(public_key_sec1)?;
    let key = VerifyingKey::from(public_key);
    let signature =
        Signature::from_der(signature_der).map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)
}
