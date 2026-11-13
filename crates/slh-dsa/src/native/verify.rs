// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN};
use crypto_core::CryptoError;
use slh_dsa::signature::Verifier;
use slh_dsa::{Sha2_128s, Signature, VerifyingKey};

/// Verify an SLH-DSA-SHA2-128s detached signature.
pub fn verify_slh_dsa_sha2_128s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }
    if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_LEN {
        return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    let verifying_key = VerifyingKey::<Sha2_128s>::try_from(public_key)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let signature = Signature::<Sha2_128s>::try_from(signature)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;

    if verifying_key.verify(message, &signature).is_ok() {
        Ok(())
    } else {
        Err(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    }
}
