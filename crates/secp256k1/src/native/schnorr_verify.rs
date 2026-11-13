// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_PUBLIC_KEY_LEN, BIP340_SCHNORR_SIGNATURE_LEN,
};
use crypto_core::CryptoError;
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};

fn invalid_signature() -> CryptoError {
    crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE
}

/// Verify a BIP-340 Schnorr signature over a 32-byte message.
pub fn verify_bip340_schnorr(
    signature: &[u8],
    message32: &[u8],
    public_key_xonly: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != BIP340_SCHNORR_SIGNATURE_LEN {
        return Err(invalid_signature());
    }
    if message32.len() != BIP340_SCHNORR_MESSAGE_LEN {
        return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    if public_key_xonly.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let verifying_key = VerifyingKey::from_slice(public_key_xonly)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let signature = Signature::from_slice(signature).map_err(|_| invalid_signature())?;

    if verifying_key.verify_prehash(message32, &signature).is_ok() {
        Ok(())
    } else {
        Err(invalid_signature())
    }
}
