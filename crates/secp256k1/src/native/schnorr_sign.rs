// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{BIP340_SCHNORR_AUX_RAND_LEN, BIP340_SCHNORR_MESSAGE_LEN, SECP256K1_SECRET_KEY_LEN};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use k256::schnorr::SigningKey;

fn invalid_message() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Sign,
        kind: SignatureFailureKind::InvalidMessage,
    }
}

/// Sign a 32-byte BIP-340 message with explicit 32-byte auxiliary randomness.
pub fn sign_bip340_schnorr(
    secret_key: &[u8],
    message32: &[u8],
    aux_rand32: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SECP256K1_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if message32.len() != BIP340_SCHNORR_MESSAGE_LEN
        || aux_rand32.len() != BIP340_SCHNORR_AUX_RAND_LEN
    {
        return Err(invalid_message());
    }
    let signing_key = SigningKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let aux = <&[u8; BIP340_SCHNORR_AUX_RAND_LEN]>::try_from(aux_rand32)
        .map_err(|_| invalid_message())?;
    let signature = signing_key
        .sign_raw(message32, aux)
        .map_err(|_| CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Sign,
            kind: SignatureFailureKind::BackendFailure,
        })?;

    Ok(signature.to_bytes().to_vec())
}
