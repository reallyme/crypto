// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::SLH_DSA_SHA2_128S_SECRET_KEY_LEN;
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use slh_dsa::signature::Signer;
use slh_dsa::{Sha2_128s, SigningKey};

/// Sign a message using SLH-DSA-SHA2-128s.
pub fn sign_slh_dsa_sha2_128s(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SLH_DSA_SHA2_128S_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    let signing_key =
        SigningKey::<Sha2_128s>::try_from(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let signature = signing_key
        .try_sign(message)
        .map_err(|_| CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Sign,
            kind: SignatureFailureKind::BackendFailure,
        })?;

    Ok(signature.to_vec())
}
