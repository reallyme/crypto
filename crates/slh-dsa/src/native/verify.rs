// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use slh_dsa::signature::Verifier;
use slh_dsa::{Sha2_128s, Signature, VerifyingKey};

/// Verify an SLH-DSA-SHA2-128s detached signature.
pub fn verify_slh_dsa_sha2_128s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_LEN {
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        });
    }
    let verifying_key =
        VerifyingKey::<Sha2_128s>::try_from(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let signature =
        Signature::<Sha2_128s>::try_from(signature).map_err(|_| CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })?;

    if verifying_key.verify(message, &signature).is_ok() {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
