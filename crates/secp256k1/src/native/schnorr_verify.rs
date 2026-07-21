// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_PUBLIC_KEY_LEN, BIP340_SCHNORR_SIGNATURE_LEN,
};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};

fn invalid_signature() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    }
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
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidMessage,
        });
    }
    if public_key_xonly.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let verifying_key =
        VerifyingKey::from_slice(public_key_xonly).map_err(|_| CryptoError::InvalidKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| invalid_signature())?;

    if verifying_key.verify_prehash(message32, &signature).is_ok() {
        Ok(())
    } else {
        Err(invalid_signature())
    }
}
