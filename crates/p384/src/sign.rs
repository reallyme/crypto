// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha384};

use crate::constants::P384_SECRET_KEY_LEN;

/// Sign `message` with P-384 ECDSA using SHA-384 prehashing.
///
/// The returned signature is DER-encoded because DER is the common X.509/PKI
/// boundary format for P-384 signatures. Verifiers accept both S forms because
/// ECDSA validity is not tied to a unique signature representation here.
pub fn sign_p384_der_prehash(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != P384_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let signing_key = SigningKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let digest = Sha384::digest(message);
    let signature: Signature =
        signing_key
            .sign_prehash(&digest)
            .map_err(|_| CryptoError::Signature {
                backend: SignatureBackend::Native,
                operation: SignatureOperation::Sign,
                kind: SignatureFailureKind::BackendFailure,
            })?;

    Ok(signature.to_der().as_bytes().to_vec())
}
