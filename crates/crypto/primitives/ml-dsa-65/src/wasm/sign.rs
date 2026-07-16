// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroize;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = signMlDsa65)]
    fn js_sign_ml_dsa_65(message: Uint8Array, secret_seed: Uint8Array) -> Uint8Array;
}

/// Sign a message using ML-DSA-65.
///
/// - Raw message
/// - Detached signature
pub fn sign_ml_dsa_65(secret_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_seed.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let msg = Uint8Array::from(message);
    let sk = Uint8Array::from(secret_seed);

    let mut sig = js_sign_ml_dsa_65(msg, sk).to_vec();

    if sig.len() != 3309 {
        sig.zeroize();
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Sign,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    Ok(sig)
}
