// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = verifyMlDsa44)]
    fn js_verify_ml_dsa_44(
        signature: Uint8Array,
        message: Uint8Array,
        public_key: Uint8Array,
    ) -> bool;
}

/// Verify an ML-DSA-44 detached signature.
pub fn verify_ml_dsa_44(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != 1312 {
        return Err(CryptoError::InvalidKey);
    }
    if signature.len() != 2420 {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    let sig = Uint8Array::from(signature);
    let msg = Uint8Array::from(message);
    let pk = Uint8Array::from(public_key);

    if js_verify_ml_dsa_44(sig, msg, pk) {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        })
    }
}
