// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = signP256DerPrehash)]
    fn js_sign_p256_der_prehash(message: Uint8Array, secret_key: Uint8Array) -> Uint8Array;
}

/// Sign using P-256 ECDSA.
/// - SHA-256 prehash
/// - DER-encoded signature
pub fn sign_p256_der_prehash(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let msg = Uint8Array::from(message);
    let sk = Uint8Array::from(secret_key);

    let sig = js_sign_p256_der_prehash(msg, sk).to_vec();

    // DER is variable length; just ensure non-empty
    if sig.is_empty() {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Sign,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    Ok(sig)
}
