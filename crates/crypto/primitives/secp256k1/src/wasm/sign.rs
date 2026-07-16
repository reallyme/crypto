// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // function signSecp256k1(message: Uint8Array, secretKey: Uint8Array): Uint8Array
    #[wasm_bindgen(js_name = signSecp256k1)]
    fn js_sign_secp256k1(message: Uint8Array, secret_key: Uint8Array) -> Uint8Array;
}

/// Signs message bytes using secp256k1 ECDSA.
///
/// The backend hashes the message exactly once with SHA-256, signs that digest
/// with deterministic ECDSA, and returns compact 64-byte `r || s` normalized
/// to low-S.
pub fn sign_secp256k1(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let msg = Uint8Array::from(message);
    let sk = Uint8Array::from(secret_key);

    let sig = js_sign_secp256k1(msg, sk).to_vec();

    if sig.len() != 64 {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Sign,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    Ok(sig)
}
