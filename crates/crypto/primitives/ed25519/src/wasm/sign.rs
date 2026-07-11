// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // JS must provide:
    // function signEd25519(message: Uint8Array, secretKey: Uint8Array): Uint8Array
    #[wasm_bindgen(js_name = signEd25519)]
    fn js_sign_ed25519(message: Uint8Array, secret_key: Uint8Array) -> Uint8Array;
}

pub fn sign_ed25519(privkey: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Match Rust signing semantics: accept 32-byte seed or 64-byte expanded key.
    let seed: &[u8] = match privkey.len() {
        32 => privkey,
        64 => &privkey[..32],
        _ => return Err(CryptoError::InvalidKey),
    };

    let msg = Uint8Array::from(message);
    let sk = Uint8Array::from(seed);

    let sig = js_sign_ed25519(msg, sk).to_vec();

    if sig.len() != 64 {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Sign,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    Ok(sig)
}
