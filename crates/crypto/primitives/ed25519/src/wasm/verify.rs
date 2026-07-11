// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // JS must provide:
    // function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean
    #[wasm_bindgen(js_name = verifyEd25519)]
    fn js_verify_ed25519(
        signature: Uint8Array,
        message: Uint8Array,
        public_key: Uint8Array,
    ) -> bool;
}

pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    if public.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    if signature.len() != 64 {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    let sig = Uint8Array::from(signature);
    let msg = Uint8Array::from(message);
    let pk = Uint8Array::from(public);

    if js_verify_ed25519(sig, msg, pk) {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        })
    }
}
