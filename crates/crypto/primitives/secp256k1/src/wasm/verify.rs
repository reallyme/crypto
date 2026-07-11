// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // function verifySecp256k1(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean
    #[wasm_bindgen(js_name = verifySecp256k1)]
    fn js_verify_secp256k1(
        signature: Uint8Array,
        message: Uint8Array,
        public_key: Uint8Array,
    ) -> bool;
}

/// Verify a compact secp256k1 ECDSA signature with the JavaScript backend.
pub fn verify_secp256k1(
    signature: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != 64 {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }
    if public_key_sec1.len() != 33 {
        return Err(CryptoError::InvalidKey);
    }
    match public_key_sec1[0] {
        0x02 | 0x03 => {}
        _ => return Err(CryptoError::InvalidKey),
    }

    let sig = Uint8Array::from(signature);
    let msg = Uint8Array::from(message);
    let pk = Uint8Array::from(public_key_sec1);

    if js_verify_secp256k1(sig, msg, pk) {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        })
    }
}
