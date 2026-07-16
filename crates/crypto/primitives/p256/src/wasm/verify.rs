// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = verifyP256DerPrehash)]
    fn js_verify_p256_der_prehash(
        signature_der: Uint8Array,
        message: Uint8Array,
        public_key_sec1: Uint8Array,
    ) -> bool;
}

/// Verifies a DER-encoded P-256 ECDSA signature over a pre-hashed message.
pub fn verify_p256_der_prehash(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    if public_key_sec1.len() != 33 && public_key_sec1.len() != 65 {
        return Err(CryptoError::InvalidKey);
    }

    let sig = Uint8Array::from(signature_der);
    let msg = Uint8Array::from(message);
    let pk = Uint8Array::from(public_key_sec1);

    if js_verify_p256_der_prehash(sig, msg, pk) {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Wasm,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        })
    }
}
