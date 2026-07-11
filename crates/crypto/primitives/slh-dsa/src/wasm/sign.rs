// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{SLH_DSA_SHA2_128S_SECRET_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroize;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = signSlhDsaSha2128s)]
    fn js_sign_slh_dsa_sha2_128s(message: Uint8Array, secret_key: Uint8Array) -> Uint8Array;
}

/// Sign a message using SLH-DSA-SHA2-128s through the wasm host provider.
pub fn sign_slh_dsa_sha2_128s(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SLH_DSA_SHA2_128S_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let mut signature =
        js_sign_slh_dsa_sha2_128s(Uint8Array::from(message), Uint8Array::from(secret_key)).to_vec();

    if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_LEN {
        signature.zeroize();
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Sign,
            kind: SignatureFailureKind::InvalidSignature,
        });
    }

    Ok(signature)
}
