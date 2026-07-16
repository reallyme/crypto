// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = verifySlhDsaSha2128s)]
    fn js_verify_slh_dsa_sha2_128s(
        signature: Uint8Array,
        message: Uint8Array,
        public_key: Uint8Array,
    ) -> bool;
}

/// Verify an SLH-DSA-SHA2-128s detached signature through the wasm host provider.
pub fn verify_slh_dsa_sha2_128s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_LEN {
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        });
    }

    if js_verify_slh_dsa_sha2_128s(
        Uint8Array::from(signature),
        Uint8Array::from(message),
        Uint8Array::from(public_key),
    ) {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
