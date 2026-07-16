// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = generateP256Keypair)]
    fn js_generate_p256_keypair() -> JsValue;
}

fn keygen_failed() -> CryptoError {
    CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Wasm,
        operation: crypto_core::SignatureOperation::KeyManagement,
        kind: crypto_core::SignatureFailureKind::KeyGenerationFailed,
    }
}

/// Generate a P-256 keypair.
///
/// Returns `(public_key_compressed[33], secret_key[32])`. Typed
/// `CryptoError` (never a JS string) is returned on failure, matching the
/// native lane and keeping secrets/inputs out of error payloads.
pub fn generate_p256_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let v = js_generate_p256_keypair();
    let obj = Object::from(v);

    let public =
        Reflect::get(&obj, &JsValue::from_str("publicKey")).map_err(|_| keygen_failed())?;
    let secret =
        Reflect::get(&obj, &JsValue::from_str("secretKey")).map_err(|_| keygen_failed())?;

    let public = Uint8Array::new(&public).to_vec();
    let secret = Zeroizing::new(Uint8Array::new(&secret).to_vec());

    if public.len() != 33 || secret.len() != 32 {
        return Err(keygen_failed());
    }

    Ok((public, secret))
}
