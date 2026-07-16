// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = generateMlDsa44Keypair)]
    fn js_generate_ml_dsa_44_keypair() -> JsValue;
}

fn keygen_failed() -> CryptoError {
    CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Wasm,
        operation: crypto_core::SignatureOperation::KeyManagement,
        kind: crypto_core::SignatureFailureKind::KeyGenerationFailed,
    }
}

/// Generate an ML-DSA-44 keypair.
///
/// Returns `(public_key[1312], secret_seed[32])`. Typed `CryptoError`
/// (never a JS string) is returned on failure, matching the native lane.
pub fn generate_ml_dsa_44_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let v = js_generate_ml_dsa_44_keypair();
    let obj = Object::from(v);

    let public =
        Reflect::get(&obj, &JsValue::from_str("publicKey")).map_err(|_| keygen_failed())?;
    let secret =
        Reflect::get(&obj, &JsValue::from_str("secretKey")).map_err(|_| keygen_failed())?;

    let public = Uint8Array::new(&public).to_vec();
    let secret_seed = Zeroizing::new(Uint8Array::new(&secret).to_vec());

    if public.len() != 1312 || secret_seed.len() != 32 {
        return Err(keygen_failed());
    }

    Ok((public, secret_seed))
}
