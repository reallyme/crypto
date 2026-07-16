// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = generateX25519Keypair)]
    fn js_generate_x25519_keypair() -> JsValue;
}

fn keygen_failed() -> CryptoError {
    CryptoError::KeyAgreementFailure {
        kind: crypto_core::KeyAgreementFailureKind::KeyGenerationFailed,
    }
}

/// Generate an X25519 keypair.
///
/// Returns `(public_key[32], secret_key[32])`. Typed `CryptoError` (never a
/// JS string) is returned on failure, matching the native lane.
pub fn generate_x25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let v = js_generate_x25519_keypair();
    let obj = Object::from(v);

    let public =
        Reflect::get(&obj, &JsValue::from_str("publicKey")).map_err(|_| keygen_failed())?;
    let secret =
        Reflect::get(&obj, &JsValue::from_str("secretKey")).map_err(|_| keygen_failed())?;

    let public = Uint8Array::new(&public).to_vec();
    let secret = Zeroizing::new(Uint8Array::new(&secret).to_vec());

    if public.len() != 32 || secret.len() != 32 {
        return Err(keygen_failed());
    }

    Ok((public, secret))
}
