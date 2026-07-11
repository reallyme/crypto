// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    // JS must provide:
    // function generateEd25519Keypair(): { secretKey: Uint8Array, publicKey: Uint8Array }
    #[wasm_bindgen(js_name = generateEd25519Keypair)]
    fn js_generate_ed25519_keypair() -> JsValue;
}

/// Generates an Ed25519 keypair through the JavaScript provider.
pub fn generate_ed25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let v = js_generate_ed25519_keypair();
    let obj = Object::from(v);

    let secret =
        Reflect::get(&obj, &JsValue::from_str("secretKey")).map_err(|_| CryptoError::InvalidKey)?;
    let public =
        Reflect::get(&obj, &JsValue::from_str("publicKey")).map_err(|_| CryptoError::InvalidKey)?;

    let secret = Zeroizing::new(Uint8Array::new(&secret).to_vec());
    let public = Uint8Array::new(&public).to_vec();

    if secret.len() != 32 || public.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    Ok((public, secret))
}
