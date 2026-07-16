// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    // function generateSecp256k1Keypair(): { secretKey: Uint8Array, publicKey: Uint8Array }
    #[wasm_bindgen(js_name = generateSecp256k1Keypair)]
    fn js_generate_secp256k1_keypair() -> JsValue;
}

/// Returns (public_key_compressed[33], secret_key[32])
pub fn generate_secp256k1_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let v = js_generate_secp256k1_keypair();
    let obj = Object::from(v);

    let public =
        Reflect::get(&obj, &JsValue::from_str("publicKey")).map_err(|_| CryptoError::InvalidKey)?;
    let secret =
        Reflect::get(&obj, &JsValue::from_str("secretKey")).map_err(|_| CryptoError::InvalidKey)?;

    let public = Uint8Array::new(&public).to_vec();
    let secret = Zeroizing::new(Uint8Array::new(&secret).to_vec());

    if public.len() != 33 || secret.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    Ok((public, secret))
}
