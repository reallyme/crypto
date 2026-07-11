// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = generateMlKem768Keypair)]
    fn js_generate_mlkem768_keypair() -> JsValue;
}

/// Generate an ML-KEM-768 keypair.
///
/// Returns:
/// (public_key[1184], secret_key[64])
pub fn generate_ml_kem_768_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), JsValue> {
    let v = js_generate_mlkem768_keypair();
    let obj = Object::from(v);

    let public = Reflect::get(&obj, &JsValue::from_str("publicKey"))?;
    let secret = Reflect::get(&obj, &JsValue::from_str("secretKey"))?;

    let public = Uint8Array::new(&public).to_vec();
    let secret = Zeroizing::new(Uint8Array::new(&secret).to_vec());

    if public.len() != 1184 || secret.len() != 64 {
        return Err(JsValue::from_str("invalid ML-KEM-768 key length"));
    }

    Ok((public, secret))
}
