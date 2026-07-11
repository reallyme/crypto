// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_argon2id::derive_key_for_version;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::map_crypto_error;

#[wasm_bindgen(js_name = argon2idDeriveKey)]
/// Derive the fixed 32-byte Argon2id key for a versioned ReallyMe profile.
pub fn argon2id_derive_key(
    kdf_version: u32,
    secret: &Uint8Array,
    salt: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_bytes = Zeroizing::new(secret.to_vec());
    let salt_bytes = salt.to_vec();
    let mut derived_key = derive_key_for_version(kdf_version, &secret_bytes, &salt_bytes)
        .map_err(map_crypto_error)?
        .as_bytes()
        .to_vec();
    let output = Uint8Array::from(derived_key.as_slice());
    derived_key.zeroize();
    Ok(output)
}
