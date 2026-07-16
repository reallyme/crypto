// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_aes_kw::{
    unwrap_key, wrap_key, Aes256KwKek, AesKwKeyData, AesKwWrappedKey, AES_256_KW_KEK_LENGTH,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::map_crypto_error;
use crate::validate_bytes::copy_exact;

#[wasm_bindgen(js_name = aes256KwWrapKey)]
/// Wrap key material with AES-256-KW and return the RFC 3394 wrapped key.
pub fn aes_256_kw_wrap_key(kek: &Uint8Array, key_data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    let kek_bytes = Zeroizing::new(copy_exact(kek, AES_256_KW_KEK_LENGTH)?);
    let key_data_bytes = Zeroizing::new(key_data.to_vec());
    let kek = Aes256KwKek::from_slice(&kek_bytes).map_err(map_crypto_error)?;
    let key_data = AesKwKeyData::from_slice(&key_data_bytes).map_err(map_crypto_error)?;
    let mut wrapped_key = wrap_key(&kek, key_data.as_bytes())
        .map_err(map_crypto_error)?
        .into_vec();
    let output = Uint8Array::from(wrapped_key.as_slice());
    wrapped_key.zeroize();
    Ok(output)
}

#[wasm_bindgen(js_name = aes256KwUnwrapKey)]
/// Unwrap an RFC 3394 AES-256-KW wrapped key.
pub fn aes_256_kw_unwrap_key(
    kek: &Uint8Array,
    wrapped_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let kek_bytes = Zeroizing::new(copy_exact(kek, AES_256_KW_KEK_LENGTH)?);
    let wrapped_key =
        AesKwWrappedKey::from_slice(&wrapped_key.to_vec()).map_err(map_crypto_error)?;
    let kek = Aes256KwKek::from_slice(&kek_bytes).map_err(map_crypto_error)?;
    let mut key_data = unwrap_key(&kek, wrapped_key.as_bytes())
        .map_err(map_crypto_error)?
        .into_vec();
    let output = Uint8Array::from(key_data.as_slice());
    key_data.zeroize();
    Ok(output)
}
