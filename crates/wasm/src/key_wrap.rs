// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::KeyWrapAlgorithm;
use crypto_runtime::aes_kw::{
    AesKwKeyData, AesKwWrappedKey, AES_128_KW_KEK_LENGTH, AES_192_KW_KEK_LENGTH,
    AES_256_KW_KEK_LENGTH, AES_KW_INTEGRITY_CHECK_LENGTH, AES_KW_MAX_KEY_DATA_LENGTH,
};
use crypto_runtime::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

use crate::map_error::{
    authentication_failed, invalid_input, provider_failure, unsupported_algorithm,
};
use crate::validate_bytes::{copy_bounded, copy_exact};

#[wasm_bindgen(js_name = aes128KwWrapKey)]
/// Wrap key material with AES-128-KW.
pub fn aes_128_kw_wrap_key(kek: &Uint8Array, key_data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    wrap(kek, key_data, AES_128_KW_KEK_LENGTH, |kek, key_data| {
        crypto_runtime::operations::key_wrap::wrap_key(KeyWrapAlgorithm::Aes128Kw, kek, key_data)
    })
}

#[wasm_bindgen(js_name = aes192KwWrapKey)]
/// Wrap key material with AES-192-KW.
pub fn aes_192_kw_wrap_key(kek: &Uint8Array, key_data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    wrap(kek, key_data, AES_192_KW_KEK_LENGTH, |kek, key_data| {
        crypto_runtime::operations::key_wrap::wrap_key(KeyWrapAlgorithm::Aes192Kw, kek, key_data)
    })
}

#[wasm_bindgen(js_name = aes256KwWrapKey)]
/// Wrap key material with AES-256-KW.
pub fn aes_256_kw_wrap_key(kek: &Uint8Array, key_data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    wrap(kek, key_data, AES_256_KW_KEK_LENGTH, |kek, key_data| {
        crypto_runtime::operations::key_wrap::wrap_key(KeyWrapAlgorithm::Aes256Kw, kek, key_data)
    })
}

#[wasm_bindgen(js_name = aes128KwUnwrapKey)]
/// Unwrap key material with AES-128-KW.
pub fn aes_128_kw_unwrap_key(
    kek: &Uint8Array,
    wrapped_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    unwrap(kek, wrapped_key, AES_128_KW_KEK_LENGTH, |kek, wrapped| {
        crypto_runtime::operations::key_wrap::unwrap_key(KeyWrapAlgorithm::Aes128Kw, kek, wrapped)
    })
}

#[wasm_bindgen(js_name = aes192KwUnwrapKey)]
/// Unwrap key material with AES-192-KW.
pub fn aes_192_kw_unwrap_key(
    kek: &Uint8Array,
    wrapped_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    unwrap(kek, wrapped_key, AES_192_KW_KEK_LENGTH, |kek, wrapped| {
        crypto_runtime::operations::key_wrap::unwrap_key(KeyWrapAlgorithm::Aes192Kw, kek, wrapped)
    })
}

#[wasm_bindgen(js_name = aes256KwUnwrapKey)]
/// Unwrap key material with AES-256-KW.
pub fn aes_256_kw_unwrap_key(
    kek: &Uint8Array,
    wrapped_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    unwrap(kek, wrapped_key, AES_256_KW_KEK_LENGTH, |kek, wrapped| {
        crypto_runtime::operations::key_wrap::unwrap_key(KeyWrapAlgorithm::Aes256Kw, kek, wrapped)
    })
}

fn wrap(
    kek: &Uint8Array,
    key_data: &Uint8Array,
    kek_length: usize,
    operation: impl FnOnce(&[u8], &[u8]) -> Result<AesKwWrappedKey, OperationError>,
) -> Result<Uint8Array, JsValue> {
    let kek_bytes = Zeroizing::new(copy_exact(kek, kek_length)?);
    let key_data_bytes = Zeroizing::new(copy_bounded(key_data, AES_KW_MAX_KEY_DATA_LENGTH)?);
    let wrapped_key = operation(&kek_bytes, &key_data_bytes).map_err(map_key_wrap_error)?;
    Ok(Uint8Array::from(wrapped_key.as_bytes()))
}

fn unwrap(
    kek: &Uint8Array,
    wrapped_key: &Uint8Array,
    kek_length: usize,
    operation: impl FnOnce(&[u8], &[u8]) -> Result<AesKwKeyData, OperationError>,
) -> Result<Uint8Array, JsValue> {
    let kek_bytes = Zeroizing::new(copy_exact(kek, kek_length)?);
    let maximum_wrapped_length = AES_KW_MAX_KEY_DATA_LENGTH
        .checked_add(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or_else(invalid_input)?;
    let wrapped_key_bytes = Zeroizing::new(copy_bounded(wrapped_key, maximum_wrapped_length)?);
    let key_data = operation(&kek_bytes, &wrapped_key_bytes).map_err(map_key_wrap_error)?;
    Ok(Uint8Array::from(key_data.as_bytes()))
}

fn map_key_wrap_error(error: OperationError) -> JsValue {
    match error {
        OperationError::Primitive {
            reason:
                PrimitiveErrorReason::InvalidKey
                | PrimitiveErrorReason::InvalidLength
                | PrimitiveErrorReason::LengthOverflow,
        } => invalid_input(),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => authentication_failed(),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => unsupported_algorithm(),
        OperationError::Primitive { .. }
        | OperationError::Backend {
            reason: BackendErrorReason::Internal | BackendErrorReason::InvalidOutput,
        } => provider_failure(),
        _ => provider_failure(),
    }
}
