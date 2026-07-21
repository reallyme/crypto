// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_kmac::{
    derive_kmac256, Kmac256Key, KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH,
    KMAC256_MAX_KEY_LENGTH, KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

use crate::map_error::map_crypto_error;

#[wasm_bindgen(js_name = kmac256Derive)]
/// Derive key material with KMAC256.
pub fn kmac_256_derive(
    key: &Uint8Array,
    context: &Uint8Array,
    customization: &Uint8Array,
    output_length: usize,
) -> Result<Uint8Array, JsValue> {
    if output_length == 0 || output_length > KMAC256_MAX_OUTPUT_LENGTH {
        return Err(kmac_error(crypto_core::KdfFailureKind::InvalidOutputLength));
    }
    let min_key_length = u32::try_from(KMAC256_MIN_KEY_LENGTH)
        .map_err(|_| kmac_error(crypto_core::KdfFailureKind::InvalidParams))?;
    let max_key_length = u32::try_from(KMAC256_MAX_KEY_LENGTH)
        .map_err(|_| kmac_error(crypto_core::KdfFailureKind::InvalidParams))?;
    let max_context_length = u32::try_from(KMAC256_MAX_CONTEXT_LENGTH)
        .map_err(|_| kmac_error(crypto_core::KdfFailureKind::InvalidParams))?;
    let max_customization_length = u32::try_from(KMAC256_MAX_CUSTOMIZATION_LENGTH)
        .map_err(|_| kmac_error(crypto_core::KdfFailureKind::InvalidParams))?;
    if key.length() < min_key_length
        || key.length() > max_key_length
        || context.length() > max_context_length
        || customization.length() > max_customization_length
    {
        return Err(kmac_error(crypto_core::KdfFailureKind::InvalidParams));
    }

    let key_bytes = Zeroizing::new(key.to_vec());
    let context_bytes = Zeroizing::new(context.to_vec());
    let customization_bytes = Zeroizing::new(customization.to_vec());
    let key = Kmac256Key::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let derived = derive_kmac256(&key, &context_bytes, &customization_bytes, output_length)
        .map_err(map_crypto_error)?;
    // Copy once into caller-owned JavaScript memory. The Rust source remains
    // under Kmac256Output's zeroizing owner until this function returns.
    Ok(Uint8Array::from(derived.as_bytes()))
}

fn kmac_error(kind: crypto_core::KdfFailureKind) -> JsValue {
    map_crypto_error(crypto_core::CryptoError::Kdf {
        algorithm: crypto_core::KdfAlgorithm::Kmac256,
        profile: crypto_core::KdfProfile::Sp800185Kmac256,
        kind,
    })
}
