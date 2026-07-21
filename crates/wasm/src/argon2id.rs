// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_argon2id::{
    derive_key_for_version, ARGON2ID_SALT_MAX_LENGTH, ARGON2ID_SALT_MIN_LENGTH,
    ARGON2ID_SECRET_MAX_LENGTH,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

use crate::map_error::{invalid_input, map_crypto_error};
use crate::validate_bytes::{copy_bounded, copy_bounded_nonempty};

#[wasm_bindgen(js_name = argon2idDeriveKey)]
/// Derive the fixed 32-byte Argon2id key for a versioned ReallyMe profile.
pub fn argon2id_derive_key(
    kdf_version: u32,
    secret: &Uint8Array,
    salt: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_bytes = Zeroizing::new(copy_bounded_nonempty(secret, ARGON2ID_SECRET_MAX_LENGTH)?);
    let salt_length = usize::try_from(salt.length()).map_err(|_| invalid_input())?;
    if !(ARGON2ID_SALT_MIN_LENGTH..=ARGON2ID_SALT_MAX_LENGTH).contains(&salt_length) {
        return Err(invalid_input());
    }
    let salt_bytes = Zeroizing::new(copy_bounded(salt, ARGON2ID_SALT_MAX_LENGTH)?);
    let derived_key = derive_key_for_version(kdf_version, &secret_bytes, &salt_bytes)
        .map_err(map_crypto_error)?;
    Ok(Uint8Array::from(derived_key.as_bytes().as_slice()))
}
