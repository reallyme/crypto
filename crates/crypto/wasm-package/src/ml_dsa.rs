// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{invalid_input, map_crypto_error, provider_failure};

const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1_312;
const ML_DSA_44_SIGNATURE_LEN: usize = 2_420;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;
const ML_DSA_65_SIGNATURE_LEN: usize = 3_309;
const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2_592;
const ML_DSA_87_SIGNATURE_LEN: usize = 4_627;
const ML_DSA_SECRET_KEY_LEN: usize = 32;

fn require_len(bytes: &Uint8Array, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    let bytes = bytes.to_vec();
    if bytes.len() == expected_len {
        Ok(bytes)
    } else {
        Err(invalid_input())
    }
}

fn set_bytes(object: &Object, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(name), &Uint8Array::from(bytes))
        .map_err(|_| provider_failure())?;
    Ok(())
}

fn keypair_to_js(
    public_key: Vec<u8>,
    mut secret_key: Zeroizing<Vec<u8>>,
    public_key_len: usize,
) -> Result<JsValue, JsValue> {
    if public_key.len() != public_key_len || secret_key.len() != ML_DSA_SECRET_KEY_LEN {
        return Err(provider_failure());
    }
    let object = Object::new();
    set_bytes(&object, "publicKey", &public_key)?;
    set_bytes(&object, "secretKey", &secret_key)?;
    secret_key.zeroize();
    Ok(object.into())
}

fn signature_to_js(signature: Vec<u8>, signature_len: usize) -> Result<Uint8Array, JsValue> {
    if signature.len() != signature_len {
        return Err(provider_failure());
    }
    Ok(Uint8Array::from(signature.as_slice()))
}

#[wasm_bindgen(js_name = mlDsa44GenerateKeypair)]
/// Generate an ML-DSA-44 keypair.
pub fn ml_dsa_44_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_ml_dsa_44::generate_ml_dsa_44_keypair().map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key, ML_DSA_44_PUBLIC_KEY_LEN)
}

#[wasm_bindgen(js_name = mlDsa44DeriveKeypair)]
/// Derive an ML-DSA-44 keypair from a 32-byte seed.
pub fn ml_dsa_44_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?);
    let secret_key = <&[u8; ML_DSA_SECRET_KEY_LEN]>::try_from(secret_key.as_slice())
        .map_err(|_| invalid_input())?;
    let (public_key, secret_key) =
        crypto_ml_dsa_44::generate_ml_dsa_44_keypair_from_seed(secret_key)
            .map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key, ML_DSA_44_PUBLIC_KEY_LEN)
}

#[wasm_bindgen(js_name = mlDsa44Sign)]
/// Sign a message with ML-DSA-44.
pub fn ml_dsa_44_sign(
    secret_key: &Uint8Array,
    message: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?);
    let message = message.to_vec();
    let signature =
        crypto_ml_dsa_44::sign_ml_dsa_44(&secret_key, &message).map_err(map_crypto_error)?;
    signature_to_js(signature, ML_DSA_44_SIGNATURE_LEN)
}

#[wasm_bindgen(js_name = mlDsa44Verify)]
/// Verify an ML-DSA-44 detached signature.
pub fn ml_dsa_44_verify(
    public_key: &Uint8Array,
    message: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    let public_key = require_len(public_key, ML_DSA_44_PUBLIC_KEY_LEN)?;
    let signature = require_len(signature, ML_DSA_44_SIGNATURE_LEN)?;
    crypto_ml_dsa_44::verify_ml_dsa_44(&public_key, &message.to_vec(), &signature)
        .map_err(map_crypto_error)
}

#[wasm_bindgen(js_name = mlDsa65GenerateKeypair)]
/// Generate an ML-DSA-65 keypair.
pub fn ml_dsa_65_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_ml_dsa_65::generate_ml_dsa_65_keypair().map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key, ML_DSA_65_PUBLIC_KEY_LEN)
}

#[wasm_bindgen(js_name = mlDsa65DeriveKeypair)]
/// Derive an ML-DSA-65 keypair from a 32-byte seed.
pub fn ml_dsa_65_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?);
    let secret_key = <&[u8; ML_DSA_SECRET_KEY_LEN]>::try_from(secret_key.as_slice())
        .map_err(|_| invalid_input())?;
    let (public_key, secret_key) =
        crypto_ml_dsa_65::generate_ml_dsa_65_keypair_from_seed(secret_key)
            .map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key, ML_DSA_65_PUBLIC_KEY_LEN)
}

#[wasm_bindgen(js_name = mlDsa65Sign)]
/// Sign a message with ML-DSA-65.
pub fn ml_dsa_65_sign(
    secret_key: &Uint8Array,
    message: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?);
    let message = message.to_vec();
    let signature =
        crypto_ml_dsa_65::sign_ml_dsa_65(&secret_key, &message).map_err(map_crypto_error)?;
    signature_to_js(signature, ML_DSA_65_SIGNATURE_LEN)
}

#[wasm_bindgen(js_name = mlDsa65Verify)]
/// Verify an ML-DSA-65 detached signature.
pub fn ml_dsa_65_verify(
    public_key: &Uint8Array,
    message: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    let public_key = require_len(public_key, ML_DSA_65_PUBLIC_KEY_LEN)?;
    let signature = require_len(signature, ML_DSA_65_SIGNATURE_LEN)?;
    crypto_ml_dsa_65::verify_ml_dsa_65(&public_key, &message.to_vec(), &signature)
        .map_err(map_crypto_error)
}

#[wasm_bindgen(js_name = mlDsa87GenerateKeypair)]
/// Generate an ML-DSA-87 keypair.
pub fn ml_dsa_87_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_ml_dsa_87::generate_ml_dsa_87_keypair().map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key, ML_DSA_87_PUBLIC_KEY_LEN)
}

#[wasm_bindgen(js_name = mlDsa87DeriveKeypair)]
/// Derive an ML-DSA-87 keypair from a 32-byte seed.
pub fn ml_dsa_87_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?);
    let secret_key = <&[u8; ML_DSA_SECRET_KEY_LEN]>::try_from(secret_key.as_slice())
        .map_err(|_| invalid_input())?;
    let (public_key, secret_key) =
        crypto_ml_dsa_87::generate_ml_dsa_87_keypair_from_seed(secret_key)
            .map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key, ML_DSA_87_PUBLIC_KEY_LEN)
}

#[wasm_bindgen(js_name = mlDsa87Sign)]
/// Sign a message with ML-DSA-87.
pub fn ml_dsa_87_sign(
    secret_key: &Uint8Array,
    message: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?);
    let message = message.to_vec();
    let signature =
        crypto_ml_dsa_87::sign_ml_dsa_87(&secret_key, &message).map_err(map_crypto_error)?;
    signature_to_js(signature, ML_DSA_87_SIGNATURE_LEN)
}

#[wasm_bindgen(js_name = mlDsa87Verify)]
/// Verify an ML-DSA-87 detached signature.
pub fn ml_dsa_87_verify(
    public_key: &Uint8Array,
    message: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    let public_key = require_len(public_key, ML_DSA_87_PUBLIC_KEY_LEN)?;
    let signature = require_len(signature, ML_DSA_87_SIGNATURE_LEN)?;
    crypto_ml_dsa_87::verify_ml_dsa_87(&public_key, &message.to_vec(), &signature)
        .map_err(map_crypto_error)
}
