// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{invalid_input, map_crypto_error, provider_failure};

const ML_KEM_512_PUBLIC_KEY_LEN: usize = 800;
const ML_KEM_512_CIPHERTEXT_LEN: usize = 768;
const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1_184;
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1_088;
const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1_568;
const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1_568;
const ML_KEM_SECRET_KEY_LEN: usize = 64;
const ML_KEM_ENCAPS_RANDOMNESS_LEN: usize = 32;
const ML_KEM_SHARED_SECRET_LEN: usize = 32;

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
) -> Result<JsValue, JsValue> {
    if secret_key.len() != ML_KEM_SECRET_KEY_LEN {
        return Err(provider_failure());
    }
    let object = Object::new();
    set_bytes(&object, "publicKey", &public_key)?;
    set_bytes(&object, "secretKey", &secret_key)?;
    secret_key.zeroize();
    Ok(object.into())
}

fn encapsulation_to_js(
    ciphertext: Vec<u8>,
    mut shared_secret: Zeroizing<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    if shared_secret.len() != ML_KEM_SHARED_SECRET_LEN {
        return Err(provider_failure());
    }
    let object = Object::new();
    set_bytes(&object, "ciphertext", &ciphertext)?;
    set_bytes(&object, "sharedSecret", &shared_secret)?;
    shared_secret.zeroize();
    Ok(object.into())
}

fn decapsulation_to_js(mut shared_secret: Zeroizing<Vec<u8>>) -> Result<Uint8Array, JsValue> {
    if shared_secret.len() != ML_KEM_SHARED_SECRET_LEN {
        return Err(provider_failure());
    }
    let output = Uint8Array::from(shared_secret.as_slice());
    shared_secret.zeroize();
    Ok(output)
}

#[wasm_bindgen(js_name = mlKem512GenerateKeypair)]
/// Generate an ML-KEM-512 keypair.
pub fn ml_kem_512_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_ml_kem_512::generate_ml_kem_512_keypair().map_err(map_crypto_error)?;
    if public_key.len() != ML_KEM_512_PUBLIC_KEY_LEN {
        return Err(provider_failure());
    }
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = mlKem512DeriveKeypair)]
/// Derive an ML-KEM-512 keypair from a 64-byte FIPS 203 seed.
pub fn ml_kem_512_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let secret_key = require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?;
    let secret_key = <&[u8; ML_KEM_SECRET_KEY_LEN]>::try_from(secret_key.as_slice())
        .map_err(|_| invalid_input())?;
    let (public_key, secret_key) =
        crypto_ml_kem_512::generate_ml_kem_512_keypair_from_seed(secret_key)
            .map_err(map_crypto_error)?;
    if public_key.len() != ML_KEM_512_PUBLIC_KEY_LEN {
        return Err(provider_failure());
    }
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = mlKem512Encapsulate)]
/// Encapsulate to an ML-KEM-512 public key.
pub fn ml_kem_512_encapsulate(public_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let public_key = require_len(public_key, ML_KEM_512_PUBLIC_KEY_LEN)?;
    let (ciphertext, shared_secret) =
        crypto_ml_kem_512::ml_kem_512_encapsulate(&public_key).map_err(map_crypto_error)?;
    if ciphertext.len() != ML_KEM_512_CIPHERTEXT_LEN {
        return Err(provider_failure());
    }
    encapsulation_to_js(ciphertext, shared_secret)
}

#[wasm_bindgen(js_name = mlKem512EncapsulateDerand)]
/// Deterministically encapsulate to an ML-KEM-512 public key.
pub fn ml_kem_512_encapsulate_derand(
    public_key: &Uint8Array,
    randomness: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let public_key = require_len(public_key, ML_KEM_512_PUBLIC_KEY_LEN)?;
    let randomness = require_len(randomness, ML_KEM_ENCAPS_RANDOMNESS_LEN)?;
    let (ciphertext, shared_secret) =
        crypto_ml_kem_512::ml_kem_512_encapsulate_derand(&public_key, &randomness)
            .map_err(map_crypto_error)?;
    if ciphertext.len() != ML_KEM_512_CIPHERTEXT_LEN {
        return Err(provider_failure());
    }
    encapsulation_to_js(ciphertext, shared_secret)
}

#[wasm_bindgen(js_name = mlKem512Decapsulate)]
/// Decapsulate an ML-KEM-512 ciphertext.
pub fn ml_kem_512_decapsulate(
    ciphertext: &Uint8Array,
    secret_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let ciphertext = require_len(ciphertext, ML_KEM_512_CIPHERTEXT_LEN)?;
    let secret_key = Zeroizing::new(require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?);
    let shared_secret = crypto_ml_kem_512::ml_kem_512_decapsulate(&ciphertext, &secret_key)
        .map_err(map_crypto_error)?;
    decapsulation_to_js(shared_secret)
}

#[wasm_bindgen(js_name = mlKem768GenerateKeypair)]
/// Generate an ML-KEM-768 keypair.
pub fn ml_kem_768_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_ml_kem_768::generate_ml_kem_768_keypair().map_err(map_crypto_error)?;
    if public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
        return Err(provider_failure());
    }
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = mlKem768DeriveKeypair)]
/// Derive an ML-KEM-768 keypair from a 64-byte FIPS 203 seed.
pub fn ml_kem_768_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let secret_key = require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?;
    let secret_key = <&[u8; ML_KEM_SECRET_KEY_LEN]>::try_from(secret_key.as_slice())
        .map_err(|_| invalid_input())?;
    let (public_key, secret_key) =
        crypto_ml_kem_768::generate_ml_kem_768_keypair_from_seed(secret_key)
            .map_err(map_crypto_error)?;
    if public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
        return Err(provider_failure());
    }
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = mlKem768Encapsulate)]
/// Encapsulate to an ML-KEM-768 public key.
pub fn ml_kem_768_encapsulate(public_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let public_key = require_len(public_key, ML_KEM_768_PUBLIC_KEY_LEN)?;
    let (ciphertext, shared_secret) =
        crypto_ml_kem_768::ml_kem_768_encapsulate(&public_key).map_err(map_crypto_error)?;
    if ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return Err(provider_failure());
    }
    encapsulation_to_js(ciphertext, shared_secret)
}

#[wasm_bindgen(js_name = mlKem768EncapsulateDerand)]
/// Deterministically encapsulate to an ML-KEM-768 public key.
pub fn ml_kem_768_encapsulate_derand(
    public_key: &Uint8Array,
    randomness: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let public_key = require_len(public_key, ML_KEM_768_PUBLIC_KEY_LEN)?;
    let randomness = require_len(randomness, ML_KEM_ENCAPS_RANDOMNESS_LEN)?;
    let (ciphertext, shared_secret) =
        crypto_ml_kem_768::ml_kem_768_encapsulate_derand(&public_key, &randomness)
            .map_err(map_crypto_error)?;
    if ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return Err(provider_failure());
    }
    encapsulation_to_js(ciphertext, shared_secret)
}

#[wasm_bindgen(js_name = mlKem768Decapsulate)]
/// Decapsulate an ML-KEM-768 ciphertext.
pub fn ml_kem_768_decapsulate(
    ciphertext: &Uint8Array,
    secret_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let ciphertext = require_len(ciphertext, ML_KEM_768_CIPHERTEXT_LEN)?;
    let secret_key = Zeroizing::new(require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?);
    let shared_secret = crypto_ml_kem_768::ml_kem_768_decapsulate(&ciphertext, &secret_key)
        .map_err(map_crypto_error)?;
    decapsulation_to_js(shared_secret)
}

#[wasm_bindgen(js_name = mlKem1024GenerateKeypair)]
/// Generate an ML-KEM-1024 keypair.
pub fn ml_kem_1024_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_ml_kem_1024::generate_ml_kem_1024_keypair().map_err(map_crypto_error)?;
    if public_key.len() != ML_KEM_1024_PUBLIC_KEY_LEN {
        return Err(provider_failure());
    }
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = mlKem1024DeriveKeypair)]
/// Derive an ML-KEM-1024 keypair from a 64-byte FIPS 203 seed.
pub fn ml_kem_1024_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let secret_key = require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?;
    let secret_key = <&[u8; ML_KEM_SECRET_KEY_LEN]>::try_from(secret_key.as_slice())
        .map_err(|_| invalid_input())?;
    let (public_key, secret_key) =
        crypto_ml_kem_1024::generate_ml_kem_1024_keypair_from_seed(secret_key)
            .map_err(map_crypto_error)?;
    if public_key.len() != ML_KEM_1024_PUBLIC_KEY_LEN {
        return Err(provider_failure());
    }
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = mlKem1024Encapsulate)]
/// Encapsulate to an ML-KEM-1024 public key.
pub fn ml_kem_1024_encapsulate(public_key: &Uint8Array) -> Result<JsValue, JsValue> {
    let public_key = require_len(public_key, ML_KEM_1024_PUBLIC_KEY_LEN)?;
    let (ciphertext, shared_secret) =
        crypto_ml_kem_1024::ml_kem_1024_encapsulate(&public_key).map_err(map_crypto_error)?;
    if ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LEN {
        return Err(provider_failure());
    }
    encapsulation_to_js(ciphertext, shared_secret)
}

#[wasm_bindgen(js_name = mlKem1024EncapsulateDerand)]
/// Deterministically encapsulate to an ML-KEM-1024 public key.
pub fn ml_kem_1024_encapsulate_derand(
    public_key: &Uint8Array,
    randomness: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let public_key = require_len(public_key, ML_KEM_1024_PUBLIC_KEY_LEN)?;
    let randomness = require_len(randomness, ML_KEM_ENCAPS_RANDOMNESS_LEN)?;
    let (ciphertext, shared_secret) =
        crypto_ml_kem_1024::ml_kem_1024_encapsulate_derand(&public_key, &randomness)
            .map_err(map_crypto_error)?;
    if ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LEN {
        return Err(provider_failure());
    }
    encapsulation_to_js(ciphertext, shared_secret)
}

#[wasm_bindgen(js_name = mlKem1024Decapsulate)]
/// Decapsulate an ML-KEM-1024 ciphertext.
pub fn ml_kem_1024_decapsulate(
    ciphertext: &Uint8Array,
    secret_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let ciphertext = require_len(ciphertext, ML_KEM_1024_CIPHERTEXT_LEN)?;
    let secret_key = Zeroizing::new(require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?);
    let shared_secret = crypto_ml_kem_1024::ml_kem_1024_decapsulate(&ciphertext, &secret_key)
        .map_err(map_crypto_error)?;
    decapsulation_to_js(shared_secret)
}
