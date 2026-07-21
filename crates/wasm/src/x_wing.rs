// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "test-vectors")]
use crypto_x_wing::X_WING_ENCAPS_SEED_LEN;
use crypto_x_wing::{
    generate_x_wing_768_keypair, generate_x_wing_768_keypair_derand, X_WING_768_CIPHERTEXT_LEN,
    X_WING_768_PUBLIC_KEY_LEN, X_WING_SECRET_KEY_LEN,
};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{invalid_input, map_crypto_error};
use crate::validate_bytes::copy_exact;

type KeypairFn = fn() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), crypto_core::CryptoError>;
type DeriveKeypairFn = fn(&[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), crypto_core::CryptoError>;
type EncapsulateFn = fn(&[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), crypto_core::CryptoError>;
#[cfg(feature = "test-vectors")]
type EncapsulateDerandFn =
    fn(&[u8], &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), crypto_core::CryptoError>;
type DecapsulateFn = fn(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, crypto_core::CryptoError>;

fn set_bytes(object: &Object, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(name), &Uint8Array::from(bytes))
        .map_err(|_| invalid_input())?;
    Ok(())
}

fn keypair_to_js(
    public_key: Vec<u8>,
    mut secret_key: Zeroizing<Vec<u8>>,
) -> Result<JsValue, JsValue> {
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
    let object = Object::new();
    set_bytes(&object, "ciphertext", &ciphertext)?;
    set_bytes(&object, "sharedSecret", &shared_secret)?;
    shared_secret.zeroize();
    Ok(object.into())
}

fn generate_keypair(generate: KeypairFn) -> Result<JsValue, JsValue> {
    let (public_key, secret_key) = generate().map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key)
}

fn derive_keypair(secret_key: &Uint8Array, derive: DeriveKeypairFn) -> Result<JsValue, JsValue> {
    let mut secret_key = Zeroizing::new(copy_exact(secret_key, X_WING_SECRET_KEY_LEN)?);
    let (public_key, derived_secret_key) = derive(&secret_key).map_err(map_crypto_error)?;
    secret_key.zeroize();
    keypair_to_js(public_key, derived_secret_key)
}

fn encapsulate(
    public_key: &Uint8Array,
    expected_public_key_len: usize,
    encapsulate: EncapsulateFn,
) -> Result<JsValue, JsValue> {
    let public_key = copy_exact(public_key, expected_public_key_len)?;
    let (ciphertext, shared_secret) = encapsulate(&public_key).map_err(map_crypto_error)?;
    encapsulation_to_js(ciphertext, shared_secret)
}

#[cfg(feature = "test-vectors")]
fn encapsulate_derand(
    public_key: &Uint8Array,
    seed: &Uint8Array,
    expected_public_key_len: usize,
    encapsulate: EncapsulateDerandFn,
) -> Result<JsValue, JsValue> {
    let public_key = copy_exact(public_key, expected_public_key_len)?;
    let mut seed = Zeroizing::new(copy_exact(seed, X_WING_ENCAPS_SEED_LEN)?);
    let (ciphertext, shared_secret) = encapsulate(&public_key, &seed).map_err(map_crypto_error)?;
    seed.zeroize();
    encapsulation_to_js(ciphertext, shared_secret)
}

fn decapsulate(
    ciphertext: &Uint8Array,
    secret_key: &Uint8Array,
    expected_ciphertext_len: usize,
    decapsulate: DecapsulateFn,
) -> Result<Uint8Array, JsValue> {
    let ciphertext = copy_exact(ciphertext, expected_ciphertext_len)?;
    let mut secret_key = Zeroizing::new(copy_exact(secret_key, X_WING_SECRET_KEY_LEN)?);
    let mut shared_secret = decapsulate(&ciphertext, &secret_key).map_err(map_crypto_error)?;
    secret_key.zeroize();
    let output = Uint8Array::from(&shared_secret[..]);
    shared_secret.zeroize();
    Ok(output)
}

#[wasm_bindgen(js_name = xWing768GenerateKeypair)]
/// Generate a random X-Wing-768 keypair for the TypeScript WASM provider.
pub fn x_wing_768_generate_keypair() -> Result<JsValue, JsValue> {
    generate_keypair(generate_x_wing_768_keypair)
}

#[wasm_bindgen(js_name = xWing768DeriveKeypair)]
/// Derive an X-Wing-768 public key from a 32-byte secret seed.
pub fn x_wing_768_derive_keypair(secret_key: &Uint8Array) -> Result<JsValue, JsValue> {
    derive_keypair(secret_key, generate_x_wing_768_keypair_derand)
}

#[wasm_bindgen(js_name = xWing768Encapsulate)]
/// Randomly encapsulate to an X-Wing-768 public key.
pub fn x_wing_768_encapsulate(public_key: &Uint8Array) -> Result<JsValue, JsValue> {
    encapsulate(
        public_key,
        X_WING_768_PUBLIC_KEY_LEN,
        crypto_x_wing::x_wing_768_encapsulate,
    )
}

#[wasm_bindgen(js_name = xWing768EncapsulateDerand)]
/// Deterministically encapsulate to an X-Wing-768 public key for conformance tests.
#[cfg(feature = "test-vectors")]
pub fn x_wing_768_encapsulate_derand(
    public_key: &Uint8Array,
    seed: &Uint8Array,
) -> Result<JsValue, JsValue> {
    encapsulate_derand(
        public_key,
        seed,
        X_WING_768_PUBLIC_KEY_LEN,
        crypto_x_wing::x_wing_768_encapsulate_derand,
    )
}

#[wasm_bindgen(js_name = xWing768Decapsulate)]
/// Decapsulate an X-Wing-768 ciphertext with a 32-byte secret seed.
pub fn x_wing_768_decapsulate(
    ciphertext: &Uint8Array,
    secret_key: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    decapsulate(
        ciphertext,
        secret_key,
        X_WING_768_CIPHERTEXT_LEN,
        crypto_x_wing::x_wing_768_decapsulate,
    )
}
