// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_hpke::{
    open_base, seal_base, HpkeError, HpkeOpenRequest, HpkeSealRequest, HpkeSuite,
    HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM, HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    HPKE_P256_PRIVATE_KEY_LEN, HPKE_P256_PUBLIC_KEY_LEN, HPKE_X25519_PRIVATE_KEY_LEN,
    HPKE_X25519_PUBLIC_KEY_LEN,
};
#[cfg(feature = "test-vectors")]
use crypto_hpke::{seal_base_derand, HpkeDerandSealRequest};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{invalid_input, provider_failure};
use crate::validate_bytes::{
    copy_bounded, copy_exact, MAX_WASM_CIPHERTEXT_LENGTH, MAX_WASM_INPUT_LENGTH,
};

const HPKE_SUITE_P256_SHA256_AES256GCM: u32 = 1;
const HPKE_SUITE_X25519_SHA256_CHACHA20POLY1305: u32 = 2;
// RFC 9180's labeled key-schedule context is bounded by a two-byte length;
// five fixed label bytes leave this many caller-controlled `info` bytes.
const HPKE_INFO_MAX_LENGTH: usize = 65_530;

#[derive(Clone, Copy)]
struct HpkeSuiteConfig {
    suite: HpkeSuite,
    public_key_length: usize,
    private_key_length: usize,
}

fn hpke_suite(suite: u32) -> Result<HpkeSuiteConfig, JsValue> {
    match suite {
        HPKE_SUITE_P256_SHA256_AES256GCM => Ok(HpkeSuiteConfig {
            suite: HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
            public_key_length: HPKE_P256_PUBLIC_KEY_LEN,
            private_key_length: HPKE_P256_PRIVATE_KEY_LEN,
        }),
        HPKE_SUITE_X25519_SHA256_CHACHA20POLY1305 => Ok(HpkeSuiteConfig {
            suite: HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
            public_key_length: HPKE_X25519_PUBLIC_KEY_LEN,
            private_key_length: HPKE_X25519_PRIVATE_KEY_LEN,
        }),
        _ => Err(invalid_input()),
    }
}

fn map_hpke_error(error: HpkeError) -> JsValue {
    match error {
        HpkeError::InvalidCiphertext
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidPrivateKey
        | HpkeError::InvalidPublicKey
        | HpkeError::InvalidRandomness
        | HpkeError::UnsupportedSuite => invalid_input(),
        HpkeError::LengthOverflow | HpkeError::OpenFailed | HpkeError::SealFailed => {
            provider_failure()
        }
        _ => provider_failure(),
    }
}

fn set_bytes(object: &Object, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(name), &Uint8Array::from(bytes))
        .map_err(|_| invalid_input())?;
    Ok(())
}

fn seal_output_to_js(
    encapsulated_key: Vec<u8>,
    mut ciphertext: Zeroizing<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let object = Object::new();
    set_bytes(&object, "encapsulatedKey", &encapsulated_key)?;
    set_bytes(&object, "ciphertext", &ciphertext)?;
    ciphertext.zeroize();
    Ok(object.into())
}

#[wasm_bindgen(js_name = hpkeSealBase)]
/// Seal one RFC 9180 HPKE Base-mode message.
pub fn hpke_seal_base(
    suite: u32,
    recipient_public_key: &Uint8Array,
    info: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let config = hpke_suite(suite)?;
    let recipient_public_key = copy_exact(recipient_public_key, config.public_key_length)?;
    let info = Zeroizing::new(copy_bounded(info, HPKE_INFO_MAX_LENGTH)?);
    let aad = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let plaintext = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let output = seal_base(&HpkeSealRequest {
        suite: config.suite,
        recipient_public_key: &recipient_public_key,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .map_err(map_hpke_error)?;
    seal_output_to_js(output.encapsulated_key, Zeroizing::new(output.ciphertext))
}

#[wasm_bindgen(js_name = hpkeSealBaseDerand)]
/// Deterministically seal one HPKE Base-mode message for conformance tests.
#[cfg(feature = "test-vectors")]
pub fn hpke_seal_base_derand(
    suite: u32,
    recipient_public_key: &Uint8Array,
    encapsulation_randomness: &Uint8Array,
    info: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let config = hpke_suite(suite)?;
    let recipient_public_key = copy_exact(recipient_public_key, config.public_key_length)?;
    let encapsulation_randomness = Zeroizing::new(copy_exact(
        encapsulation_randomness,
        config.private_key_length,
    )?);
    let info = Zeroizing::new(copy_bounded(info, HPKE_INFO_MAX_LENGTH)?);
    let aad = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let plaintext = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let output = seal_base_derand(&HpkeDerandSealRequest {
        suite: config.suite,
        recipient_public_key: &recipient_public_key,
        encapsulation_randomness: &encapsulation_randomness,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .map_err(map_hpke_error)?;
    seal_output_to_js(output.encapsulated_key, Zeroizing::new(output.ciphertext))
}

#[wasm_bindgen(js_name = hpkeOpenBase)]
/// Open one RFC 9180 HPKE Base-mode message.
pub fn hpke_open_base(
    suite: u32,
    recipient_secret_key: &Uint8Array,
    encapsulated_key: &Uint8Array,
    info: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let config = hpke_suite(suite)?;
    let recipient_secret_key =
        Zeroizing::new(copy_exact(recipient_secret_key, config.private_key_length)?);
    let encapsulated_key = copy_exact(encapsulated_key, config.public_key_length)?;
    let info = Zeroizing::new(copy_bounded(info, HPKE_INFO_MAX_LENGTH)?);
    let aad = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = Zeroizing::new(copy_bounded(ciphertext, MAX_WASM_CIPHERTEXT_LENGTH)?);
    let mut plaintext = open_base(&HpkeOpenRequest {
        suite: config.suite,
        encapsulated_key: &encapsulated_key,
        recipient_private_key: &recipient_secret_key,
        info: &info,
        aad: &aad,
        ciphertext: &ciphertext,
    })
    .map_err(map_hpke_error)?
    .plaintext;
    let output = Uint8Array::from(plaintext.as_slice());
    plaintext.zeroize();
    Ok(output)
}
