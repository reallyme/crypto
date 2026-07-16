// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_hpke::{
    open_base, seal_base, seal_base_derand, HpkeDerandSealRequest, HpkeError, HpkeOpenRequest,
    HpkeSealRequest, HpkeSuite,
};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{invalid_input, provider_failure};

const HPKE_SUITE_P256_SHA256_AES256GCM: u32 = 1;
const HPKE_SUITE_X25519_SHA256_CHACHA20POLY1305: u32 = 2;

fn hpke_suite(suite: u32) -> Result<HpkeSuite, JsValue> {
    match suite {
        HPKE_SUITE_P256_SHA256_AES256GCM => Ok(HpkeSuite::P256Sha256Aes256Gcm),
        HPKE_SUITE_X25519_SHA256_CHACHA20POLY1305 => Ok(HpkeSuite::X25519Sha256ChaCha20Poly1305),
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
    let suite = hpke_suite(suite)?;
    let recipient_public_key = recipient_public_key.to_vec();
    let info = info.to_vec();
    let aad = aad.to_vec();
    let plaintext = Zeroizing::new(plaintext.to_vec());
    let output = seal_base(&HpkeSealRequest {
        suite,
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
pub fn hpke_seal_base_derand(
    suite: u32,
    recipient_public_key: &Uint8Array,
    encapsulation_randomness: &Uint8Array,
    info: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let suite = hpke_suite(suite)?;
    let recipient_public_key = recipient_public_key.to_vec();
    let encapsulation_randomness = Zeroizing::new(encapsulation_randomness.to_vec());
    let info = info.to_vec();
    let aad = aad.to_vec();
    let plaintext = Zeroizing::new(plaintext.to_vec());
    let output = seal_base_derand(&HpkeDerandSealRequest {
        suite,
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
    let suite = hpke_suite(suite)?;
    let recipient_secret_key = Zeroizing::new(recipient_secret_key.to_vec());
    let encapsulated_key = encapsulated_key.to_vec();
    let info = info.to_vec();
    let aad = aad.to_vec();
    let ciphertext = Zeroizing::new(ciphertext.to_vec());
    let mut plaintext = open_base(&HpkeOpenRequest {
        suite,
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
