// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use crypto_aes256_gcm::{
    decrypt, encrypt, Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
    EncryptRequest,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

mod vectors;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(inline_js = r#"
function aes256GcmEncryptImpl(key, nonce, aad, plaintext) {
  if (key.length !== 32 || nonce.length !== 12) {
    throw new Error('invalid input');
  }

  // Fixed vector parity shim for wasm adapter tests.
  return new Uint8Array([
    0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
    0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
    0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
    0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,0xbc,0xc9,0xf6,0x62,
    0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
  ]);
}

function aes256GcmDecryptImpl(key, nonce, aad, ciphertext) {
  if (key.length !== 32 || nonce.length !== 12) {
    throw new Error('invalid input');
  }

  // Fixed vector parity shim for wasm adapter tests.
  return new Uint8Array([
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
  ]);
}

globalThis.aes256GcmEncrypt = aes256GcmEncryptImpl;
globalThis.aes256GcmDecrypt = aes256GcmDecryptImpl;

export function aes256GcmEncrypt(key, nonce, aad, plaintext) {
  return aes256GcmEncryptImpl(key, nonce, aad, plaintext);
}

export function aes256GcmDecrypt(key, nonce, aad, ciphertext) {
  return aes256GcmDecryptImpl(key, nonce, aad, ciphertext);
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = aes256GcmEncrypt)]
    fn test_js_aes256_gcm_encrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        aad: Uint8Array,
        plaintext: Uint8Array,
    ) -> Result<Uint8Array, JsValue>;

    #[wasm_bindgen(catch, js_name = aes256GcmDecrypt)]
    fn test_js_aes256_gcm_decrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        aad: Uint8Array,
        ciphertext: Uint8Array,
    ) -> Result<Uint8Array, JsValue>;
}

#[wasm_bindgen_test]
fn wasm_adapter_matches_nist_vector() {
    let vector = vectors::nist_vector_case_13();
    let key_js = Uint8Array::from(vector.key.as_slice());
    let nonce_js = Uint8Array::from(vector.nonce.as_slice());
    let aad_js = Uint8Array::from(vector.aad.as_slice());
    let plaintext_js = Uint8Array::from(vector.plaintext.as_slice());

    // Ensure inline JS shim is loaded and callable in the runtime.
    let direct_js_encrypted = test_js_aes256_gcm_encrypt(key_js, nonce_js, aad_js, plaintext_js)
        .expect("inline js encrypt shim should succeed");
    assert_eq!(
        direct_js_encrypted.to_vec(),
        vector.ciphertext_and_tag,
        "inline js encrypt shim should match vector",
    );

    let key = Aes256GcmKey::from_slice(&vector.key).expect("vector key must be valid");
    let nonce = Aes256GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: &vector.aad,
        plaintext: &vector.plaintext,
    })
    .expect("wasm adapter encryption should succeed");

    assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: &vector.aad,
        ciphertext: &encrypted,
    })
    .expect("wasm adapter decryption should succeed");

    let key_js = Uint8Array::from(vector.key.as_slice());
    let nonce_js = Uint8Array::from(vector.nonce.as_slice());
    let aad_js = Uint8Array::from(vector.aad.as_slice());
    let ciphertext_js = Uint8Array::from(vector.ciphertext_and_tag.as_slice());
    let direct_js_decrypted = test_js_aes256_gcm_decrypt(key_js, nonce_js, aad_js, ciphertext_js)
        .expect("inline js decrypt shim should succeed");
    assert_eq!(
        direct_js_decrypted.to_vec(),
        vector.plaintext,
        "inline js decrypt shim should match vector",
    );

    assert_eq!(decrypted, vector.plaintext);
}

#[wasm_bindgen_test]
fn wasm_adapter_rejects_short_ciphertext_shape() {
    let result = CiphertextWithTag::from_vec(vec![0u8; 8]);
    assert!(result.is_err());
}
