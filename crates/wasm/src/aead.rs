// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::AeadAlgorithm;
use crypto_runtime::aes::{
    encrypt as aes_256_gcm_encrypt, encrypt_aes128_gcm, encrypt_aes192_gcm,
    Aes128GcmEncryptRequest, Aes128GcmKey, Aes128GcmNonce, Aes192GcmEncryptRequest, Aes192GcmKey,
    Aes192GcmNonce, Aes256GcmKey, Aes256GcmNonce, EncryptRequest as Aes256GcmEncryptRequest,
    AES_128_GCM_KEY_LENGTH, AES_128_GCM_NONCE_LENGTH, AES_192_GCM_KEY_LENGTH,
    AES_192_GCM_NONCE_LENGTH, AES_256_GCM_KEY_LENGTH, AES_256_GCM_NONCE_LENGTH,
};
use crypto_runtime::aes_gcm_siv::{
    encrypt as aes_256_gcm_siv_encrypt, Aes256GcmSivKey, Aes256GcmSivNonce,
    EncryptRequest as Aes256GcmSivEncryptRequest, AES_256_GCM_SIV_KEY_LENGTH,
    AES_256_GCM_SIV_NONCE_LENGTH,
};
use crypto_runtime::chacha20_poly1305::{
    encrypt as chacha20_poly1305_encrypt, encrypt_xchacha20_poly1305, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, EncryptRequest as ChaCha20Poly1305EncryptRequest,
    XChaCha20Poly1305EncryptRequest, XChaCha20Poly1305Nonce, CHACHA20_POLY1305_KEY_LENGTH,
    CHACHA20_POLY1305_NONCE_LENGTH, XCHACHA20_POLY1305_NONCE_LENGTH,
};
use crypto_runtime::operations::aead::open;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

use crate::map_error::map_crypto_error;
use crate::publish_plaintext::publish_plaintext;
use crate::validate_bytes::{
    copy_bounded, copy_exact, MAX_WASM_CIPHERTEXT_LENGTH, MAX_WASM_INPUT_LENGTH,
};

fn seal_aes_256_gcm(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_bytes = Zeroizing::new(copy_exact(key, AES_256_GCM_KEY_LENGTH)?);
    let nonce_bytes = copy_exact(nonce, AES_256_GCM_NONCE_LENGTH)?;
    let key = Aes256GcmKey::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let nonce = Aes256GcmNonce::from_slice(&nonce_bytes).map_err(map_crypto_error)?;
    let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let aad_bytes = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = aes_256_gcm_encrypt(&Aes256GcmEncryptRequest {
        key: &key,
        nonce,
        aad: &aad_bytes,
        plaintext: &plaintext_bytes,
    })
    .map_err(map_crypto_error)?
    .into_vec();
    Ok(Uint8Array::from(ciphertext.as_slice()))
}

fn seal_aes_128_gcm(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_bytes = Zeroizing::new(copy_exact(key, AES_128_GCM_KEY_LENGTH)?);
    let nonce_bytes = copy_exact(nonce, AES_128_GCM_NONCE_LENGTH)?;
    let key = Aes128GcmKey::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let nonce = Aes128GcmNonce::from_slice(&nonce_bytes).map_err(map_crypto_error)?;
    let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let aad_bytes = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad: &aad_bytes,
        plaintext: &plaintext_bytes,
    })
    .map_err(map_crypto_error)?
    .into_vec();
    Ok(Uint8Array::from(ciphertext.as_slice()))
}

fn seal_aes_192_gcm(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_bytes = Zeroizing::new(copy_exact(key, AES_192_GCM_KEY_LENGTH)?);
    let nonce_bytes = copy_exact(nonce, AES_192_GCM_NONCE_LENGTH)?;
    let key = Aes192GcmKey::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let nonce = Aes192GcmNonce::from_slice(&nonce_bytes).map_err(map_crypto_error)?;
    let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let aad_bytes = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad: &aad_bytes,
        plaintext: &plaintext_bytes,
    })
    .map_err(map_crypto_error)?
    .into_vec();
    Ok(Uint8Array::from(ciphertext.as_slice()))
}

fn seal_aes_256_gcm_siv(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_bytes = Zeroizing::new(copy_exact(key, AES_256_GCM_SIV_KEY_LENGTH)?);
    let nonce_bytes = copy_exact(nonce, AES_256_GCM_SIV_NONCE_LENGTH)?;
    let key = Aes256GcmSivKey::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let nonce = Aes256GcmSivNonce::from_slice(&nonce_bytes).map_err(map_crypto_error)?;
    let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let aad_bytes = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = aes_256_gcm_siv_encrypt(&Aes256GcmSivEncryptRequest {
        key: &key,
        nonce,
        aad: &aad_bytes,
        plaintext: &plaintext_bytes,
    })
    .map_err(map_crypto_error)?
    .into_vec();
    Ok(Uint8Array::from(ciphertext.as_slice()))
}

fn seal_chacha20_poly1305(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_bytes = Zeroizing::new(copy_exact(key, CHACHA20_POLY1305_KEY_LENGTH)?);
    let nonce_bytes = copy_exact(nonce, CHACHA20_POLY1305_NONCE_LENGTH)?;
    let key = ChaCha20Poly1305Key::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(&nonce_bytes).map_err(map_crypto_error)?;
    let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let aad_bytes = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = chacha20_poly1305_encrypt(&ChaCha20Poly1305EncryptRequest {
        key: &key,
        nonce,
        aad: &aad_bytes,
        plaintext: &plaintext_bytes,
    })
    .map_err(map_crypto_error)?
    .into_vec();
    Ok(Uint8Array::from(ciphertext.as_slice()))
}

fn seal_xchacha20_poly1305(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_bytes = Zeroizing::new(copy_exact(key, CHACHA20_POLY1305_KEY_LENGTH)?);
    let nonce_bytes = copy_exact(nonce, XCHACHA20_POLY1305_NONCE_LENGTH)?;
    let key = ChaCha20Poly1305Key::from_slice(&key_bytes).map_err(map_crypto_error)?;
    let nonce = XChaCha20Poly1305Nonce::from_slice(&nonce_bytes).map_err(map_crypto_error)?;
    let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);
    let aad_bytes = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = encrypt_xchacha20_poly1305(&XChaCha20Poly1305EncryptRequest {
        key: &key,
        nonce,
        aad: &aad_bytes,
        plaintext: &plaintext_bytes,
    })
    .map_err(map_crypto_error)?
    .into_vec();
    Ok(Uint8Array::from(ciphertext.as_slice()))
}

fn open_aead(
    algorithm: AeadAlgorithm,
    key_length: usize,
    nonce_length: usize,
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key = Zeroizing::new(copy_exact(key, key_length)?);
    let nonce = copy_exact(nonce, nonce_length)?;
    let aad = Zeroizing::new(copy_bounded(aad, MAX_WASM_INPUT_LENGTH)?);
    let ciphertext = copy_bounded(ciphertext, MAX_WASM_CIPHERTEXT_LENGTH)?;

    let opened = open(algorithm, &key, &nonce, &aad, &ciphertext);
    publish_plaintext(opened, |plaintext| Uint8Array::from(plaintext)).map_err(map_crypto_error)
}

#[wasm_bindgen(js_name = aes256GcmSeal)]
/// Seal plaintext with AES-256-GCM and return `ciphertext || tag`.
pub fn aes_256_gcm_seal(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    seal_aes_256_gcm(key, nonce, aad, plaintext)
}

#[wasm_bindgen(js_name = aes128GcmSeal)]
/// Seal plaintext with AES-128-GCM and return `ciphertext || tag`.
pub fn aes_128_gcm_seal(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    seal_aes_128_gcm(key, nonce, aad, plaintext)
}

#[wasm_bindgen(js_name = aes192GcmSeal)]
/// Seal plaintext with AES-192-GCM and return `ciphertext || tag`.
pub fn aes_192_gcm_seal(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    seal_aes_192_gcm(key, nonce, aad, plaintext)
}

#[wasm_bindgen(js_name = aes256GcmOpen)]
/// Open and authenticate an AES-256-GCM `ciphertext || tag`.
pub fn aes_256_gcm_open(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    open_aead(
        AeadAlgorithm::Aes256Gcm,
        AES_256_GCM_KEY_LENGTH,
        AES_256_GCM_NONCE_LENGTH,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

#[wasm_bindgen(js_name = aes128GcmOpen)]
/// Open and authenticate an AES-128-GCM `ciphertext || tag`.
pub fn aes_128_gcm_open(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    open_aead(
        AeadAlgorithm::Aes128Gcm,
        AES_128_GCM_KEY_LENGTH,
        AES_128_GCM_NONCE_LENGTH,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

#[wasm_bindgen(js_name = aes192GcmOpen)]
/// Open and authenticate an AES-192-GCM `ciphertext || tag`.
pub fn aes_192_gcm_open(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    open_aead(
        AeadAlgorithm::Aes192Gcm,
        AES_192_GCM_KEY_LENGTH,
        AES_192_GCM_NONCE_LENGTH,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

#[wasm_bindgen(js_name = aes256GcmSivSeal)]
/// Seal plaintext with AES-256-GCM-SIV and return `ciphertext || tag`.
pub fn aes_256_gcm_siv_seal(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    seal_aes_256_gcm_siv(key, nonce, aad, plaintext)
}

#[wasm_bindgen(js_name = aes256GcmSivOpen)]
/// Open and authenticate an AES-256-GCM-SIV `ciphertext || tag`.
pub fn aes_256_gcm_siv_open(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    open_aead(
        AeadAlgorithm::Aes256GcmSiv,
        AES_256_GCM_SIV_KEY_LENGTH,
        AES_256_GCM_SIV_NONCE_LENGTH,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

#[wasm_bindgen(js_name = chacha20Poly1305Seal)]
/// Seal plaintext with ChaCha20-Poly1305 and return `ciphertext || tag`.
pub fn chacha20_poly1305_seal(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    seal_chacha20_poly1305(key, nonce, aad, plaintext)
}

#[wasm_bindgen(js_name = chacha20Poly1305Open)]
/// Open and authenticate a ChaCha20-Poly1305 `ciphertext || tag`.
pub fn chacha20_poly1305_open(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    open_aead(
        AeadAlgorithm::ChaCha20Poly1305,
        CHACHA20_POLY1305_KEY_LENGTH,
        CHACHA20_POLY1305_NONCE_LENGTH,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

#[wasm_bindgen(js_name = xchacha20Poly1305Seal)]
/// Seal plaintext with XChaCha20-Poly1305 and return `ciphertext || tag`.
pub fn xchacha20_poly1305_seal(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    seal_xchacha20_poly1305(key, nonce, aad, plaintext)
}

#[wasm_bindgen(js_name = xchacha20Poly1305Open)]
/// Open and authenticate an XChaCha20-Poly1305 `ciphertext || tag`.
pub fn xchacha20_poly1305_open(
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    open_aead(
        AeadAlgorithm::XChaCha20Poly1305,
        CHACHA20_POLY1305_KEY_LENGTH,
        XCHACHA20_POLY1305_NONCE_LENGTH,
        key,
        nonce,
        aad,
        ciphertext,
    )
}
