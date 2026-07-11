// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JNI bridge for Kotlin AEADs that intentionally use Rust providers.
//!
//! Kotlin keeps AES-GCM on JCE/JCA. GCM-SIV and XChaCha are not portable JCE
//! contracts, so this bridge delegates them to the same audited Rust C ABI used
//! by other platform lanes.

use crate::aes256_gcm_siv::{
    rm_crypto_aes256_gcm_siv_decrypt, rm_crypto_aes256_gcm_siv_encrypt, AES256_GCM_SIV_TAG_LEN,
};
use crate::chacha20_poly1305::{
    rm_crypto_chacha20_poly1305_decrypt, rm_crypto_chacha20_poly1305_encrypt,
    rm_crypto_xchacha20_poly1305_decrypt, rm_crypto_xchacha20_poly1305_encrypt,
    CHACHA20_POLY1305_TAG_LEN,
};
use crate::status::CRYPTO_OK;
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::{EnvUnowned, Outcome};
use std::ptr;
use zeroize::Zeroize;

type EncryptFunction = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> i32;

type DecryptFunction = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> i32;

/// Seals with AES-256-GCM-SIV for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_com_reallyme_crypto_ReallyMeRustAead_aes256GcmSivSealNative<'local>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    seal_native(
        env,
        class,
        rm_crypto_aes256_gcm_siv_encrypt,
        AES256_GCM_SIV_TAG_LEN,
        key,
        nonce,
        aad,
        plaintext,
    )
}

/// Opens with AES-256-GCM-SIV for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_com_reallyme_crypto_ReallyMeRustAead_aes256GcmSivOpenNative<'local>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    open_native(
        env,
        class,
        rm_crypto_aes256_gcm_siv_decrypt,
        AES256_GCM_SIV_TAG_LEN,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

/// Seals with RFC 8439 ChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_com_reallyme_crypto_ReallyMeRustAead_chacha20Poly1305SealNative<
    'local,
>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    seal_native(
        env,
        class,
        rm_crypto_chacha20_poly1305_encrypt,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        plaintext,
    )
}

/// Opens with RFC 8439 ChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_com_reallyme_crypto_ReallyMeRustAead_chacha20Poly1305OpenNative<
    'local,
>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    open_native(
        env,
        class,
        rm_crypto_chacha20_poly1305_decrypt,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

/// Seals with XChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_com_reallyme_crypto_ReallyMeRustAead_xchacha20Poly1305SealNative<
    'local,
>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    seal_native(
        env,
        class,
        rm_crypto_xchacha20_poly1305_encrypt,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        plaintext,
    )
}

/// Opens with XChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_com_reallyme_crypto_ReallyMeRustAead_xchacha20Poly1305OpenNative<
    'local,
>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    open_native(
        env,
        class,
        rm_crypto_xchacha20_poly1305_decrypt,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_native<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    encrypt: EncryptFunction,
    tag_len: usize,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let Some(output_len) = plaintext
            .len(env)
            .ok()
            .and_then(|len| len.checked_add(tag_len))
        else {
            return Ok(ptr::null_mut());
        };
        let mut key_bytes = match env.convert_byte_array(&key) {
            Ok(value) => value,
            Err(_) => return Ok(ptr::null_mut()),
        };
        let nonce_bytes = match env.convert_byte_array(&nonce) {
            Ok(value) => value,
            Err(_) => {
                key_bytes.zeroize();
                return Ok(ptr::null_mut());
            }
        };
        let aad_bytes = match env.convert_byte_array(&aad) {
            Ok(value) => value,
            Err(_) => {
                key_bytes.zeroize();
                return Ok(ptr::null_mut());
            }
        };
        let mut plaintext_bytes = match env.convert_byte_array(&plaintext) {
            Ok(value) => value,
            Err(_) => {
                key_bytes.zeroize();
                return Ok(ptr::null_mut());
            }
        };
        let mut output = vec![0_u8; output_len];
        let mut produced_len = 0_usize;
        let status = unsafe {
            encrypt(
                key_bytes.as_ptr(),
                key_bytes.len(),
                nonce_bytes.as_ptr(),
                nonce_bytes.len(),
                aad_bytes.as_ptr(),
                aad_bytes.len(),
                plaintext_bytes.as_ptr(),
                plaintext_bytes.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut produced_len,
            )
        };
        key_bytes.zeroize();
        plaintext_bytes.zeroize();
        if status != CRYPTO_OK || produced_len > output.len() {
            output.zeroize();
            return Ok(ptr::null_mut());
        }

        let result = match env.byte_array_from_slice(&output[..produced_len]) {
            Ok(value) => value.into_raw(),
            Err(_) => ptr::null_mut(),
        };
        output.zeroize();
        Ok(result)
    });

    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(_) | Outcome::Panic(_) => ptr::null_mut(),
    }
}

#[allow(clippy::too_many_arguments)]
fn open_native<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    decrypt: DecryptFunction,
    tag_len: usize,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let Some(output_len) = ciphertext
            .len(env)
            .ok()
            .and_then(|len| len.checked_sub(tag_len))
        else {
            return Ok(ptr::null_mut());
        };
        let mut key_bytes = match env.convert_byte_array(&key) {
            Ok(value) => value,
            Err(_) => return Ok(ptr::null_mut()),
        };
        let nonce_bytes = match env.convert_byte_array(&nonce) {
            Ok(value) => value,
            Err(_) => {
                key_bytes.zeroize();
                return Ok(ptr::null_mut());
            }
        };
        let aad_bytes = match env.convert_byte_array(&aad) {
            Ok(value) => value,
            Err(_) => {
                key_bytes.zeroize();
                return Ok(ptr::null_mut());
            }
        };
        let mut ciphertext_bytes = match env.convert_byte_array(&ciphertext) {
            Ok(value) => value,
            Err(_) => {
                key_bytes.zeroize();
                return Ok(ptr::null_mut());
            }
        };
        let mut output = vec![0_u8; output_len];
        let mut produced_len = 0_usize;
        let status = unsafe {
            decrypt(
                key_bytes.as_ptr(),
                key_bytes.len(),
                nonce_bytes.as_ptr(),
                nonce_bytes.len(),
                aad_bytes.as_ptr(),
                aad_bytes.len(),
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut produced_len,
            )
        };
        key_bytes.zeroize();
        ciphertext_bytes.zeroize();
        if status != CRYPTO_OK || produced_len > output.len() {
            output.zeroize();
            return Ok(ptr::null_mut());
        }

        let result = match env.byte_array_from_slice(&output[..produced_len]) {
            Ok(value) => value.into_raw(),
            Err(_) => ptr::null_mut(),
        };
        output.zeroize();
        Ok(result)
    });

    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(_) | Outcome::Panic(_) => ptr::null_mut(),
    }
}
