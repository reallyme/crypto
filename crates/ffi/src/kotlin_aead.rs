// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JNI bridge for Kotlin AEADs that intentionally use Rust providers.
//!
//! Kotlin keeps AES-GCM on JCE/JCA. GCM-SIV and XChaCha are not portable JCE
//! contracts, so this bridge delegates them to the same audited Rust C ABI used
//! by other platform lanes.

use crate::aes256_gcm_siv::{
    rm_crypto_aes256_gcm_siv_decrypt, rm_crypto_aes256_gcm_siv_encrypt, AES256_GCM_SIV_KEY_LEN,
    AES256_GCM_SIV_NONCE_LEN, AES256_GCM_SIV_TAG_LEN,
};
use crate::chacha20_poly1305::{
    rm_crypto_chacha20_poly1305_decrypt, rm_crypto_chacha20_poly1305_encrypt,
    rm_crypto_xchacha20_poly1305_decrypt, rm_crypto_xchacha20_poly1305_encrypt,
    CHACHA20_POLY1305_KEY_LEN, CHACHA20_POLY1305_NONCE_LEN, CHACHA20_POLY1305_TAG_LEN,
    XCHACHA20_POLY1305_NONCE_LEN,
};
use crate::kotlin_result::{
    backend_internal_result, error_result, ok_result, status_from_crypto_status,
    KOTLIN_NATIVE_BACKEND_INTERNAL, KOTLIN_NATIVE_INVALID_INPUT,
};
use crate::status::CRYPTO_OK;
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::{EnvUnowned, Outcome};
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

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

const MAX_JNI_BYTE_INPUT_LENGTH: usize = 1_048_576;

/// Seals with AES-256-GCM-SIV for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustAead_aes256GcmSivSealNative<'local>(
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
        AES256_GCM_SIV_KEY_LEN,
        AES256_GCM_SIV_NONCE_LEN,
        AES256_GCM_SIV_TAG_LEN,
        key,
        nonce,
        aad,
        plaintext,
    )
}

/// Opens with AES-256-GCM-SIV for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustAead_aes256GcmSivOpenNative<'local>(
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
        AES256_GCM_SIV_KEY_LEN,
        AES256_GCM_SIV_NONCE_LEN,
        AES256_GCM_SIV_TAG_LEN,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

/// Seals with RFC 8439 ChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustAead_chacha20Poly1305SealNative<'local>(
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
        CHACHA20_POLY1305_KEY_LEN,
        CHACHA20_POLY1305_NONCE_LEN,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        plaintext,
    )
}

/// Opens with RFC 8439 ChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustAead_chacha20Poly1305OpenNative<'local>(
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
        CHACHA20_POLY1305_KEY_LEN,
        CHACHA20_POLY1305_NONCE_LEN,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        ciphertext,
    )
}

/// Seals with XChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustAead_xchacha20Poly1305SealNative<
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
        CHACHA20_POLY1305_KEY_LEN,
        XCHACHA20_POLY1305_NONCE_LEN,
        CHACHA20_POLY1305_TAG_LEN,
        key,
        nonce,
        aad,
        plaintext,
    )
}

/// Opens with XChaCha20-Poly1305 for the Kotlin `ReallyMeRustAead` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustAead_xchacha20Poly1305OpenNative<
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
        CHACHA20_POLY1305_KEY_LEN,
        XCHACHA20_POLY1305_NONCE_LEN,
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
    expected_key_len: usize,
    expected_nonce_len: usize,
    tag_len: usize,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let key_len = match key.len(env) {
            Ok(value) if value == expected_key_len => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let nonce_len = match nonce.len(env) {
            Ok(value) if value == expected_nonce_len => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let aad_len = match aad.len(env) {
            Ok(value) if value <= MAX_JNI_BYTE_INPUT_LENGTH => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let plaintext_len = match plaintext.len(env) {
            Ok(value) if value <= MAX_JNI_BYTE_INPUT_LENGTH => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let output_len = match plaintext_len.checked_add(tag_len) {
            Some(value) => value,
            None => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let key_bytes = match env.convert_byte_array(&key) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let nonce_bytes = match env.convert_byte_array(&nonce) {
            Ok(value) => value,
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let aad_bytes = match env.convert_byte_array(&aad) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let plaintext_bytes = match env.convert_byte_array(&plaintext) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        if key_bytes.len() != key_len
            || nonce_bytes.len() != nonce_len
            || aad_bytes.len() != aad_len
            || plaintext_bytes.len() != plaintext_len
        {
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }
        // The output buffer can hold ciphertext or authenticated plaintext.
        // Drop-time cleanup covers JNI errors and unwind paths in addition to
        // the explicit wipe after the Java byte array has been constructed.
        let mut output = Zeroizing::new(vec![0_u8; output_len]);
        let mut produced_len = 0_usize;
        // SAFETY: Every pointer is borrowed from a live Rust allocation for
        // the duration of the call. The output and produced-length storage are
        // uniquely owned here and cannot alias any input allocation.
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
        if status != CRYPTO_OK {
            output.zeroize();
            return error_result(env, status_from_crypto_status(status));
        }
        if produced_len != output.len() {
            output.zeroize();
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }

        let result = ok_result(env, &output[..produced_len]);
        output.zeroize();
        result
    });

    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(_) | Outcome::Panic(_) => {
            let outcome = env.with_env(backend_internal_result);
            match outcome.into_outcome() {
                Outcome::Ok(value) => value,
                Outcome::Err(_) | Outcome::Panic(_) => ptr::null_mut(),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn open_native<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    decrypt: DecryptFunction,
    expected_key_len: usize,
    expected_nonce_len: usize,
    tag_len: usize,
    key: JByteArray<'local>,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let key_len = match key.len(env) {
            Ok(value) if value == expected_key_len => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let nonce_len = match nonce.len(env) {
            Ok(value) if value == expected_nonce_len => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let aad_len = match aad.len(env) {
            Ok(value) if value <= MAX_JNI_BYTE_INPUT_LENGTH => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let maximum_ciphertext_len = match MAX_JNI_BYTE_INPUT_LENGTH.checked_add(tag_len) {
            Some(value) => value,
            None => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let ciphertext_len = match ciphertext.len(env) {
            Ok(value) if (tag_len..=maximum_ciphertext_len).contains(&value) => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let output_len = match ciphertext_len.checked_sub(tag_len) {
            Some(value) => value,
            None => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let key_bytes = match env.convert_byte_array(&key) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let nonce_bytes = match env.convert_byte_array(&nonce) {
            Ok(value) => value,
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let aad_bytes = match env.convert_byte_array(&aad) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let ciphertext_bytes = match env.convert_byte_array(&ciphertext) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        if key_bytes.len() != key_len
            || nonce_bytes.len() != nonce_len
            || aad_bytes.len() != aad_len
            || ciphertext_bytes.len() != ciphertext_len
        {
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }
        // Authenticated plaintext must be protected before native code writes
        // into the allocation so every subsequent exit path wipes it.
        let mut output = Zeroizing::new(vec![0_u8; output_len]);
        let mut produced_len = 0_usize;
        // SAFETY: Every pointer is borrowed from a live Rust allocation for
        // the duration of the call. The plaintext output and produced-length
        // storage are uniquely owned here and disjoint from all inputs.
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
        if status != CRYPTO_OK {
            output.zeroize();
            return error_result(env, status_from_crypto_status(status));
        }
        if produced_len != output.len() {
            output.zeroize();
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }

        let result = ok_result(env, &output[..produced_len]);
        output.zeroize();
        result
    });

    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(_) | Outcome::Panic(_) => {
            let outcome = env.with_env(backend_internal_result);
            match outcome.into_outcome() {
                Outcome::Ok(value) => value,
                Outcome::Err(_) | Outcome::Panic(_) => ptr::null_mut(),
            }
        }
    }
}
