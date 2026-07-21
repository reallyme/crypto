// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JNI bridge for Kotlin Argon2id.
//!
//! The Kotlin package deliberately uses Rust for Argon2id rather than a JVM or
//! Android provider. This bridge stays tiny and delegates to the same C ABI
//! function Swift uses, so the memory-hard KDF has one implementation contract.

use crate::argon2id::{rm_crypto_argon2id_derive_key, ARGON2ID_DERIVED_KEY_LEN};
use crate::kotlin_result::{
    backend_internal_result, error_result, ok_result, status_from_crypto_status,
    KOTLIN_NATIVE_BACKEND_INTERNAL, KOTLIN_NATIVE_INVALID_INPUT,
};
use crate::status::CRYPTO_OK;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint};
use jni::{EnvUnowned, Outcome};
use reallyme_crypto::argon2id::{
    Argon2KdfVersion, ARGON2ID_SALT_MAX_LENGTH, ARGON2ID_SALT_MIN_LENGTH,
    ARGON2ID_SECRET_MAX_LENGTH,
};
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

/// Verifies that the loaded native image contains the expected JNI symbols.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustNativeProvider_probeNative<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jint {
    1
}

/// Derives an Argon2id key for the Kotlin `ReallyMeArgon2id` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeArgon2id_deriveKeyNative<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    kdf_version: jint,
    secret: JByteArray<'local>,
    salt: JByteArray<'local>,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let kdf_version = match u32::try_from(kdf_version) {
            Ok(value) if Argon2KdfVersion::try_from(value).is_ok() => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let secret_len = match secret.len(env) {
            Ok(value) if (1..=ARGON2ID_SECRET_MAX_LENGTH).contains(&value) => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let salt_len = match salt.len(env) {
            Ok(value) if (ARGON2ID_SALT_MIN_LENGTH..=ARGON2ID_SALT_MAX_LENGTH).contains(&value) => {
                value
            }
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let secret_bytes = match env.convert_byte_array(&secret) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let salt_bytes = match env.convert_byte_array(&salt) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        if secret_bytes.len() != secret_len || salt_bytes.len() != salt_len {
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }
        let mut derived = Zeroizing::new([0_u8; ARGON2ID_DERIVED_KEY_LEN]);
        // SAFETY: The JNI inputs were copied into live Rust-owned allocations.
        // The fixed-size output is uniquely owned, writable, and disjoint from
        // both inputs for the duration of the C ABI call.
        let status = unsafe {
            rm_crypto_argon2id_derive_key(
                kdf_version,
                secret_bytes.as_ptr(),
                secret_bytes.len(),
                salt_bytes.as_ptr(),
                salt_bytes.len(),
                derived.as_mut_ptr(),
                derived.len(),
            )
        };

        if status != CRYPTO_OK {
            derived.zeroize();
            return error_result(env, status_from_crypto_status(status));
        }

        let result = ok_result(env, &derived[..]);
        derived.zeroize();
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
