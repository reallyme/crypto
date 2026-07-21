// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JNI bridge for Kotlin KMAC256.

use crate::kmac::rm_crypto_kmac256_derive;
use crate::kotlin_result::{
    backend_internal_result, error_result, ok_result, status_from_crypto_status,
    KOTLIN_NATIVE_BACKEND_INTERNAL, KOTLIN_NATIVE_INVALID_INPUT,
};
use crate::status::CRYPTO_OK;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint};
use jni::{EnvUnowned, Outcome};
use reallyme_crypto::kmac::{
    KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH, KMAC256_MAX_KEY_LENGTH,
    KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};
use std::ptr;
use zeroize::Zeroizing;

/// Derives KMAC256 output for the Kotlin `ReallyMeKmac` provider.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeKmac_deriveKmac256Native<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    context: JByteArray<'local>,
    customization: JByteArray<'local>,
    output_len: jint,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let output_len = match usize::try_from(output_len) {
            Ok(value) if value > 0 && value <= KMAC256_MAX_OUTPUT_LENGTH => value,
            _ => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let key_len = match key.len(env) {
            Ok(value) if (KMAC256_MIN_KEY_LENGTH..=KMAC256_MAX_KEY_LENGTH).contains(&value) => {
                value
            }
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let context_len = match context.len(env) {
            Ok(value) if value <= KMAC256_MAX_CONTEXT_LENGTH => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let customization_len = match customization.len(env) {
            Ok(value) if value <= KMAC256_MAX_CUSTOMIZATION_LENGTH => value,
            Ok(_) | Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let key_bytes = match env.convert_byte_array(&key) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let context_bytes = match env.convert_byte_array(&context) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        let customization_bytes = match env.convert_byte_array(&customization) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return error_result(env, KOTLIN_NATIVE_INVALID_INPUT),
        };
        if key_bytes.len() != key_len
            || context_bytes.len() != context_len
            || customization_bytes.len() != customization_len
        {
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }
        let mut output = Zeroizing::new(vec![0_u8; output_len]);
        // SAFETY: All inputs and the output are distinct Rust-owned
        // allocations that remain live for the call. The output is uniquely
        // borrowed and writable for its complete declared length.
        let status = unsafe {
            rm_crypto_kmac256_derive(
                key_bytes.as_ptr(),
                key_bytes.len(),
                context_bytes.as_ptr(),
                context_bytes.len(),
                customization_bytes.as_ptr(),
                customization_bytes.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        if status != CRYPTO_OK {
            return error_result(env, status_from_crypto_status(status));
        }
        if output.len() != output_len {
            return error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL);
        }

        ok_result(env, &output)
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
