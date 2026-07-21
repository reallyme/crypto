// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Compact JNI result envelope shared by Kotlin native providers.
//!
//! JNI methods return a byte array containing a signed 32-bit status followed by
//! optional result bytes. This avoids constructing JVM objects in Rust while
//! still making every native failure explicit and deterministic.

use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY,
    CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};
use jni::objects::JByteArray;
use jni::sys::jbyteArray;
use jni::Env;
use zeroize::{Zeroize, Zeroizing};

const STATUS_LEN: usize = 4;

/// Kotlin native status for successful operation results.
pub const KOTLIN_NATIVE_OK: i32 = 0;
/// Kotlin native status for malformed, unsupported, or invalid caller input.
pub const KOTLIN_NATIVE_INVALID_INPUT: i32 = 1;
/// Kotlin native status for authenticated decryption failures.
pub const KOTLIN_NATIVE_AUTHENTICATION_FAILED: i32 = 2;
/// Kotlin native status for backend failures that must not expose internals.
pub const KOTLIN_NATIVE_BACKEND_INTERNAL: i32 = 5;
/// Kotlin native status for signature verification failures.
pub const KOTLIN_NATIVE_INVALID_SIGNATURE: i32 = 6;

/// Maps C ABI status values to the deterministic Kotlin native status domain.
pub fn status_from_crypto_status(status: CryptoStatus) -> i32 {
    match status {
        CRYPTO_OK => KOTLIN_NATIVE_OK,
        CRYPTO_INVALID_ARGUMENT | CRYPTO_INVALID_KEY | CRYPTO_INVALID_CIPHERTEXT => {
            KOTLIN_NATIVE_INVALID_INPUT
        }
        CRYPTO_AUTHENTICATION_FAILED => KOTLIN_NATIVE_AUTHENTICATION_FAILED,
        CRYPTO_INVALID_SIGNATURE => KOTLIN_NATIVE_INVALID_SIGNATURE,
        // JNI wrappers size their own native output buffers. A too-small status
        // here means the wrapper contract drifted, not that the caller supplied
        // invalid input.
        CRYPTO_BUFFER_TOO_SMALL => KOTLIN_NATIVE_BACKEND_INTERNAL,
        CRYPTO_INTERNAL_ERROR => KOTLIN_NATIVE_BACKEND_INTERNAL,
        _ => KOTLIN_NATIVE_BACKEND_INTERNAL,
    }
}

pub(crate) fn ok_result<'local>(
    env: &mut Env<'local>,
    payload: &[u8],
) -> jni::errors::Result<jbyteArray> {
    encode_result(env, KOTLIN_NATIVE_OK, payload)
}

pub(crate) fn error_result<'local>(
    env: &mut Env<'local>,
    status: i32,
) -> jni::errors::Result<jbyteArray> {
    encode_result(env, status, &[])
}

pub(crate) fn backend_internal_result<'local>(
    env: &mut Env<'local>,
) -> jni::errors::Result<jbyteArray> {
    clear_pending_exception(env);
    error_result(env, KOTLIN_NATIVE_BACKEND_INTERNAL)
}

fn clear_pending_exception(env: &mut Env<'_>) {
    if env.exception_check() {
        env.exception_clear();
    }
}

fn encode_result<'local>(
    env: &mut Env<'local>,
    status: i32,
    payload: &[u8],
) -> jni::errors::Result<jbyteArray> {
    let capacity = STATUS_LEN
        .checked_add(payload.len())
        .ok_or(jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
    // Native result payloads may contain plaintext or derived key material.
    // Drop-time wiping covers JNI allocation errors and unwind paths.
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    encoded.extend_from_slice(&status.to_be_bytes());
    encoded.extend_from_slice(payload);
    let output: JByteArray<'local> = env.byte_array_from_slice(&encoded)?;
    encoded.zeroize();
    Ok(output.into_raw())
}
