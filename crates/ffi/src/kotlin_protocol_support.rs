// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared bounded, zeroizing transport for Kotlin protocol adapters.

use crypto_core::CryptoError;
use jni::objects::JByteArray;
use jni::sys::jbyteArray;
use jni::{Env, EnvUnowned, Outcome};
use zeroize::Zeroizing;

use crate::kotlin_result::{
    backend_internal_result, error_result, ok_result, status_from_crypto_status,
};

pub(super) type Bytes = Zeroizing<Vec<u8>>;
const MAX_INPUT: usize = crypto_core::contract_constants::adapter_limits::MAX_JNI_BYTE_INPUT_LENGTH;

// Copy only after validating the managed array's length. Every copy, including
// plaintext and caller seeds, has one Rust owner that wipes on every exit path.
pub(super) fn input(env: &mut Env<'_>, value: &JByteArray<'_>) -> Result<Bytes, CryptoError> {
    bounded_input(env, value, MAX_INPUT)
}

pub(super) fn hpke_ciphertext(
    env: &mut Env<'_>,
    value: &JByteArray<'_>,
) -> Result<Bytes, CryptoError> {
    let limit = MAX_INPUT
        .checked_add(reallyme_crypto::hpke::HPKE_AEAD_TAG_LEN)
        .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    bounded_input(env, value, limit)
}

fn bounded_input(
    env: &mut Env<'_>,
    value: &JByteArray<'_>,
    maximum: usize,
) -> Result<Bytes, CryptoError> {
    if value.is_null() {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    let length = value.len(env).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    if length > maximum {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    let bytes = Zeroizing::new(
        env.convert_byte_array(value)
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?,
    );
    if bytes.len() != length {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    Ok(bytes)
}

// Components have schema-defined fixed widths (or a caller-known ciphertext
// width). Concatenating them avoids creating immutable JVM secret containers.
pub(super) fn pair(first: &[u8], second: &[u8]) -> Result<Bytes, CryptoError> {
    let length = first
        .len()
        .checked_add(second.len())
        .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    bytes.extend_from_slice(first);
    bytes.extend_from_slice(second);
    Ok(bytes)
}

pub(super) fn run<'local>(
    mut env: EnvUnowned<'local>,
    project: fn(CryptoError) -> i32,
    operation: impl FnOnce(&mut Env<'local>) -> Result<Bytes, CryptoError>,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        match operation(env) {
            Ok(bytes) => ok_result(env, &bytes),
            Err(error) => {
                if env.exception_check() {
                    return backend_internal_result(env);
                }
                let status = if error == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM {
                    crypto_core::contract_constants::kotlin_native_status::KOTLIN_NATIVE_UNSUPPORTED_ALGORITHM
                } else if error == CryptoError::PRIMITIVE_INVALID_SHARED_SECRET {
                    // Non-contributory recipient keys are malformed peer input
                    // in the Kotlin contract, not a provider implementation failure.
                    crypto_core::contract_constants::kotlin_native_status::KOTLIN_NATIVE_INVALID_INPUT
                } else {
                    status_from_crypto_status(project(error))
                };
                error_result(env, status)
            }
        }
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(_) | Outcome::Panic(_) => {
            // with_env catches unwinding before any JVM boundary is crossed.
            match env.with_env(backend_internal_result).into_outcome() {
                Outcome::Ok(value) => value,
                Outcome::Err(_) | Outcome::Panic(_) => std::ptr::null_mut(),
            }
        }
    }
}
