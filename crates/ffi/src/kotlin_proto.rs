// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JNI bridge for the Kotlin executable protobuf boundary.
//!
//! Kotlin receives raw binary protobuf operation output; operation failures
//! remain in generated protobuf messages instead of being translated into a
//! second JNI exception vocabulary.

use crypto_proto::operation_response_wire::MAX_CRYPTO_OPERATION_RESPONSE_BYTES;
use crypto_proto::wire::{MAX_CRYPTO_PROTO_JSON_BYTES, MAX_CRYPTO_PROTO_MESSAGE_BYTES};
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::{EnvUnowned, Outcome};
use reallyme_crypto::operation_contract::{
    process_operation_response as process_operation_response_request,
    process_operation_response_json as process_operation_response_json_request,
};
use std::ptr;
use zeroize::Zeroizing;

type ProcessOperationFunction = fn(&[u8]) -> Zeroizing<Vec<u8>>;

/// Executes one binary protobuf request and returns `CryptoOperationResponse`.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeCryptoOperationResponseNative_processOperationResponseNative<
    'local,
>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    request: JByteArray<'local>,
) -> jbyteArray {
    process_operation_response(
        env,
        class,
        request,
        MAX_CRYPTO_PROTO_MESSAGE_BYTES,
        MAX_CRYPTO_OPERATION_RESPONSE_BYTES,
        process_operation_response_request,
    )
}

/// Executes one generated ProtoJSON request and returns `CryptoOperationResponse`.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeCryptoOperationResponseNative_processOperationResponseJsonNative<
    'local,
>(
    env: EnvUnowned<'local>,
    class: JClass<'local>,
    request: JByteArray<'local>,
) -> jbyteArray {
    process_operation_response(
        env,
        class,
        request,
        MAX_CRYPTO_PROTO_JSON_BYTES,
        MAX_CRYPTO_OPERATION_RESPONSE_BYTES,
        process_operation_response_json_request,
    )
}

fn process_operation_response<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: JByteArray<'local>,
    max_request_len: usize,
    max_output_len: usize,
    process: ProcessOperationFunction,
) -> jbyteArray {
    let outcome = env.with_env(|env| -> jni::errors::Result<jbyteArray> {
        let request_len = match request.len(env) {
            Ok(value) => value,
            Err(_) => return throw_provider_failure(env),
        };
        let request = if request_len > max_request_len {
            // Avoid copying an attacker-sized managed array into native memory.
            // A one-byte-over-limit sentinel drives the canonical Rust decoder
            // into its typed resource-limit response without retaining input.
            let sentinel_len = match max_request_len.checked_add(1) {
                Some(value) => value,
                None => return throw_provider_failure(env),
            };
            Zeroizing::new(vec![0_u8; sentinel_len])
        } else {
            match env.convert_byte_array(&request) {
                Ok(value) => Zeroizing::new(value),
                Err(_) => return throw_provider_failure(env),
            }
        };
        // The primary JNI route calls the canonical Rust operation boundary
        // directly. This avoids C ABI probe/fill semantics and executes future
        // randomized or expensive operations exactly once.
        let output = process(request.as_slice());
        if output.is_empty() || output.len() > max_output_len {
            return throw_provider_failure(env);
        }
        env.byte_array_from_slice(output.as_slice())
            .map(|value| value.into_raw())
    });

    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(_) | Outcome::Panic(_) => {
            throw_provider_failure_if_clear(&mut env);
            ptr::null_mut()
        }
    }
}

fn throw_provider_failure<T>(env: &mut jni::Env<'_>) -> jni::errors::Result<T> {
    env.throw_new_void(jni::jni_str!(
        "me/really/crypto/ReallyMeCryptoException$ProviderFailure"
    ))?;
    Err(jni::errors::Error::JavaException)
}

fn throw_provider_failure_if_clear(env: &mut EnvUnowned<'_>) {
    let _outcome = env.with_env(|env| -> jni::errors::Result<()> {
        if !env.exception_check() {
            env.throw_new_void(jni::jni_str!(
                "me/really/crypto/ReallyMeCryptoException$ProviderFailure"
            ))?;
        }
        Ok(())
    });
}
