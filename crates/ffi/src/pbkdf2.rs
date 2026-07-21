// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{
    CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};
use reallyme_crypto::pbkdf2::{
    Pbkdf2Prf, PBKDF2_MAX_ITERATIONS, PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MAX_PASSWORD_LENGTH,
    PBKDF2_MAX_SALT_LENGTH, PBKDF2_MIN_OUTPUT_LENGTH, PBKDF2_MIN_PASSWORD_LENGTH,
    PBKDF2_MIN_SALT_LENGTH, PBKDF2_MODERN_MIN_ITERATIONS,
};

/// Minimum password length accepted by the PBKDF2 ABI.
pub const PBKDF2_PASSWORD_MIN_LEN: usize = PBKDF2_MIN_PASSWORD_LENGTH;
/// Maximum password length accepted by the PBKDF2 ABI.
pub const PBKDF2_PASSWORD_MAX_LEN: usize = PBKDF2_MAX_PASSWORD_LENGTH;
/// Minimum salt length accepted by the PBKDF2 ABI.
pub const PBKDF2_SALT_MIN_LEN: usize = PBKDF2_MIN_SALT_LENGTH;
/// Maximum salt length accepted by the PBKDF2 ABI.
pub const PBKDF2_SALT_MAX_LEN: usize = PBKDF2_MAX_SALT_LENGTH;
/// Minimum PBKDF2 iteration count accepted by this public ABI.
pub const PBKDF2_ITERATIONS_MIN: u32 = PBKDF2_MODERN_MIN_ITERATIONS;
/// Maximum PBKDF2 iteration count accepted by this public ABI.
pub const PBKDF2_ITERATIONS_MAX: u32 = PBKDF2_MAX_ITERATIONS;
/// Minimum PBKDF2 output length accepted by the ABI.
pub const PBKDF2_OUTPUT_MIN_LEN: usize = PBKDF2_MIN_OUTPUT_LENGTH;
/// Maximum PBKDF2 output length accepted by the ABI.
pub const PBKDF2_OUTPUT_MAX_LEN: usize = PBKDF2_MAX_OUTPUT_LENGTH;

fn map_error(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive { .. } => CRYPTO_INVALID_ARGUMENT,
        OperationError::Backend { .. } => CRYPTO_INTERNAL_ERROR,
        OperationError::Provider { .. } => CRYPTO_INVALID_ARGUMENT,
        _ => CRYPTO_INTERNAL_ERROR,
    }
}

struct Pbkdf2FfiRequest {
    prf: Pbkdf2Prf,
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    output: *mut u8,
    output_len: usize,
}

fn derive_pbkdf2(request: Pbkdf2FfiRequest) -> CryptoStatus {
    if !(PBKDF2_MIN_OUTPUT_LENGTH..=PBKDF2_MAX_OUTPUT_LENGTH).contains(&request.output_len) {
        return CRYPTO_INVALID_ARGUMENT;
    }
    // SAFETY: This zero-length preflight checks the caller-owned output
    // pointer before PBKDF2 performs CPU-expensive work. The final write still
    // validates aliasing against registered password and salt inputs.
    let output_status = unsafe { write_fixed(request.output, request.output_len, &[]) };
    if output_status != CRYPTO_OK {
        return output_status;
    }

    // SAFETY: The exported entry point requires the password allocation to
    // remain valid and immutable for this call. The pointer helper validates
    // the pair and registers the input range for the later alias check.
    let password = match unsafe { read_slice(request.password, request.password_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    // SAFETY: The exported entry point applies the same lifetime and
    // immutability contract to the salt allocation.
    let salt = match unsafe { read_slice(request.salt, request.salt_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };

    let derived = match reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw(
        request.prf,
        password,
        salt,
        request.iterations,
        request.output_len,
    ) {
        Ok(value) => value,
        Err(error) => return map_error(error),
    };

    // SAFETY: The caller-owned output is required to be writable for its
    // declared length. `write_fixed` validates capacity and rejects overlap
    // with the registered password and salt inputs before constructing a
    // mutable slice.
    unsafe { write_fixed(request.output, request.output_len, derived.as_bytes()) }
}

/// Derives output keying material with PBKDF2-HMAC-SHA-256.
///
/// # Safety
///
/// `password` and `salt` must be valid for their lengths. `output` must point
/// to `output_len` writable bytes; `output_len` is also the requested derived
/// key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_pbkdf2_hmac_sha256_derive_key(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    output: *mut u8,
    output_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        derive_pbkdf2(Pbkdf2FfiRequest {
            prf: Pbkdf2Prf::HmacSha256,
            password,
            password_len,
            salt,
            salt_len,
            iterations,
            output,
            output_len,
        })
    })
}

/// Derives output keying material with PBKDF2-HMAC-SHA-512.
///
/// # Safety
///
/// `password` and `salt` must be valid for their lengths. `output` must point
/// to `output_len` writable bytes; `output_len` is also the requested derived
/// key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_pbkdf2_hmac_sha512_derive_key(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    output: *mut u8,
    output_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        derive_pbkdf2(Pbkdf2FfiRequest {
            prf: Pbkdf2Prf::HmacSha512,
            password,
            password_len,
            salt,
            salt_len,
            iterations,
            output,
            output_len,
        })
    })
}
