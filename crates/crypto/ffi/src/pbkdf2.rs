// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{CryptoStatus, CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_KEY};
use crypto_core::{CryptoError, KdfFailureKind};
use crypto_pbkdf2::{
    derive_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request, Pbkdf2Salt,
    PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MAX_PASSWORD_LENGTH, PBKDF2_MAX_SALT_LENGTH,
    PBKDF2_MIN_ITERATIONS, PBKDF2_MIN_OUTPUT_LENGTH, PBKDF2_MIN_PASSWORD_LENGTH,
    PBKDF2_MIN_SALT_LENGTH,
};
use zeroize::Zeroize;

/// Minimum password length accepted by the PBKDF2 ABI.
pub const PBKDF2_PASSWORD_MIN_LEN: usize = PBKDF2_MIN_PASSWORD_LENGTH;
/// Maximum password length accepted by the PBKDF2 ABI.
pub const PBKDF2_PASSWORD_MAX_LEN: usize = PBKDF2_MAX_PASSWORD_LENGTH;
/// Minimum salt length accepted by the PBKDF2 ABI.
pub const PBKDF2_SALT_MIN_LEN: usize = PBKDF2_MIN_SALT_LENGTH;
/// Maximum salt length accepted by the PBKDF2 ABI.
pub const PBKDF2_SALT_MAX_LEN: usize = PBKDF2_MAX_SALT_LENGTH;
/// Minimum PBKDF2 iteration count accepted by the ABI.
pub const PBKDF2_ITERATIONS_MIN: u32 = PBKDF2_MIN_ITERATIONS;
/// Minimum PBKDF2 output length accepted by the ABI.
pub const PBKDF2_OUTPUT_MIN_LEN: usize = PBKDF2_MIN_OUTPUT_LENGTH;
/// Maximum PBKDF2 output length accepted by the ABI.
pub const PBKDF2_OUTPUT_MAX_LEN: usize = PBKDF2_MAX_OUTPUT_LENGTH;

fn map_error(error: CryptoError) -> CryptoStatus {
    match error {
        CryptoError::Kdf {
            kind: KdfFailureKind::InvalidSecretLength,
            ..
        } => CRYPTO_INVALID_KEY,
        CryptoError::Kdf {
            kind:
                KdfFailureKind::InvalidSaltLength
                | KdfFailureKind::InvalidOutputLength
                | KdfFailureKind::InvalidIterationCount
                | KdfFailureKind::InvalidParams
                | KdfFailureKind::DerivationFailed,
            ..
        } => CRYPTO_INVALID_ARGUMENT,
        _ => CRYPTO_INVALID_ARGUMENT,
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
    let password = match unsafe { read_slice(request.password, request.password_len) } {
        Ok(value) => match Pbkdf2Password::from_slice(value, request.prf) {
            Ok(value) => value,
            Err(error) => return map_error(error),
        },
        Err(status) => return status,
    };
    let salt = match unsafe { read_slice(request.salt, request.salt_len) } {
        Ok(value) => match Pbkdf2Salt::from_slice(value, request.prf) {
            Ok(value) => value,
            Err(error) => return map_error(error),
        },
        Err(status) => return status,
    };
    let iterations = match Pbkdf2Iterations::from_u32(request.iterations, request.prf) {
        Ok(value) => value,
        Err(error) => return map_error(error),
    };
    let mut derived = match derive_key(&Pbkdf2Request {
        prf: request.prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len: request.output_len,
    }) {
        Ok(value) => value.into_vec(),
        Err(error) => return map_error(error),
    };

    let status = unsafe { write_fixed(request.output, request.output_len, &derived) };
    derived.zeroize();
    status
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
