// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{write_fixed, write_slice};
use crate::status::{CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT, CRYPTO_OK};
use crypto_core::RngOutputKind;
use crypto_csprng::{
    generate_aead_nonce_12, generate_argon2_salt_16, generate_argon2_salt_32, OsSecureRandom,
    SecureRandom, AEAD_NONCE_12_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
};

/// Length in bytes of a generated 12-byte AEAD nonce (12).
pub const CSPRNG_AEAD_NONCE_12_LEN: usize = AEAD_NONCE_12_LENGTH;
/// Length in bytes of a generated 16-byte Argon2 salt (16).
pub const CSPRNG_ARGON2_SALT_16_LEN: usize = ARGON2_SALT_16_LENGTH;
/// Length in bytes of a generated 32-byte Argon2 salt (32).
pub const CSPRNG_ARGON2_SALT_32_LEN: usize = ARGON2_SALT_32_LENGTH;

/// Fills `output_out` with `output_out_len` cryptographically secure random
/// bytes from the operating-system CSPRNG. A zero length is rejected.
///
/// # Safety
///
/// `output_out` must be non-null and point to at least `output_out_len`
/// writable bytes. Returns [`CryptoStatus`] via the return value:
/// [`CRYPTO_OK`] on success, [`CRYPTO_INVALID_ARGUMENT`] if `output_out_len`
/// is `0`, or [`CRYPTO_INTERNAL_ERROR`] if the RNG fails.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_csprng_generate_bytes(
    output_out: *mut u8,
    output_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        if output_out_len == 0 {
            return CRYPTO_INVALID_ARGUMENT;
        }
        let output = match unsafe { write_slice(output_out, output_out_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let mut rng = OsSecureRandom;
        match rng.fill_secure(output, RngOutputKind::Generic) {
            Ok(()) => CRYPTO_OK,
            Err(_) => CRYPTO_INTERNAL_ERROR,
        }
    })
}

/// Generates a random 12-byte AEAD nonce and writes it to `output_out`.
///
/// # Safety
///
/// `output_out` must be non-null and point to at least `output_out_len`
/// writable bytes, which must be at least [`CSPRNG_AEAD_NONCE_12_LEN`] (12).
/// Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success or
/// a negative error code (e.g. buffer too small, or RNG failure).
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_csprng_generate_aead_nonce_12(
    output_out: *mut u8,
    output_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let mut rng = OsSecureRandom;
        let nonce = match generate_aead_nonce_12(&mut rng) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        unsafe { write_fixed(output_out, output_out_len, nonce.as_bytes()) }
    })
}

/// Generates a random 16-byte Argon2 salt and writes it to `output_out`.
///
/// # Safety
///
/// `output_out` must be non-null and point to at least `output_out_len`
/// writable bytes, which must be at least [`CSPRNG_ARGON2_SALT_16_LEN`] (16).
/// Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success or
/// a negative error code (e.g. buffer too small, or RNG failure).
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_csprng_generate_argon2_salt_16(
    output_out: *mut u8,
    output_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let mut rng = OsSecureRandom;
        let salt = match generate_argon2_salt_16(&mut rng) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        unsafe { write_fixed(output_out, output_out_len, salt.as_bytes()) }
    })
}

/// Generates a random 32-byte Argon2 salt and writes it to `output_out`.
///
/// # Safety
///
/// `output_out` must be non-null and point to at least `output_out_len`
/// writable bytes, which must be at least [`CSPRNG_ARGON2_SALT_32_LEN`] (32).
/// Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success or
/// a negative error code (e.g. buffer too small, or RNG failure).
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_csprng_generate_argon2_salt_32(
    output_out: *mut u8,
    output_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let mut rng = OsSecureRandom;
        let salt = match generate_argon2_salt_32(&mut rng) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        unsafe { write_fixed(output_out, output_out_len, salt.as_bytes()) }
    })
}
