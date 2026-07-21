// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{
    CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use reallyme_crypto::argon2id::{
    Argon2KdfVersion, Argon2Profile, Argon2Salt, Argon2Secret, DeriveKeyRequest,
    ARGON2ID_DERIVED_KEY_LENGTH,
};
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};
use zeroize::Zeroize;

/// Length in bytes of the Argon2id-derived key (32).
pub const ARGON2ID_DERIVED_KEY_LEN: usize = ARGON2ID_DERIVED_KEY_LENGTH;

fn map_operation_error(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive { .. } => CRYPTO_INVALID_ARGUMENT,
        OperationError::Provider { .. } => CRYPTO_INVALID_ARGUMENT,
        OperationError::Backend { .. } => CRYPTO_INTERNAL_ERROR,
        _ => CRYPTO_INTERNAL_ERROR,
    }
}

/// Derives a 32-byte key from `secret` and `salt` using Argon2id, selecting the
/// cost profile from `kdf_version`, and writes it to `derived_key_out`.
///
/// # Safety
///
/// `secret` must be valid for `secret_len` bytes and `salt` for `salt_len`
/// bytes (either may be null only when its length is `0`). `derived_key_out`
/// must be non-null and point to at least `derived_key_out_len` writable bytes,
/// which must be at least [`ARGON2ID_DERIVED_KEY_LEN`] (32). Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`]
/// on success, [`CRYPTO_INVALID_ARGUMENT`] for an unknown `kdf_version` or bad
/// salt, [`CRYPTO_INVALID_KEY`] for an unacceptable secret.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_argon2id_derive_key(
    kdf_version: u32,
    secret: *const u8,
    secret_len: usize,
    salt: *const u8,
    salt_len: usize,
    derived_key_out: *mut u8,
    derived_key_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        if derived_key_out_len < ARGON2ID_DERIVED_KEY_LENGTH {
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        // SAFETY: This preflight validates the output pointer before the
        // memory-hard Argon2id computation. The final write rechecks aliasing
        // after registering the secret and salt inputs.
        let output_status = unsafe { write_fixed(derived_key_out, derived_key_out_len, &[]) };
        if output_status != CRYPTO_OK {
            return output_status;
        }

        let profile = match Argon2KdfVersion::try_from(kdf_version) {
            Ok(version) => Argon2Profile::from(version),
            Err(_) => return CRYPTO_INVALID_ARGUMENT,
        };
        let secret = match unsafe { read_slice(secret, secret_len) } {
            Ok(value) => match Argon2Secret::from_slice(value, profile) {
                Ok(secret) => secret,
                Err(_) => return CRYPTO_INVALID_KEY,
            },
            Err(status) => return status,
        };
        let salt = match unsafe { read_slice(salt, salt_len) } {
            Ok(value) => match Argon2Salt::from_slice(value, profile) {
                Ok(salt) => salt,
                Err(_) => return CRYPTO_INVALID_ARGUMENT,
            },
            Err(status) => return status,
        };

        let request = DeriveKeyRequest {
            profile,
            secret: &secret,
            salt: &salt,
        };
        let mut derived = match reallyme_crypto::operations::kdf::derive_argon2id(&request) {
            Ok(value) => value,
            Err(error) => return map_operation_error(error),
        };
        let status =
            unsafe { write_fixed(derived_key_out, derived_key_out_len, derived.as_bytes()) };
        // Wipe the derived key explicitly at the copy-out (it also zeroizes
        // on drop), matching the AEAD path and bounding the secret's window.
        derived.zeroize();
        status
    })
}
