// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_INVALID_KEY,
};
use crypto_core::MacAlgorithm;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

/// Suite selector value requesting HMAC-SHA-256 (`1`).
pub const HMAC_SUITE_SHA256: u32 = 1;
/// Suite selector value requesting HMAC-SHA-512 (`2`).
pub const HMAC_SUITE_SHA512: u32 = 2;
/// Length in bytes of an HMAC-SHA-256 tag (32).
pub const HMAC_SHA256_TAG_LEN: usize = reallyme_crypto::hmac::HMAC_SHA256_TAG_LENGTH;
/// Length in bytes of an HMAC-SHA-512 tag (64).
pub const HMAC_SHA512_TAG_LEN: usize = reallyme_crypto::hmac::HMAC_SHA512_TAG_LENGTH;

fn suite_from_u32(value: u32) -> Result<MacAlgorithm, CryptoStatus> {
    match value {
        HMAC_SUITE_SHA256 => Ok(MacAlgorithm::HmacSha256),
        HMAC_SUITE_SHA512 => Ok(MacAlgorithm::HmacSha512),
        _ => Err(CRYPTO_INVALID_ARGUMENT),
    }
}

fn status_from_error(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        } => CRYPTO_INVALID_ARGUMENT,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => CRYPTO_AUTHENTICATION_FAILED,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INTERNAL_ERROR,
        OperationError::Primitive { .. }
        | OperationError::Provider { .. }
        | OperationError::Backend { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}

/// Computes an HMAC tag over `message` with the selected suite.
///
/// # Safety
///
/// `key` and `message` must be valid for their respective lengths (the message
/// may be null only when `message_len == 0`). `tag_out` must be non-null and
/// point to at least `tag_out_len` writable bytes; `tag_out_len` must be at
/// least 32 for SHA-256 or 64 for SHA-512. The status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_hmac_authenticate(
    suite: u32,
    key: *const u8,
    key_len: usize,
    message: *const u8,
    message_len: usize,
    tag_out: *mut u8,
    tag_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let suite = match suite_from_u32(suite) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let tag = match reallyme_crypto::operations::mac::authenticate(suite, key, message) {
            Ok(value) => value,
            Err(error) => return status_from_error(error),
        };

        unsafe { write_fixed(tag_out, tag_out_len, &tag) }
    })
}

/// Verifies an HMAC tag over `message` with the selected suite.
///
/// # Safety
///
/// `key`, `message`, and `tag` must be valid for their respective lengths
/// (message may be null only when `message_len == 0`). The tag length must be
/// exact for the selected suite: 32 bytes for SHA-256 or 64 bytes for SHA-512.
/// The status is [`CRYPTO_OK`](crate::status::CRYPTO_OK) on success and
/// [`CRYPTO_AUTHENTICATION_FAILED`] when the tag is well-formed but invalid.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_hmac_verify(
    suite: u32,
    key: *const u8,
    key_len: usize,
    message: *const u8,
    message_len: usize,
    tag: *const u8,
    tag_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let suite = match suite_from_u32(suite) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let tag = match unsafe { read_slice(tag, tag_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        match reallyme_crypto::operations::mac::verify(suite, key, message, tag) {
            Ok(()) => crate::status::CRYPTO_OK,
            Err(error) => status_from_error(error),
        }
    })
}
