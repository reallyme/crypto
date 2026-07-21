// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{CryptoStatus, CRYPTO_OK};

/// Length in bytes of a SHA3-224 digest (28).
pub const SHA3_224_DIGEST_LEN: usize = reallyme_crypto::sha3::SHA3_224_DIGEST_LENGTH;
/// Length in bytes of a SHA3-384 digest (48).
pub const SHA3_384_DIGEST_LEN: usize = reallyme_crypto::sha3::SHA3_384_DIGEST_LENGTH;
/// Length in bytes of a SHA3-512 digest (64).
pub const SHA3_512_DIGEST_LEN: usize = reallyme_crypto::sha3::SHA3_512_DIGEST_LENGTH;

/// Computes the SHA3-224 digest of `message` and writes it to `digest_out`.
///
/// # Safety
///
/// `message` must be valid for `message_len` bytes (may be null only when
/// `message_len == 0`). `digest_out` must be non-null and point to at least
/// `digest_out_len` writable bytes, and `digest_out_len` must be at least
/// [`SHA3_224_DIGEST_LEN`] (28). The status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_sha3_224_digest(
    message: *const u8,
    message_len: usize,
    digest_out: *mut u8,
    digest_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let digest = reallyme_crypto::operations::hash::sha3_224(message);
        let status = unsafe { write_fixed(digest_out, digest_out_len, digest.as_bytes()) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}

/// Computes the SHA3-384 digest of `message` and writes it to `digest_out`.
///
/// # Safety
///
/// `message` must be valid for `message_len` bytes (may be null only when
/// `message_len == 0`). `digest_out` must be non-null and point to at least
/// `digest_out_len` writable bytes, and `digest_out_len` must be at least
/// [`SHA3_384_DIGEST_LEN`] (48). The status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_sha3_384_digest(
    message: *const u8,
    message_len: usize,
    digest_out: *mut u8,
    digest_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let digest = reallyme_crypto::operations::hash::sha3_384(message);
        let status = unsafe { write_fixed(digest_out, digest_out_len, digest.as_bytes()) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}

/// Computes the SHA3-512 digest of `message` and writes it to `digest_out`.
///
/// # Safety
///
/// `message` must be valid for `message_len` bytes (may be null only when
/// `message_len == 0`). `digest_out` must be non-null and point to at least
/// `digest_out_len` writable bytes, and `digest_out_len` must be at least
/// [`SHA3_512_DIGEST_LEN`] (64). The status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_sha3_512_digest(
    message: *const u8,
    message_len: usize,
    digest_out: *mut u8,
    digest_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let digest = reallyme_crypto::operations::hash::sha3_512(message);
        let status = unsafe { write_fixed(digest_out, digest_out_len, digest.as_bytes()) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}
