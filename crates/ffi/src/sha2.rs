// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{CryptoStatus, CRYPTO_OK};

/// Length in bytes of a SHA-384 digest (48).
pub const SHA2_384_DIGEST_LEN: usize = reallyme_crypto::sha2::SHA2_384_DIGEST_LENGTH;
/// Length in bytes of a SHA-512 digest (64).
pub const SHA2_512_DIGEST_LEN: usize = reallyme_crypto::sha2::SHA2_512_DIGEST_LENGTH;

/// Computes the SHA-384 digest of `message` and writes it to `digest_out`.
///
/// # Safety
///
/// `message` must be valid for `message_len` bytes (may be null only when
/// `message_len == 0`). `digest_out` must be non-null and point to at least
/// `digest_out_len` writable bytes, and `digest_out_len` must be at least
/// [`SHA2_384_DIGEST_LEN`] (48). The status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_sha2_384_digest(
    message: *const u8,
    message_len: usize,
    digest_out: *mut u8,
    digest_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        // SAFETY: The C caller keeps this input readable and initialized for the stated length until the call
        // returns. read_slice bounds and registers the borrowed range; ownership stays with the caller.
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let digest = reallyme_crypto::operations::hash::sha2_384(message);
        // SAFETY: The C caller keeps this output writable for the stated length until the call returns.
        // write_fixed bounds the copy and rejects overlap with borrowed inputs; ownership stays with the caller.
        let status = unsafe { write_fixed(digest_out, digest_out_len, digest.as_bytes()) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}

/// Computes the SHA-512 digest of `message` and writes it to `digest_out`.
///
/// # Safety
///
/// `message` must be valid for `message_len` bytes (may be null only when
/// `message_len == 0`). `digest_out` must be non-null and point to at least
/// `digest_out_len` writable bytes, and `digest_out_len` must be at least
/// [`SHA2_512_DIGEST_LEN`] (64). The status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_sha2_512_digest(
    message: *const u8,
    message_len: usize,
    digest_out: *mut u8,
    digest_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        // SAFETY: The C caller keeps this input readable and initialized for the stated length until the call
        // returns. read_slice bounds and registers the borrowed range; ownership stays with the caller.
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let digest = reallyme_crypto::operations::hash::sha2_512(message);
        // SAFETY: The C caller keeps this output writable for the stated length until the call returns.
        // write_fixed bounds the copy and rejects overlap with borrowed inputs; ownership stays with the caller.
        let status = unsafe { write_fixed(digest_out, digest_out_len, digest.as_bytes()) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}
