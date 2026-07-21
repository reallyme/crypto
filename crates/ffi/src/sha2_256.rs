// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{CryptoStatus, CRYPTO_OK};

/// Length in bytes of a SHA-256 digest (32).
pub const SHA2_256_DIGEST_LEN: usize = reallyme_crypto::sha2::SHA2_256_DIGEST_LENGTH;

/// Computes the SHA-256 digest of `message` and writes it to `digest_out`.
///
/// # Safety
///
/// `message` must be valid for `message_len` bytes (may be null only when
/// `message_len == 0`). `digest_out` must be non-null and point to at least
/// `digest_out_len` writable bytes, and `digest_out_len` must be at least
/// [`SHA2_256_DIGEST_LEN`] (32). Returns [`CRYPTO_OK`] on success or a negative
/// [`CryptoStatus`] error code (e.g. buffer too small); the status is the
/// return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_sha2_256_digest(
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
        let digest = reallyme_crypto::operations::hash::sha2_256(message);
        let status = unsafe { write_fixed(digest_out, digest_out_len, digest.as_bytes()) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}
