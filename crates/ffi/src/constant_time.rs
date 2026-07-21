// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_i32};
use crate::status::{CryptoStatus, CRYPTO_OK};

/// Compares two byte slices in constant time, writing `1` (equal) or `0`
/// (not equal) to `equal_out`. Slices of differing lengths compare as not equal.
///
/// # Safety
///
/// `left` must be valid for `left_len` bytes and `right` for `right_len` bytes
/// (either may be null only when its length is `0`). `equal_out` must be
/// non-null and point to a writable `i32`. Returns [`CRYPTO_OK`] on success or
/// a negative [`CryptoStatus`] error code; the status is the return value.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_constant_time_equal(
    left: *const u8,
    left_len: usize,
    right: *const u8,
    right_len: usize,
    equal_out: *mut i32,
) -> CryptoStatus {
    ffi_guard(|| {
        let left = match unsafe { read_slice(left, left_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let right = match unsafe { read_slice(right, right_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let equal = if reallyme_crypto::operations::constant_time::equal(left, right) {
            1
        } else {
            0
        };
        let status = unsafe { write_i32(equal_out, equal) };
        if status == CRYPTO_OK {
            CRYPTO_OK
        } else {
            status
        }
    })
}
