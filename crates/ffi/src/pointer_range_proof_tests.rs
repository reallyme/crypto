// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{checked_range_end, validate_disjoint_addresses};
use crate::status::CRYPTO_INVALID_ARGUMENT;

fn valid_extent(start: usize, len: usize) -> bool {
    len == 0 || (start != 0 && len <= usize::MAX / 2 && len <= usize::MAX - start)
}

#[kani::proof]
fn ffi_range_end_rejects_null_oversized_or_overflowing_extents() {
    let start: usize = kani::any();
    let len: usize = kani::any();
    let actual = checked_range_end(start, len);
    if valid_extent(start, len) {
        assert_eq!(actual, Ok(start + len));
    } else {
        assert_eq!(actual, Err(CRYPTO_INVALID_ARGUMENT));
    }
    kani::cover!(
        start == usize::MAX && len == 1 && actual.is_err(),
        "address overflow"
    );
    kani::cover!(
        start == 0 && len == 0 && actual.is_ok(),
        "empty null extent"
    );
}

#[kani::proof]
fn ffi_range_guard_accepts_exactly_valid_disjoint_extents() {
    let read: usize = kani::any();
    let read_len: usize = kani::any();
    let write: usize = kani::any();
    let write_len: usize = kani::any();

    // Specifying disjointness by the distance between starting addresses
    // keeps the oracle independent of the implementation's endpoint sums.
    let disjoint = read_len == 0
        || write_len == 0
        || if read <= write {
            read_len <= write - read
        } else {
            write_len <= read - write
        };
    let expected = if valid_extent(read, read_len) && valid_extent(write, write_len) && disjoint {
        Ok(())
    } else {
        Err(CRYPTO_INVALID_ARGUMENT)
    };
    let actual = validate_disjoint_addresses(read, read_len, write, write_len);
    assert_eq!(actual, expected);
    kani::cover!(
        read == 8 && read_len == 8 && write == 16 && write_len == 8 && actual.is_ok(),
        "adjacent extents"
    );
    kani::cover!(
        read == 8 && read_len == 8 && write == 15 && write_len == 8 && actual.is_err(),
        "one byte of overlap"
    );
    kani::cover!(
        read == write && read_len == write_len && read_len == 8 && read != 0 && actual.is_err(),
        "identical nonempty extents"
    );
}
