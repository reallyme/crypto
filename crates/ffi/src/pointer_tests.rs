// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_read_pair, validate_write_pair};
use crate::status::CRYPTO_INVALID_ARGUMENT;

#[test]
fn wrapping_byte_ranges_fail_validation_without_dereferencing() {
    let pointer = core::ptr::without_provenance_mut::<u8>(usize::MAX);
    assert_eq!(validate_read_pair(pointer, 2), Err(CRYPTO_INVALID_ARGUMENT));
    assert_eq!(
        validate_write_pair(pointer, 2),
        Err(CRYPTO_INVALID_ARGUMENT)
    );
    // Zero-length pointers retain their existing no-access semantics.
    assert_eq!(validate_read_pair(pointer, 0), Ok(()));
    assert_eq!(validate_write_pair(pointer, 0), Ok(()));
}
