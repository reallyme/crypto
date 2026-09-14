// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::ffi_guard;
use crate::status::CRYPTO_INTERNAL_ERROR;

#[test]
#[allow(clippy::panic)]
fn panic_is_mapped_to_internal_error_in_unwind_capable_builds() {
    let status = ffi_guard(|| panic!("test-only panic firewall probe"));

    assert_eq!(status, CRYPTO_INTERNAL_ERROR);
}
