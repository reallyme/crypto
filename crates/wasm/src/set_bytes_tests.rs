// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::require_stored;
use crypto_core::CryptoError;

#[test]
fn a_backend_rejected_property_write_cannot_report_success() {
    assert_eq!(require_stored(false), Err(CryptoError::BACKEND_INTERNAL));
    assert_eq!(require_stored(true), Ok(()));
}
