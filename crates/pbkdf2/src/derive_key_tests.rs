// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::validate_work_factor;
use crypto_core::CryptoError;

#[test]
fn work_factor_accepts_exact_limit_and_rejects_next_evaluation() {
    assert_eq!(validate_work_factor(10_000_000, 2), Ok(()));
    assert!(matches!(
        validate_work_factor(10_000_000, 3),
        Err(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    ));
    assert!(matches!(
        validate_work_factor(u32::MAX, usize::MAX),
        Err(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    ));
}
