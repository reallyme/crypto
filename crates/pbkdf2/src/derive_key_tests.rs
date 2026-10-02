// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_work_factor, Pbkdf2Prf};
use crypto_core::{CryptoError, KdfFailureKind};

#[test]
fn work_factor_accepts_exact_limit_and_rejects_next_evaluation() {
    let prf = Pbkdf2Prf::HmacSha256;
    assert_eq!(validate_work_factor(prf, 10_000_000, 2), Ok(()));
    assert!(matches!(
        validate_work_factor(prf, 10_000_000, 3),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::ResourceLimitExceeded,
            ..
        })
    ));
    assert!(matches!(
        validate_work_factor(prf, u32::MAX, usize::MAX),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::ResourceLimitExceeded,
            ..
        })
    ));
}
