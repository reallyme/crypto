// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
use crypto_constant_time::{ct_eq, ct_eq_fixed, require_ct_eq};
use crypto_core::{ConstantTimeFailureKind, CryptoError};

#[test]
fn equal_buffers_return_true() {
    assert!(ct_eq(b"abc", b"abc"));
}

#[test]
fn unequal_buffers_return_false() {
    assert!(!ct_eq(b"abc", b"abd"));
}

#[test]
fn different_lengths_return_false() {
    assert!(!ct_eq(b"abc", b"abcd"));
}

#[test]
fn fixed_array_comparison_works() {
    let left = [9u8; 16];
    let right = [9u8; 16];
    assert!(ct_eq_fixed(&left, &right));
}

#[test]
fn require_ct_eq_rejects_length_mismatch() {
    let result = require_ct_eq(b"a", b"ab");

    assert_eq!(
        result,
        Err(CryptoError::ConstantTimeComparison {
            kind: ConstantTimeFailureKind::LengthMismatch,
            left_len: 1,
            right_len: 2,
        })
    );
}

#[test]
fn require_ct_eq_rejects_non_equal() {
    let result = require_ct_eq(b"abc", b"abd");

    assert_eq!(
        result,
        Err(CryptoError::ConstantTimeComparison {
            kind: ConstantTimeFailureKind::NotEqual,
            left_len: 3,
            right_len: 3,
        })
    );
}

#[test]
fn require_ct_eq_accepts_equal() {
    let result = require_ct_eq(b"abc", b"abc");
    assert!(result.is_ok());
}
