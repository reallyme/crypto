// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::assertions_on_constants)]

//! Feature-lane guard tests for the RSA primitive.

use crypto_rsa::{RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS};

#[test]
fn native_feature_lane_executes_tests() {
    assert!(cfg!(feature = "native"));
    assert_eq!(RSA_MIN_MODULUS_BITS, 1024);
    assert_eq!(RSA_MAX_MODULUS_BITS, 8192);
}
