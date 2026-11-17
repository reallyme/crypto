// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use core::mem::needs_drop;

#[test]
fn kmac256_backend_requires_drop_cleanup() {
    // SHA-3 0.10 gates its sponge destructor on `zeroize` without exposing a
    // public ZeroizeOnDrop marker. Check the actual KMAC backend rather than the
    // feature-unifying alias: enabling a different SHA-3 release must not pass.
    // This avoids reading secret-bearing memory after its owner has been dropped.
    assert!(needs_drop::<sha3_kmac::Kmac256>());
}
