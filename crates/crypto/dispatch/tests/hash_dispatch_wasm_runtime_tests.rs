// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use crypto_core::HashAlgorithm;
use crypto_dispatch::hash_digest;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn wasm_runtime_sha3_dispatch_matches_regression_vectors() {
    let vectors = [
        (
            b"".as_slice(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            b"The quick brown fox jumps over the lazy dog".as_slice(),
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
        ),
        (
            b"The quick brown fox jumps over the lazy dog.".as_slice(),
            "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
        ),
    ];

    for (message, digest_hex) in vectors {
        let dispatched =
            hash_digest(HashAlgorithm::Sha3_256, message).expect("dispatch hashing must succeed");
        assert_eq!(hex::encode(dispatched), digest_hex);
    }
}
