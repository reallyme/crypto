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

use std::path::Path;

const PRIMITIVE_CRATES: &[&str] = &[
    "aes256-gcm-siv",
    "aes256-gcm",
    "argon2id",
    "chacha20-poly1305",
    "constant-time",
    "csprng",
    "ed25519",
    "hmac",
    "hkdf",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "ml-kem-512",
    "ml-kem-1024",
    "ml-kem-768",
    "p256",
    "secp256k1",
    "sha2",
    "sha2-256",
    "sha3",
    "sha3-256",
    "x25519",
];

// Rust crates expose native/wasm feature lanes. Swift and Kotlin provider
// selection is enforced in the SDK package matrix, not primitive Cargo features.
const REQUIRED_BACKEND_LANES: &[&str] = &["native", "wasm"];

#[test]
fn every_crypto_primitive_has_backend_lane_tests() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for crate_name in PRIMITIVE_CRATES {
        let test_path = workspace_root
            .join("crates/crypto/primitives")
            .join(crate_name)
            .join("tests/feature_lane_tests.rs");
        assert!(
            test_path.is_file(),
            "missing backend lane test file for {crate_name}"
        );

        let test_source =
            std::fs::read_to_string(&test_path).expect("backend lane test file should be readable");

        for lane in REQUIRED_BACKEND_LANES {
            let cfg_marker = format!("feature = \"{lane}\"");
            assert!(
                test_source.contains(&cfg_marker),
                "missing {lane} backend lane assertion for {crate_name}"
            );
        }
    }
}
