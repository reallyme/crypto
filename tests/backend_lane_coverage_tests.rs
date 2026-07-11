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

const ROOT_BACKEND_FORWARD_DEPS: &[&str] = &[
    "crypto-aes-kw",
    "crypto-aes256-gcm",
    "crypto-aes256-gcm-siv",
    "crypto-argon2id",
    "crypto-chacha20-poly1305",
    "crypto-constant-time",
    "crypto-csprng",
    "crypto-dispatch",
    "crypto-ed25519",
    "crypto-hkdf",
    "crypto-hmac",
    "crypto-hpke",
    "crypto-ml-dsa-44",
    "crypto-ml-dsa-65",
    "crypto-ml-dsa-87",
    "crypto-ml-kem-1024",
    "crypto-ml-kem-512",
    "crypto-ml-kem-768",
    "crypto-p256",
    "crypto-p384",
    "crypto-p521",
    "crypto-pbkdf2",
    "crypto-rsa",
    "crypto-secp256k1",
    "crypto-sha2",
    "crypto-sha2-256",
    "crypto-sha3",
    "crypto-sha3-256",
    "crypto-signer",
    "crypto-slh-dsa",
    "crypto-x-wing",
    "crypto-x25519",
    "envelopes-jwk",
    "envelopes-jwk-multikey",
];

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

#[test]
fn root_backend_lanes_forward_to_enabled_backend_dependencies() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = workspace_root.join("Cargo.toml");
    let manifest =
        std::fs::read_to_string(&manifest_path).expect("root Cargo.toml should be readable");

    for dependency in ROOT_BACKEND_FORWARD_DEPS {
        for lane in REQUIRED_BACKEND_LANES {
            let feature = format!("\"{dependency}?/{lane}\"");
            assert!(
                manifest.contains(&feature),
                "root {lane} feature must weak-forward to {dependency}/{lane}"
            );
        }
    }
}
