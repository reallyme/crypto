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

use std::path::{Path, PathBuf};

const PRIMITIVE_CRATES: &[&str] = &[
    "aes256-gcm-siv",
    "aes256-gcm",
    "argon2id",
    "chacha20-poly1305",
    "concat-kdf",
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
    "crypto-concat-kdf",
    "crypto-constant-time",
    "crypto-csprng",
    "crypto-dispatch",
    "crypto-ed25519",
    "crypto-hkdf",
    "crypto-hmac",
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_crypto_primitive_has_backend_lane_tests() {
    let workspace_root = workspace_root();

    for crate_name in PRIMITIVE_CRATES {
        let test_path = workspace_root
            .join("crates")
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
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
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

    // HPKE is intentionally different from ordinary primitive crates. The
    // root backend lanes install only its implementation machinery; `hpke`
    // and `hpke-openmls` select the full or narrow algorithm sets separately.
    // Weak-forwarding `native` or `wasm` here would silently restore every
    // HPKE component whenever an otherwise narrow consumer selects a backend.
    assert_eq!(
        manifest.matches("\"crypto-hpke?/backend-native\"").count(),
        REQUIRED_BACKEND_LANES.len(),
        "root native and wasm features must weak-forward only the HPKE backend machinery"
    );
    assert!(!manifest.contains("\"crypto-hpke?/native\""));
    assert!(!manifest.contains("\"crypto-hpke?/wasm\""));
    assert!(manifest.contains("hpke = [\"hpke-api\", \"crypto-hpke/native\"]"));
    assert!(manifest.contains("hpke-openmls = [\"hpke-api\", \"crypto-hpke/openmls\"]"));
}

#[test]
fn root_manifest_keeps_platform_provider_selection_out_of_rust_features() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest =
        std::fs::read_to_string(&manifest_path).expect("root Cargo.toml should be readable");

    assert!(manifest.contains("default = [\n    \"native\","));
    assert!(!manifest.contains("\nswift ="));
    assert!(!manifest.contains("\nkotlin ="));
    assert!(manifest.contains("operation-response = ["));
    assert!(!manifest.contains("proto-process"));
}
