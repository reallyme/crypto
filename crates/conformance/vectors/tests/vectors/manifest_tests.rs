// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::collections::BTreeSet;

use crate::support::{
    field_array, field_string, load, load_package_json, object_field, VectorTestError,
};

const NOBLE_POST_QUANTUM_VERSION: &str = "0.6.1";
const NOBLE_POST_QUANTUM_INTEGRITY: &str =
    "sha512-+pormrDZwjRw05U8ADK4JpHejo87+gBd+muRBB/ozztH5yhDLMDF4jHQWN3NQQAsu1zBNPWTG0ZwVI0CR29H0A==";

#[test]
fn noble_post_quantum_vector_oracle_is_pinned() -> Result<(), VectorTestError> {
    let package = load_package_json("package.json")?;
    let lock = load_package_json("package-lock.json")?;

    assert_eq!(
        package
            .get("dependencies")
            .and_then(|dependencies| dependencies.get("@noble/post-quantum"))
            .and_then(Value::as_str)
            .ok_or(VectorTestError::InvalidField)?,
        NOBLE_POST_QUANTUM_VERSION
    );
    assert_eq!(
        lock.get("packages")
            .and_then(|packages| packages.get(""))
            .and_then(|root| root.get("dependencies"))
            .and_then(|dependencies| dependencies.get("@noble/post-quantum"))
            .and_then(Value::as_str)
            .ok_or(VectorTestError::InvalidField)?,
        NOBLE_POST_QUANTUM_VERSION
    );
    assert_eq!(
        lock.get("packages")
            .and_then(|packages| packages.get("node_modules/@noble/post-quantum"))
            .and_then(|package| package.get("version"))
            .and_then(Value::as_str)
            .ok_or(VectorTestError::InvalidField)?,
        NOBLE_POST_QUANTUM_VERSION
    );
    assert_eq!(
        lock.get("packages")
            .and_then(|packages| packages.get("node_modules/@noble/post-quantum"))
            .and_then(|package| package.get("integrity"))
            .and_then(Value::as_str)
            .ok_or(VectorTestError::InvalidField)?,
        NOBLE_POST_QUANTUM_INTEGRITY
    );

    Ok(())
}

#[test]
fn manifest_is_crypto_only() -> Result<(), VectorTestError> {
    let manifest = load("manifest.json")?;
    let vectors = field_array(&manifest, "vectors")?;
    let negative_vectors = field_array(&manifest, "negative_vectors")?;

    assert!(vectors.contains(&Value::String("p256.json".to_owned())));
    assert!(vectors.contains(&Value::String("p384.json".to_owned())));
    assert!(vectors.contains(&Value::String("p521.json".to_owned())));
    assert!(vectors.contains(&Value::String("rsa.json".to_owned())));
    assert!(vectors.contains(&Value::String("bip340_schnorr.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes128gcm.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes192gcm.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes256gcm.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes256kw.json".to_owned())));
    assert!(vectors.contains(&Value::String("chacha20poly1305.json".to_owned())));
    assert!(vectors.contains(&Value::String("hmac.json".to_owned())));
    assert!(vectors.contains(&Value::String("concat_kdf.json".to_owned())));
    assert!(vectors.contains(&Value::String("pbkdf2.json".to_owned())));
    assert!(vectors.contains(&Value::String("ml_dsa_44.json".to_owned())));
    assert!(vectors.contains(&Value::String("ml_dsa_65.json".to_owned())));
    assert!(vectors.contains(&Value::String("ml_dsa_87.json".to_owned())));
    assert!(vectors.contains(&Value::String("slh_dsa_sha2_128s.json".to_owned())));
    assert!(vectors.contains(&Value::String("mlkem512.json".to_owned())));
    assert!(vectors.contains(&Value::String("mlkem768.json".to_owned())));
    assert!(vectors.contains(&Value::String("mlkem1024.json".to_owned())));
    assert!(vectors.contains(&Value::String("x_wing.json".to_owned())));
    assert!(vectors.contains(&Value::String("hashes.json".to_owned())));
    assert!(negative_vectors.contains(&Value::String("negative/fail_closed.json".to_owned())));
    assert!(!vectors.contains(&Value::String("didme-genesis.json".to_owned())));

    Ok(())
}

#[test]
fn shared_negative_vectors_pin_fail_closed_semantics() -> Result<(), VectorTestError> {
    let manifest = load("manifest.json")?;
    let positive_vectors: BTreeSet<&str> = field_array(&manifest, "vectors")?
        .iter()
        .map(|value| value.as_str().ok_or(VectorTestError::InvalidField))
        .collect::<Result<_, _>>()?;
    let negative_vectors = field_array(&manifest, "negative_vectors")?;
    let mut covered_algorithms = BTreeSet::new();

    for vector in negative_vectors {
        let path = vector.as_str().ok_or(VectorTestError::InvalidField)?;
        let file = load(path)?;
        assert_eq!(
            object_field(&file, "schemaVersion")?
                .as_u64()
                .ok_or(VectorTestError::InvalidField)?,
            1
        );
        for test_case in field_array(&file, "cases")? {
            let id = field_string(test_case, "id")?;
            let algorithm = field_string(test_case, "algorithm")?;
            let positive_vector = field_string(test_case, "positiveVector")?;
            assert!(
                positive_vectors.contains(positive_vector),
                "{id} references unknown positive vector {positive_vector}"
            );
            covered_algorithms.insert(algorithm.to_owned());

            let expected = object_field(test_case, "expected")?;
            assert!(
                ["primitive", "provider", "backend"]
                    .contains(&field_string(expected, "wireBranch")?),
                "{id} has an unknown wire branch"
            );
            assert!(
                field_string(expected, "reason")?.starts_with("CRYPTO_ERROR_REASON_"),
                "{id} must pin a protobuf CryptoErrorReason"
            );
            for lane in [
                "rust-native",
                "swift-native",
                "kotlin-jvm-native",
                "typescript-wasm",
            ] {
                assert!(
                    field_array(test_case, "lanes")?.contains(&Value::String(lane.to_owned())),
                    "{id} must declare {lane} coverage or guard"
                );
            }
        }
    }

    for algorithm in [
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
        "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
        "ML-KEM-768",
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
        "X-Wing-768",
        "AES-256-GCM",
    ] {
        assert!(
            covered_algorithms.contains(algorithm),
            "negative vectors must cover {algorithm}"
        );
    }

    Ok(())
}

#[test]
fn manifest_declares_cross_language_lanes() -> Result<(), VectorTestError> {
    let manifest = load("manifest.json")?;
    let lanes = field_array(&manifest, "runtime_lanes")?;

    for lane_name in [
        "rust-native",
        "rust-wasm",
        "typescript-native-noble",
        "swift-native",
        "kotlin-native-jvm",
    ] {
        let found = lanes.iter().any(|lane| {
            object_field(lane, "name")
                .and_then(|value| value.as_str().ok_or(VectorTestError::InvalidField))
                .map(|name| name == lane_name)
                .unwrap_or(false)
        });
        assert!(found, "manifest missing lane {lane_name}");
    }

    let kotlin_lane = lanes
        .iter()
        .find(|lane| {
            object_field(lane, "name")
                .and_then(|value| value.as_str().ok_or(VectorTestError::InvalidField))
                .map(|name| name == "kotlin-native-jvm")
                .unwrap_or(false)
        })
        .ok_or(VectorTestError::InvalidField)?;
    let kotlin_harness = object_field(kotlin_lane, "harness")?
        .as_str()
        .ok_or(VectorTestError::InvalidField)?;
    assert!(
        kotlin_harness.contains("--rerun-tasks"),
        "Kotlin conformance harness must force test execution"
    );

    Ok(())
}
