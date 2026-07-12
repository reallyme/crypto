// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::support::{field_array, load, load_package_json, object_field, VectorTestError};

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
    assert!(vectors.contains(&Value::String("codecs.json".to_owned())));
    assert!(!vectors.contains(&Value::String("didme-genesis.json".to_owned())));

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
