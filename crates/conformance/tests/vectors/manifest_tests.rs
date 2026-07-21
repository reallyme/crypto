// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::Enumeration;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoErrorReason,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::support::{
    b64u_to_bytes, field_array, field_string, load, load_package_json, object_field,
    read_repo_file, VectorTestError,
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
    let lifecycle_vectors = field_array(&manifest, "lifecycle_vectors")?;

    assert!(vectors.contains(&Value::String("p256.json".to_owned())));
    assert!(vectors.contains(&Value::String("p384.json".to_owned())));
    assert!(vectors.contains(&Value::String("p521.json".to_owned())));
    assert!(vectors.contains(&Value::String("ed25519.json".to_owned())));
    assert!(vectors.contains(&Value::String("secp256k1.json".to_owned())));
    assert!(vectors.contains(&Value::String("rsa.json".to_owned())));
    assert!(vectors.contains(&Value::String("x25519.json".to_owned())));
    assert!(vectors.contains(&Value::String("bip340_schnorr.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes128gcm.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes192gcm.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes256gcm.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes256gcmsiv.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes128kw.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes192kw.json".to_owned())));
    assert!(vectors.contains(&Value::String("aes256kw.json".to_owned())));
    assert!(vectors.contains(&Value::String("argon2id.json".to_owned())));
    assert!(vectors.contains(&Value::String("kmac256.json".to_owned())));
    assert!(vectors.contains(&Value::String("chacha20poly1305.json".to_owned())));
    assert!(vectors.contains(&Value::String("hkdf.json".to_owned())));
    assert!(vectors.contains(&Value::String("hkdf_sha384.json".to_owned())));
    assert!(vectors.contains(&Value::String("hpke.json".to_owned())));
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
    assert!(vectors.contains(&Value::String("operation_response.json".to_owned())));
    assert!(vectors.contains(&Value::String("jwk.json".to_owned())));
    assert!(negative_vectors.contains(&Value::String("negative/fail_closed.json".to_owned())));
    assert!(lifecycle_vectors.contains(&Value::String("platform_key_lifecycle.json".to_owned())));
    assert!(!vectors.contains(&Value::String("didme-genesis.json".to_owned())));

    Ok(())
}

#[test]
fn operation_response_vector_has_an_independent_semantic_oracle() -> Result<(), VectorTestError> {
    const SHA2_256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    let vector = load("operation_response.json")?;
    assert_eq!(
        object_field(&vector, "schema_version")?
            .as_u64()
            .ok_or(VectorTestError::InvalidField)?,
        1
    );

    let response_bytes = b64u_to_bytes(field_string(&vector, "operation_response")?)?;
    let response =
        decode_operation_response(&response_bytes).map_err(|_| VectorTestError::InvalidField)?;
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        return Err(VectorTestError::InvalidField);
    };
    let Some(CryptoOperationResultBranch::Hash(hash_result)) = result.result else {
        return Err(VectorTestError::InvalidField);
    };
    assert_eq!(hash_result.digest, SHA2_256_ABC);

    for (field, expected_reason) in [
        (
            "malformed_protobuf_response",
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
        ),
        (
            "malformed_json_response",
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
        ),
    ] {
        let response_bytes = b64u_to_bytes(field_string(&vector, field)?)?;
        let response = decode_operation_response(&response_bytes)
            .map_err(|_| VectorTestError::InvalidField)?;
        let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
            return Err(VectorTestError::InvalidField);
        };
        let Some(CryptoErrorBranch::Primitive(primitive)) = error.error else {
            return Err(VectorTestError::InvalidField);
        };
        assert_eq!(primitive.reason.as_known(), Some(expected_reason));
    }

    Ok(())
}

#[test]
fn shared_negative_vectors_pin_fail_closed_semantics() -> Result<(), VectorTestError> {
    let manifest = load("manifest.json")?;
    let positive_vectors: BTreeSet<&str> = field_array(&manifest, "vectors")?
        .iter()
        .map(|value| value.as_str().ok_or(VectorTestError::InvalidField))
        .collect::<Result<_, _>>()?;
    let lifecycle_vectors: BTreeSet<&str> = field_array(&manifest, "lifecycle_vectors")?
        .iter()
        .map(|value| value.as_str().ok_or(VectorTestError::InvalidField))
        .collect::<Result<_, _>>()?;
    let negative_vectors = field_array(&manifest, "negative_vectors")?;
    let mut covered_algorithms = BTreeSet::new();
    let mut covered_operations = BTreeSet::new();

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
                positive_vectors.contains(positive_vector)
                    || lifecycle_vectors.contains(positive_vector),
                "{id} references unknown positive vector {positive_vector}"
            );
            covered_algorithms.insert(algorithm.to_owned());
            covered_operations.insert(field_string(test_case, "operation")?.to_owned());

            let expected = object_field(test_case, "expected")?;
            let reason = field_string(expected, "reason")?;
            assert!(
                ["primitive", "provider", "backend"]
                    .contains(&field_string(expected, "wireBranch")?),
                "{id} has an unknown wire branch"
            );
            assert!(
                CryptoErrorReason::from_proto_name(reason).is_some(),
                "{id} must pin an existing protobuf CryptoErrorReason"
            );
            let expected_reason_prefix = match field_string(expected, "wireBranch")? {
                "primitive" => "CRYPTO_ERROR_REASON_PRIMITIVE_",
                "provider" => "CRYPTO_ERROR_REASON_PROVIDER_",
                "backend" => "CRYPTO_ERROR_REASON_BACKEND_",
                _ => return Err(VectorTestError::InvalidField),
            };
            assert!(
                reason.starts_with(expected_reason_prefix),
                "{id} reason must belong to its declared wire branch"
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
        "AES-256-KW",
        "X25519",
        "PBKDF2-HMAC-SHA-256",
        "RSA-PSS-SHA256-MGF1-SHA256",
        "P-256 platform key",
    ] {
        assert!(
            covered_algorithms.contains(algorithm),
            "negative vectors must cover {algorithm}"
        );
    }

    for operation in [
        "aead_open",
        "hpke_open",
        "jwk_import",
        "kdf_derive",
        "kem_decapsulate",
        "key_agreement_derive_shared_secret",
        "key_unwrap",
        "platform_key_lifecycle",
        "signature_verify",
    ] {
        assert!(
            covered_operations.contains(operation),
            "negative vectors must cover {operation}"
        );
    }

    Ok(())
}

#[test]
fn platform_key_lifecycle_vectors_pin_hardware_provider_policy() -> Result<(), VectorTestError> {
    let manifest = load("manifest.json")?;
    let lifecycle_vectors = field_array(&manifest, "lifecycle_vectors")?;
    assert_eq!(
        lifecycle_vectors.len(),
        1,
        "manifest should keep one platform lifecycle vector inventory"
    );
    assert!(
        lifecycle_vectors.contains(&Value::String("platform_key_lifecycle.json".to_owned())),
        "manifest must reference platform_key_lifecycle.json"
    );

    let vectors = load("platform_key_lifecycle.json")?;
    assert_eq!(
        object_field(&vectors, "schemaVersion")?
            .as_u64()
            .ok_or(VectorTestError::InvalidField)?,
        1
    );

    let mut ids = BTreeSet::new();
    for test_case in field_array(&vectors, "cases")? {
        let id = field_string(test_case, "id")?;
        assert!(
            ids.insert(id.to_owned()),
            "duplicate lifecycle vector id {id}"
        );
        let handle_prefix = field_string(test_case, "handlePrefix")?;
        assert!(
            ["SE:", "SES:", "RMAK"].contains(&handle_prefix),
            "{id} must use an approved platform-key handle prefix"
        );
        let tag_length = object_field(test_case, "tagLength")?;
        assert_eq!(
            object_field(tag_length, "min")?
                .as_u64()
                .ok_or(VectorTestError::InvalidField)?,
            1,
            "{id} must reject empty platform-key tags"
        );
        assert_eq!(
            object_field(tag_length, "max")?
                .as_u64()
                .ok_or(VectorTestError::InvalidField)?,
            256,
            "{id} must cap platform-key tags"
        );
        let expected = object_field(test_case, "expected")?;
        match field_string(expected, "outcome")? {
            "success" => assert!(
                !field_array(expected, "assertions")?.is_empty(),
                "{id} success lifecycle vectors must state observable assertions"
            ),
            "error" => {
                assert_eq!(
                    field_string(expected, "wireBranch")?,
                    "provider",
                    "{id} must use provider lifecycle error reasons"
                );
                let reason = field_string(expected, "reason")?;
                assert!(
                    reason.starts_with("CRYPTO_ERROR_REASON_PROVIDER_")
                        && CryptoErrorReason::from_proto_name(reason).is_some(),
                    "{id} must pin an existing provider CryptoErrorReason"
                );
            }
            _ => return Err(VectorTestError::InvalidField),
        }

        let evidence = object_field(test_case, "evidence")?;
        let evidence_path = field_string(evidence, "path")?;
        let evidence_test = field_string(evidence, "test")?;
        assert!(
            read_repo_file(evidence_path)?.contains(evidence_test),
            "{id} references missing lifecycle evidence {evidence_path}:{evidence_test}"
        );
        let lanes = object_field(test_case, "lanes")?
            .as_object()
            .ok_or(VectorTestError::InvalidField)?;
        assert_eq!(lanes.len(), 4, "{id} must classify exactly four SDK lanes");
        for lane in ["swift", "kotlin_android", "kotlin_jvm", "typescript_wasm"] {
            let status = lanes
                .get(lane)
                .and_then(Value::as_str)
                .ok_or(VectorTestError::InvalidField)?;
            assert!(
                ["executable", "hardware-skip-aware", "unsupported"].contains(&status),
                "{id} has invalid {lane} lifecycle status {status}"
            );
        }
    }

    for required in [
        "swift-secure-enclave-ecdh-handle-validation",
        "swift-secure-enclave-ecdh-round-trip",
        "swift-secure-enclave-ecdh-duplicate-tag",
        "swift-secure-enclave-ecdh-idempotent-delete",
        "swift-secure-enclave-signing-handle-validation",
        "swift-secure-enclave-signing-verifier",
        "swift-secure-enclave-signing-round-trip",
        "swift-secure-enclave-signing-duplicate-tag",
        "android-strongbox-signing-round-trip",
    ] {
        assert!(
            ids.contains(required),
            "platform-key lifecycle vectors must cover {required}"
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

    for lane in lanes {
        let lane_name = field_string(lane, "name")?;
        let algorithms = field_array(lane, "algorithms")?;
        for algorithm in ["HMAC-SHA-384", "HKDF-SHA256", "HKDF-SHA384"] {
            assert!(
                algorithms.contains(&Value::String(algorithm.to_owned())),
                "manifest lane {lane_name} must cover {algorithm}"
            );
        }
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
