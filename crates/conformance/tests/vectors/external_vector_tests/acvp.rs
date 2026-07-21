// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::external_vector_tests::provenance;
use crate::support::{field_array, field_string, object_field, VectorTestError};

#[test]
fn representative_acvp_vectors_parse() -> Result<(), VectorTestError> {
    assert_acvp_json_shape(
        "nist-acvp/aead/aes-gcm/internalProjection.json",
        "ACVP-AES-GCM",
    )?;
    assert_acvp_json_shape("nist-acvp/ml-kem/keygen/internalProjection.json", "ML-KEM")?;
    assert_acvp_json_shape(
        "nist-acvp/signature/eddsa-sigver/internalProjection.json",
        "EDDSA",
    )?;

    Ok(())
}

#[test]
fn acvp_ml_kem_sample_contains_all_parameter_sets() -> Result<(), VectorTestError> {
    let value = crate::support::load_external("nist-acvp/ml-kem/keygen/internalProjection.json")?;
    let groups = field_array(&value, "testGroups")?;

    for parameter_set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        assert!(
            groups.iter().any(|group| {
                group
                    .get("parameterSet")
                    .and_then(Value::as_str)
                    .is_some_and(|candidate| candidate == parameter_set)
            }),
            "{parameter_set}"
        );
    }

    Ok(())
}

#[test]
#[ignore = "full ACVP corpus parse sweep; run deliberately when auditing vendored vectors"]
fn all_vendored_acvp_json_files_parse() -> Result<(), VectorTestError> {
    let value = provenance::provenance()?;

    for entry in provenance::file_entries(&value)? {
        if field_string(entry, "source_id")? != "nist-acvp" {
            continue;
        }
        if field_string(entry, "format")? != "json" {
            continue;
        }

        let local_path = field_string(entry, "local_path")?;
        let json = crate::support::load_external(local_path)?;
        assert!(
            json.get("testGroups").is_some(),
            "ACVP file has no testGroups: {local_path}"
        );
    }

    Ok(())
}

fn assert_acvp_json_shape(
    local_path: &str,
    expected_algorithm: &str,
) -> Result<(), VectorTestError> {
    let value = crate::support::load_external(local_path)?;
    assert_eq!(field_string(&value, "algorithm")?, expected_algorithm);
    object_field(&value, "vsId")?;

    let groups = field_array(&value, "testGroups")?;
    assert!(!groups.is_empty(), "{local_path}");
    for group in groups.iter().take(2) {
        let tests = field_array(group, "tests")?;
        assert!(!tests.is_empty(), "{local_path}");
    }

    Ok(())
}
