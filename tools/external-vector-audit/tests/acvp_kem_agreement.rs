// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ACVP key-agreement and KEM audit adapters.

use crypto_ml_kem_1024::{generate_ml_kem_1024_keypair_from_seed, ml_kem_1024_encapsulate_derand};
use crypto_ml_kem_512::{generate_ml_kem_512_keypair_from_seed, ml_kem_512_encapsulate_derand};
use crypto_ml_kem_768::{generate_ml_kem_768_keypair_from_seed, ml_kem_768_encapsulate_derand};
use crypto_x25519::derive_x25519_shared_secret;
use external_vector_audit::support::{
    assert_bytes_eq, hex_array, hex_bytes, load_json, AuditError,
};
use serde::Deserialize;

const PRACTICAL_SUBSET_PER_PARAMETER_SET: usize = 8;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemKeygenFile {
    test_groups: Vec<MlKemKeygenGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemKeygenGroup {
    parameter_set: MlKemParameterSet,
    tests: Vec<MlKemKeygenCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemKeygenCase {
    d: String,
    z: String,
    ek: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemEncapFile {
    test_groups: Vec<MlKemEncapGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemEncapGroup {
    function: MlKemFunction,
    parameter_set: MlKemParameterSet,
    tests: Vec<MlKemEncapCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemEncapCase {
    ek: String,
    c: Option<String>,
    k: Option<String>,
    m: Option<String>,
}

#[derive(Deserialize)]
enum MlKemFunction {
    #[serde(rename = "encapsulation")]
    Encapsulation,
    #[serde(other)]
    Other,
}

#[derive(Deserialize, Clone, Copy)]
enum MlKemParameterSet {
    #[serde(rename = "ML-KEM-512")]
    MlKem512,
    #[serde(rename = "ML-KEM-768")]
    MlKem768,
    #[serde(rename = "ML-KEM-1024")]
    MlKem1024,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XecdhFile {
    test_groups: Vec<XecdhGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XecdhGroup {
    curve: String,
    tests: Vec<XecdhCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XecdhCase {
    test_passed: bool,
    private_server: String,
    public_server: String,
    private_iut: String,
    public_iut: String,
    z: String,
}

#[test]
fn acvp_x25519_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: XecdhFile = load_json("nist-acvp/agreement/xecdh-ssc/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.curve != "Curve25519" {
            continue;
        }
        for case in &group.tests {
            if !case.test_passed {
                continue;
            }
            let expected = hex_bytes(&case.z)?;
            let iut_secret = hex_bytes(&case.private_iut)?;
            let server_public = hex_bytes(&case.public_server)?;
            let actual = derive_x25519_shared_secret(&iut_secret, &server_public)
                .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_slice(), &expected)?;

            let server_secret = hex_bytes(&case.private_server)?;
            let iut_public = hex_bytes(&case.public_iut)?;
            let actual = derive_x25519_shared_secret(&server_secret, &iut_public)
                .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(actual.as_slice(), &expected)?;

            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
            if executed >= PRACTICAL_SUBSET_PER_PARAMETER_SET {
                return Ok(());
            }
        }
    }

    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

#[test]
fn acvp_ml_kem_keygen_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: MlKemKeygenFile = load_json("nist-acvp/ml-kem/keygen/internalProjection.json")?;
    let mut counts = MlKemCounts::default();

    for group in &file.test_groups {
        for case in &group.tests {
            execute_ml_kem_keygen_case(group.parameter_set, case)?;
            counts.increment(group.parameter_set)?;
            if counts.complete() {
                return Ok(());
            }
        }
    }

    counts.require_all()
}

#[test]
fn acvp_ml_kem_encapsulation_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: MlKemEncapFile = load_json("nist-acvp/ml-kem/encap-decap/internalProjection.json")?;
    let mut counts = MlKemCounts::default();

    for group in &file.test_groups {
        if !matches!(group.function, MlKemFunction::Encapsulation) {
            continue;
        }
        for case in &group.tests {
            execute_ml_kem_encapsulation_case(group.parameter_set, case)?;
            counts.increment(group.parameter_set)?;
            if counts.complete() {
                return Ok(());
            }
        }
    }

    counts.require_all()
}

fn execute_ml_kem_keygen_case(
    parameter_set: MlKemParameterSet,
    case: &MlKemKeygenCase,
) -> Result<(), AuditError> {
    let seed = ml_kem_seed(&case.d, &case.z)?;
    let expected_ek = hex_bytes(&case.ek)?;
    let actual_ek = match parameter_set {
        MlKemParameterSet::MlKem512 => {
            generate_ml_kem_512_keypair_from_seed(&seed)
                .map_err(|_| AuditError::Mismatch)?
                .0
        }
        MlKemParameterSet::MlKem768 => {
            generate_ml_kem_768_keypair_from_seed(&seed)
                .map_err(|_| AuditError::Mismatch)?
                .0
        }
        MlKemParameterSet::MlKem1024 => {
            generate_ml_kem_1024_keypair_from_seed(&seed)
                .map_err(|_| AuditError::Mismatch)?
                .0
        }
    };
    assert_bytes_eq(&actual_ek, &expected_ek)
}

fn execute_ml_kem_encapsulation_case(
    parameter_set: MlKemParameterSet,
    case: &MlKemEncapCase,
) -> Result<(), AuditError> {
    let ek = hex_bytes(&case.ek)?;
    let m = hex_bytes(case.m.as_ref().ok_or(AuditError::Shape)?)?;
    let expected_c = hex_bytes(case.c.as_ref().ok_or(AuditError::Shape)?)?;
    let expected_k = hex_bytes(case.k.as_ref().ok_or(AuditError::Shape)?)?;
    let (actual_c, actual_k) = ml_kem_encapsulate_derand(parameter_set, &ek, &m)?;
    assert_bytes_eq(&actual_c, &expected_c)?;
    assert_bytes_eq(actual_k.as_slice(), &expected_k)
}

fn ml_kem_seed(d: &str, z: &str) -> Result<[u8; 64], AuditError> {
    let d = hex_array::<32>(d)?;
    let z = hex_array::<32>(z)?;
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&d);
    seed[32..].copy_from_slice(&z);
    Ok(seed)
}

fn ml_kem_encapsulate_derand(
    parameter_set: MlKemParameterSet,
    ek: &[u8],
    m: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AuditError> {
    match parameter_set {
        MlKemParameterSet::MlKem512 => ml_kem_512_encapsulate_derand(ek, m)
            .map(|(ciphertext, shared_secret)| (ciphertext, shared_secret.to_vec()))
            .map_err(|_| AuditError::Mismatch),
        MlKemParameterSet::MlKem768 => ml_kem_768_encapsulate_derand(ek, m)
            .map(|(ciphertext, shared_secret)| (ciphertext, shared_secret.to_vec()))
            .map_err(|_| AuditError::Mismatch),
        MlKemParameterSet::MlKem1024 => ml_kem_1024_encapsulate_derand(ek, m)
            .map(|(ciphertext, shared_secret)| (ciphertext, shared_secret.to_vec()))
            .map_err(|_| AuditError::Mismatch),
    }
}

#[derive(Default)]
struct MlKemCounts {
    ml_kem_512: usize,
    ml_kem_768: usize,
    ml_kem_1024: usize,
}

impl MlKemCounts {
    fn increment(&mut self, parameter_set: MlKemParameterSet) -> Result<(), AuditError> {
        let count = match parameter_set {
            MlKemParameterSet::MlKem512 => &mut self.ml_kem_512,
            MlKemParameterSet::MlKem768 => &mut self.ml_kem_768,
            MlKemParameterSet::MlKem1024 => &mut self.ml_kem_1024,
        };
        *count = count
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.ml_kem_512 >= PRACTICAL_SUBSET_PER_PARAMETER_SET
            && self.ml_kem_768 >= PRACTICAL_SUBSET_PER_PARAMETER_SET
            && self.ml_kem_1024 >= PRACTICAL_SUBSET_PER_PARAMETER_SET
    }

    fn require_all(&self) -> Result<(), AuditError> {
        if self.ml_kem_512 > 0 && self.ml_kem_768 > 0 && self.ml_kem_1024 > 0 {
            Ok(())
        } else {
            Err(AuditError::NoExecutableVectors)
        }
    }
}
