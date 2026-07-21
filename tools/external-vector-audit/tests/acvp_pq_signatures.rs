// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ACVP post-quantum signature audit adapters.

use crypto_ml_dsa_44::generate_ml_dsa_44_keypair_from_seed;
use crypto_ml_dsa_44::verify_ml_dsa_44;
use crypto_ml_dsa_65::generate_ml_dsa_65_keypair_from_seed;
use crypto_ml_dsa_65::verify_ml_dsa_65;
use crypto_ml_dsa_87::generate_ml_dsa_87_keypair_from_seed;
use crypto_ml_dsa_87::verify_ml_dsa_87;
use crypto_slh_dsa::verify_slh_dsa_sha2_128s;
use external_vector_audit::support::{
    assert_bytes_eq, hex_array, hex_bytes, load_json, AuditError,
};
use serde::Deserialize;

const PRACTICAL_SUBSET_PER_PARAMETER_SET: usize = 8;
const ML_DSA_PUBLIC_SIGVER_CASES: usize = 3;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaKeygenFile {
    test_groups: Vec<MlDsaKeygenGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaKeygenGroup {
    parameter_set: MlDsaParameterSet,
    tests: Vec<MlDsaKeygenCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaKeygenCase {
    seed: String,
    pk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaSigverFile {
    test_groups: Vec<MlDsaSigverGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaSigverGroup {
    parameter_set: MlDsaParameterSet,
    signature_interface: SignatureInterface,
    pre_hash: PreHashMode,
    external_mu: bool,
    tests: Vec<MlDsaSigverCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaSigverCase {
    test_passed: bool,
    pk: String,
    message: Option<String>,
    context: Option<String>,
    signature: String,
}

#[derive(Deserialize)]
enum MlDsaParameterSet {
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SlhDsaSigverFile {
    test_groups: Vec<SlhDsaSigverGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SlhDsaSigverGroup {
    parameter_set: SlhDsaParameterSet,
    signature_interface: SignatureInterface,
    pre_hash: PreHashMode,
    tests: Vec<SlhDsaSigverCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SlhDsaSigverCase {
    test_passed: bool,
    pk: String,
    message: String,
    context: Option<String>,
    signature: String,
}

#[derive(Deserialize)]
enum SlhDsaParameterSet {
    #[serde(rename = "SLH-DSA-SHA2-128s")]
    SlhDsaSha2_128s,
    #[serde(other)]
    Unsupported,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
enum SignatureInterface {
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "external")]
    External,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
enum PreHashMode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "pure")]
    Pure,
    #[serde(rename = "preHash")]
    PreHash,
}

#[test]
fn acvp_ml_dsa_keygen_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: MlDsaKeygenFile = load_json("nist-acvp/ml-dsa/keygen/internalProjection.json")?;
    let mut counts = MlDsaCounts::default();

    for group in &file.test_groups {
        for case in &group.tests {
            execute_ml_dsa_keygen_case(&group.parameter_set, case)?;
            counts.increment(&group.parameter_set)?;
            if counts.complete() {
                return Ok(());
            }
        }
    }

    counts.require_all()
}

#[test]
fn acvp_ml_dsa_sigver_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: MlDsaSigverFile = load_json("nist-acvp/ml-dsa/sigver/internalProjection.json")?;
    let mut counts = MlDsaSigverCounts::default();

    for group in &file.test_groups {
        if !group.matches_public_boundary() {
            continue;
        }
        for case in &group.tests {
            if !case.matches_public_boundary() {
                continue;
            }
            execute_ml_dsa_sigver_case(&group.parameter_set, case)?;
            counts.increment(&group.parameter_set, case.test_passed)?;
        }
    }

    counts.require_all()
}

#[test]
fn acvp_slh_dsa_sigver_vectors_record_current_public_boundary_status() -> Result<(), AuditError> {
    let file: SlhDsaSigverFile = load_json("nist-acvp/slh-dsa/sigver/internalProjection.json")?;
    let mut counts = SigverOutcomeCounts::default();

    for group in &file.test_groups {
        if !group.matches_public_boundary() {
            continue;
        }
        for case in &group.tests {
            if !case.matches_public_boundary() {
                continue;
            }
            execute_slh_dsa_sigver_case(case)?;
            counts.increment(case.test_passed)?;
        }
    }

    counts.require_rejected_only()
}

fn execute_ml_dsa_keygen_case(
    parameter_set: &MlDsaParameterSet,
    case: &MlDsaKeygenCase,
) -> Result<(), AuditError> {
    let seed = hex_array::<32>(&case.seed)?;
    let expected_public_key = hex_bytes(&case.pk)?;
    let actual_public_key = match parameter_set {
        MlDsaParameterSet::MlDsa44 => {
            generate_ml_dsa_44_keypair_from_seed(&seed).map_err(|_| AuditError::Mismatch)?
        }
        MlDsaParameterSet::MlDsa65 => {
            generate_ml_dsa_65_keypair_from_seed(&seed).map_err(|_| AuditError::Mismatch)?
        }
        MlDsaParameterSet::MlDsa87 => {
            generate_ml_dsa_87_keypair_from_seed(&seed).map_err(|_| AuditError::Mismatch)?
        }
    }
    .0;
    assert_bytes_eq(&actual_public_key, &expected_public_key)
}

fn execute_ml_dsa_sigver_case(
    parameter_set: &MlDsaParameterSet,
    case: &MlDsaSigverCase,
) -> Result<(), AuditError> {
    if case
        .context
        .as_ref()
        .is_some_and(|context| !context.is_empty())
    {
        return Err(AuditError::UnsupportedBoundary);
    }
    let public_key = hex_bytes(&case.pk)?;
    let message = hex_bytes(case.message.as_ref().ok_or(AuditError::Shape)?)?;
    let signature = hex_bytes(&case.signature)?;
    let actual = match parameter_set {
        MlDsaParameterSet::MlDsa44 => verify_ml_dsa_44(&public_key, &message, &signature),
        MlDsaParameterSet::MlDsa65 => verify_ml_dsa_65(&public_key, &message, &signature),
        MlDsaParameterSet::MlDsa87 => verify_ml_dsa_87(&public_key, &message, &signature),
    };
    assert_signature_result(case.test_passed, actual)
}

fn execute_slh_dsa_sigver_case(case: &SlhDsaSigverCase) -> Result<(), AuditError> {
    if case
        .context
        .as_ref()
        .is_some_and(|context| !context.is_empty())
    {
        return Err(AuditError::UnsupportedBoundary);
    }
    let public_key = hex_bytes(&case.pk)?;
    let message = hex_bytes(&case.message)?;
    let signature = hex_bytes(&case.signature)?;
    assert_signature_result(
        case.test_passed,
        verify_slh_dsa_sha2_128s(&public_key, &message, &signature),
    )
}

fn assert_signature_result(
    expected_pass: bool,
    actual: Result<(), crypto_core::CryptoError>,
) -> Result<(), AuditError> {
    match (expected_pass, actual.is_ok()) {
        (true, true) | (false, false) => Ok(()),
        _ => Err(AuditError::Mismatch),
    }
}

impl MlDsaSigverGroup {
    fn matches_public_boundary(&self) -> bool {
        self.signature_interface == SignatureInterface::External
            && self.pre_hash == PreHashMode::Pure
            && !self.external_mu
    }
}

impl MlDsaSigverCase {
    fn matches_public_boundary(&self) -> bool {
        self.context.as_ref().is_none_or(String::is_empty) && self.message.is_some()
    }
}

impl SlhDsaSigverGroup {
    fn matches_public_boundary(&self) -> bool {
        matches!(self.parameter_set, SlhDsaParameterSet::SlhDsaSha2_128s)
            && self.signature_interface == SignatureInterface::External
            && self.pre_hash == PreHashMode::Pure
    }
}

impl SlhDsaSigverCase {
    fn matches_public_boundary(&self) -> bool {
        self.context.as_ref().is_none_or(String::is_empty)
    }
}

#[derive(Default)]
struct MlDsaCounts {
    ml_dsa_44: usize,
    ml_dsa_65: usize,
    ml_dsa_87: usize,
}

impl MlDsaCounts {
    fn increment(&mut self, parameter_set: &MlDsaParameterSet) -> Result<(), AuditError> {
        let count = match parameter_set {
            MlDsaParameterSet::MlDsa44 => &mut self.ml_dsa_44,
            MlDsaParameterSet::MlDsa65 => &mut self.ml_dsa_65,
            MlDsaParameterSet::MlDsa87 => &mut self.ml_dsa_87,
        };
        *count = count
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.ml_dsa_44 >= PRACTICAL_SUBSET_PER_PARAMETER_SET
            && self.ml_dsa_65 >= PRACTICAL_SUBSET_PER_PARAMETER_SET
            && self.ml_dsa_87 >= PRACTICAL_SUBSET_PER_PARAMETER_SET
    }

    fn require_all(&self) -> Result<(), AuditError> {
        if self.ml_dsa_44 > 0 && self.ml_dsa_65 > 0 && self.ml_dsa_87 > 0 {
            Ok(())
        } else {
            Err(AuditError::NoExecutableVectors)
        }
    }
}

#[derive(Default)]
struct MlDsaSigverCounts {
    ml_dsa_44: bool,
    ml_dsa_65: bool,
    ml_dsa_87: bool,
    outcomes: SigverOutcomeCounts,
}

impl MlDsaSigverCounts {
    fn increment(
        &mut self,
        parameter_set: &MlDsaParameterSet,
        expected_pass: bool,
    ) -> Result<(), AuditError> {
        match parameter_set {
            MlDsaParameterSet::MlDsa44 => self.ml_dsa_44 = true,
            MlDsaParameterSet::MlDsa65 => self.ml_dsa_65 = true,
            MlDsaParameterSet::MlDsa87 => self.ml_dsa_87 = true,
        };
        self.outcomes.increment(expected_pass)
    }

    fn require_all(&self) -> Result<(), AuditError> {
        if self.ml_dsa_44 && self.ml_dsa_65 && self.ml_dsa_87 {
            self.outcomes.require_minimum(ML_DSA_PUBLIC_SIGVER_CASES)
        } else {
            Err(AuditError::NoExecutableVectors)
        }
    }
}

#[derive(Default)]
struct SigverOutcomeCounts {
    passed: usize,
    rejected: usize,
}

impl SigverOutcomeCounts {
    fn increment(&mut self, expected_pass: bool) -> Result<(), AuditError> {
        let count = if expected_pass {
            &mut self.passed
        } else {
            &mut self.rejected
        };
        *count = count
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
        Ok(())
    }

    fn require_minimum(&self, minimum: usize) -> Result<(), AuditError> {
        let total = self
            .passed
            .checked_add(self.rejected)
            .ok_or(AuditError::NoExecutableVectors)?;
        if total >= minimum && self.passed > 0 && self.rejected > 0 {
            Ok(())
        } else {
            Err(AuditError::NoExecutableVectors)
        }
    }

    fn require_rejected_only(&self) -> Result<(), AuditError> {
        if self.passed == 0 && self.rejected > 0 {
            Ok(())
        } else {
            Err(AuditError::NoExecutableVectors)
        }
    }
}
