// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! CCTV ML-DSA accumulated and benchmark vectors.

use external_vector_audit::support::{
    assert_bytes_eq, hex_bytes, load_json, load_text, AuditError,
};
use shake::{ExtendableOutput, Shake128, Update, XofReader};

use crypto_ml_dsa_44::{generate_ml_dsa_44_keypair_from_seed, sign_ml_dsa_44, verify_ml_dsa_44};
use crypto_ml_dsa_65::{generate_ml_dsa_65_keypair_from_seed, sign_ml_dsa_65, verify_ml_dsa_65};
use crypto_ml_dsa_87::{generate_ml_dsa_87_keypair_from_seed, sign_ml_dsa_87, verify_ml_dsa_87};

const ACCUMULATED_100_ITERATIONS: usize = 100;
const ACCUMULATED_10K_ITERATIONS: usize = 10_000;
const BENCHMARK_SUBSET_PER_FILE: usize = 8;

#[derive(Clone, Copy)]
enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaParameterSet {
    fn label(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    fn expected_100_hash(self) -> &'static str {
        match self {
            Self::MlDsa44 => "d51148e1f9f4fa1a723a6cf42e25f2a99eb5c1b378b3d2dbbd561b1203beeae4",
            Self::MlDsa65 => "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199",
            Self::MlDsa87 => "8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b",
        }
    }

    fn expected_10k_hash(self) -> &'static str {
        match self {
            Self::MlDsa44 => "e7fd21f6a59bcba60d65adc44404bb29a7c00e5d8d3ec06a732c00a306a7d143",
            Self::MlDsa65 => "5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329",
            Self::MlDsa87 => "80a8cf39317f7d0be0e24972c51ac152bd2a3e09bc0c32ce29dd82c4e7385e60",
        }
    }
}

const PARAMETER_SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];

#[test]
fn cctv_ml_dsa_accumulated_100_vectors_match_public_api() -> Result<(), AuditError> {
    assert_accumulated_readme()?;

    for parameter_set in PARAMETER_SETS {
        let actual = accumulated_hash(parameter_set, ACCUMULATED_100_ITERATIONS)?;
        let expected = hex_bytes(parameter_set.expected_100_hash())?;
        assert_bytes_eq(&actual, &expected)?;
    }

    Ok(())
}

#[test]
#[ignore = "10,000-iteration CCTV ML-DSA accumulated audit; run deliberately outside fast loops"]
fn cctv_ml_dsa_accumulated_10k_vectors_match_public_api() -> Result<(), AuditError> {
    assert_accumulated_readme()?;

    for parameter_set in PARAMETER_SETS {
        let actual = accumulated_hash(parameter_set, ACCUMULATED_10K_ITERATIONS)?;
        let expected = hex_bytes(parameter_set.expected_10k_hash())?;
        assert_bytes_eq(&actual, &expected)?;
    }

    Ok(())
}

#[test]
fn cctv_ml_dsa_benchmark_messages_sign_and_verify() -> Result<(), AuditError> {
    let readme = load_text("cctv/ml-dsa/benchmark/README.md")?;
    if !readme.contains("ML-DSA signing benchmark targets") {
        return Err(AuditError::Shape);
    }

    for parameter_set in PARAMETER_SETS {
        exercise_benchmark_file(parameter_set, false)?;
        exercise_benchmark_file(parameter_set, true)?;
    }

    Ok(())
}

fn assert_accumulated_readme() -> Result<(), AuditError> {
    let readme = load_text("cctv/ml-dsa/accumulated/README.md")?;
    if readme.contains("Accumulated ML-DSA tests") && readme.contains("10 000 iterations") {
        Ok(())
    } else {
        Err(AuditError::Shape)
    }
}

fn accumulated_hash(
    parameter_set: MlDsaParameterSet,
    iterations: usize,
) -> Result<[u8; 32], AuditError> {
    let mut seed_reader = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();
    let message = [];

    for _ in 0..iterations {
        let mut seed = [0u8; 32];
        seed_reader.read(&mut seed);
        let public_key = generate_keypair(parameter_set, &seed)?;
        accumulator.update(&public_key);
        let signature = sign(parameter_set, &seed, &message)?;
        accumulator.update(&signature);
        verify(parameter_set, &public_key, &message, &signature)?;
    }

    let mut out = [0u8; 32];
    accumulator.finalize_xof().read(&mut out);
    Ok(out)
}

fn exercise_benchmark_file(
    parameter_set: MlDsaParameterSet,
    alternate: bool,
) -> Result<(), AuditError> {
    let suffix = if alternate { ".alt" } else { "" };
    let path = format!(
        "cctv/ml-dsa/benchmark/{}{}.json",
        parameter_set.label(),
        suffix
    );
    let messages: Vec<String> = load_json(&path)?;
    let seed = [0u8; 32];
    let public_key = generate_keypair(parameter_set, &seed)?;
    let mut executed = 0usize;

    for message in messages.iter().take(BENCHMARK_SUBSET_PER_FILE) {
        let signature = sign(parameter_set, &seed, message.as_bytes())?;
        verify(parameter_set, &public_key, message.as_bytes(), &signature)?;
        executed = executed
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }

    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

fn generate_keypair(
    parameter_set: MlDsaParameterSet,
    seed: &[u8; 32],
) -> Result<Vec<u8>, AuditError> {
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => generate_ml_dsa_44_keypair_from_seed(seed)
            .map(|(public_key, _secret_key)| public_key)
            .map_err(|_| AuditError::Mismatch),
        MlDsaParameterSet::MlDsa65 => generate_ml_dsa_65_keypair_from_seed(seed)
            .map(|(public_key, _secret_key)| public_key)
            .map_err(|_| AuditError::Mismatch),
        MlDsaParameterSet::MlDsa87 => generate_ml_dsa_87_keypair_from_seed(seed)
            .map(|(public_key, _secret_key)| public_key)
            .map_err(|_| AuditError::Mismatch),
    }
}

fn sign(
    parameter_set: MlDsaParameterSet,
    seed: &[u8; 32],
    message: &[u8],
) -> Result<Vec<u8>, AuditError> {
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => {
            sign_ml_dsa_44(seed, message).map_err(|_| AuditError::Mismatch)
        }
        MlDsaParameterSet::MlDsa65 => {
            sign_ml_dsa_65(seed, message).map_err(|_| AuditError::Mismatch)
        }
        MlDsaParameterSet::MlDsa87 => {
            sign_ml_dsa_87(seed, message).map_err(|_| AuditError::Mismatch)
        }
    }
}

fn verify(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), AuditError> {
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => {
            verify_ml_dsa_44(public_key, message, signature).map_err(|_| AuditError::Mismatch)
        }
        MlDsaParameterSet::MlDsa65 => {
            verify_ml_dsa_65(public_key, message, signature).map_err(|_| AuditError::Mismatch)
        }
        MlDsaParameterSet::MlDsa87 => {
            verify_ml_dsa_87(public_key, message, signature).map_err(|_| AuditError::Mismatch)
        }
    }
}
