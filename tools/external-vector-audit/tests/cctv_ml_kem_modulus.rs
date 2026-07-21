// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! CCTV ML-KEM modulus-check vectors for invalid encapsulation keys.

#[path = "support/cctv_ml_kem.rs"]
mod cctv_ml_kem;

use cctv_ml_kem::{load_modulus_public_keys, MlKemParameterSet, ALL_PARAMETER_SETS};
use crypto_core::CryptoError;
use crypto_ml_kem_1024::ml_kem_1024_encapsulate;
use crypto_ml_kem_512::ml_kem_512_encapsulate;
use crypto_ml_kem_768::ml_kem_768_encapsulate;
use external_vector_audit::support::AuditError;

const PRACTICAL_SUBSET_PER_PARAMETER_SET: usize = 8;

#[test]
fn cctv_ml_kem_modulus_vectors_reject_invalid_public_keys() -> Result<(), AuditError> {
    for parameter_set in ALL_PARAMETER_SETS {
        let public_keys =
            load_modulus_public_keys(parameter_set, PRACTICAL_SUBSET_PER_PARAMETER_SET)?;
        for public_key in &public_keys {
            assert_invalid_encapsulation_key(parameter_set, public_key)?;
        }
    }

    Ok(())
}

#[test]
#[ignore = "full CCTV modulus corpus; run deliberately for periodic adversarial ML-KEM audits"]
fn all_cctv_ml_kem_modulus_vectors_reject_invalid_public_keys() -> Result<(), AuditError> {
    for parameter_set in ALL_PARAMETER_SETS {
        let public_keys = load_modulus_public_keys(parameter_set, usize::MAX)?;
        for public_key in &public_keys {
            assert_invalid_encapsulation_key(parameter_set, public_key)?;
        }
    }

    Ok(())
}

fn assert_invalid_encapsulation_key(
    parameter_set: MlKemParameterSet,
    public_key: &[u8],
) -> Result<(), AuditError> {
    match encapsulate(parameter_set, public_key) {
        Ok(()) => Err(AuditError::Mismatch),
        Err(CryptoError::InvalidKey) => Ok(()),
        Err(_) => Err(AuditError::Mismatch),
    }
}

fn encapsulate(parameter_set: MlKemParameterSet, public_key: &[u8]) -> Result<(), CryptoError> {
    match parameter_set {
        MlKemParameterSet::MlKem512 => ml_kem_512_encapsulate(public_key).map(|_| ()),
        MlKemParameterSet::MlKem768 => ml_kem_768_encapsulate(public_key).map(|_| ()),
        MlKemParameterSet::MlKem1024 => ml_kem_1024_encapsulate(public_key).map(|_| ()),
    }
}
