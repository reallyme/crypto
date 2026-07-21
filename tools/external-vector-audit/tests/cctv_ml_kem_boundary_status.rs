// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! CCTV ML-KEM vector classes that are present but outside public APIs.

#[path = "support/cctv_ml_kem.rs"]
mod cctv_ml_kem;

use cctv_ml_kem::{
    intermediate_text_has_internal_markers, load_strcmp_vector_shape, ALL_PARAMETER_SETS,
};
use external_vector_audit::support::{load_text, AuditError};

const REALLYME_ML_KEM_SECRET_SEED_LEN: usize = 64;
const ML_KEM_SHARED_SECRET_LEN: usize = 32;
const CCTV_ACCUMULATED_HASHES_10K: [&str; 3] = [
    "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4",
    "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3",
    "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543",
];
const CCTV_ACCUMULATED_HASHES_1M: [&str; 3] = [
    "578eeaa1156848cbf7a15bafef963b4ccabe3308ddfb7dbdd20ad965f634e81d",
    "70090cc5842aad0ec43d5042c783fae9bc320c047b5dafcb6e134821db02384d",
    "7ccc6d803739d3db3c5ce39c7130f459db32a199c6605e3be210e5a89d4c4b95",
];

#[test]
fn cctv_ml_kem_strcmp_vectors_require_full_decapsulation_key_import() -> Result<(), AuditError> {
    for parameter_set in ALL_PARAMETER_SETS {
        let shape = load_strcmp_vector_shape(parameter_set)?;
        if shape.decapsulation_key_len <= REALLYME_ML_KEM_SECRET_SEED_LEN {
            return Err(AuditError::Shape);
        }
        if shape.ciphertext_len == 0 || shape.shared_secret_len != ML_KEM_SHARED_SECRET_LEN {
            return Err(AuditError::Shape);
        }
    }

    Ok(())
}

#[test]
fn cctv_ml_kem_intermediate_vectors_require_internal_math_boundary() -> Result<(), AuditError> {
    for parameter_set in ALL_PARAMETER_SETS {
        if !intermediate_text_has_internal_markers(parameter_set)? {
            return Err(AuditError::Shape);
        }
    }

    Ok(())
}

#[test]
fn cctv_ml_kem_accumulated_vectors_require_full_decapsulation_key_export() -> Result<(), AuditError>
{
    let readme = load_text("cctv/ml-kem/README.md")?;
    if !readme.contains("`dk` from ML-KEM.KeyGen") {
        return Err(AuditError::Shape);
    }

    for expected_hash in CCTV_ACCUMULATED_HASHES_10K {
        if !readme.contains(expected_hash) {
            return Err(AuditError::Shape);
        }
    }

    for expected_hash in CCTV_ACCUMULATED_HASHES_1M {
        if !readme.contains(expected_hash) {
            return Err(AuditError::Shape);
        }
    }

    for parameter_set in ALL_PARAMETER_SETS {
        let shape = load_strcmp_vector_shape(parameter_set)?;
        if shape.decapsulation_key_len <= REALLYME_ML_KEM_SECRET_SEED_LEN {
            return Err(AuditError::Shape);
        }
    }

    Ok(())
}
