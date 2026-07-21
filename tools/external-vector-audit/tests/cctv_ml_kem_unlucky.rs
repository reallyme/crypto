// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! CCTV ML-KEM unlucky XOF vector status checks.

#[path = "support/cctv_ml_kem.rs"]
mod cctv_ml_kem;

use cctv_ml_kem::{load_unlucky_vector, ALL_PARAMETER_SETS};
use external_vector_audit::support::AuditError;

#[test]
fn cctv_ml_kem_unlucky_vectors_are_vendored_for_final_fips_review() -> Result<(), AuditError> {
    for parameter_set in ALL_PARAMETER_SETS {
        let vector = load_unlucky_vector(parameter_set)?;
        if vector.seed.iter().all(|byte| *byte == 0)
            || vector.ek.is_empty()
            || vector.m.iter().all(|byte| *byte == 0)
            || vector.c.is_empty()
            || vector.k.iter().all(|byte| *byte == 0)
        {
            return Err(AuditError::Shape);
        }
    }

    Ok(())
}
