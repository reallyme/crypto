// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for constant-time equality operations.

use super::{OperationError, PrimitiveErrorReason};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Compare same-length byte slices without data-dependent early exit.
///
/// Length mismatch remains public metadata and returns `false` before entering
/// the primitive comparator. Equal-length contents are compared by the reviewed
/// constant-time crate so adapters do not choose their own equality semantics.
pub fn equal(left: &[u8], right: &[u8]) -> bool {
    let _policy = bind_operation_policy(SecretMaterialOperation::ConstantTimeCompare);
    crypto_constant_time::ct_eq(left, right)
}

/// Compare fixed-size byte arrays without data-dependent early exit.
pub fn equal_fixed<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let _policy = bind_operation_policy(SecretMaterialOperation::ConstantTimeCompare);
    crypto_constant_time::ct_eq_fixed(left, right)
}

/// Require equality and return a fixed operation-layer reason on failure.
pub fn require_equal(left: &[u8], right: &[u8]) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::ConstantTimeCompare);
    if left.len() != right.len() {
        return Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        });
    }

    if equal(left, right) {
        return Ok(());
    }

    Err(OperationError::Primitive {
        reason: PrimitiveErrorReason::VerificationFailed,
    })
}
