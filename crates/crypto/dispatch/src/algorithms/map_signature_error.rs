// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{Algorithm, CryptoError, SignatureFailureKind, SignatureOperation};

use crate::AlgorithmError;

pub(crate) fn map_verify_error(algorithm: Algorithm, error: CryptoError) -> AlgorithmError {
    match error {
        CryptoError::Signature {
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
            ..
        } => AlgorithmError::SignatureInvalid(algorithm),
        other => AlgorithmError::from(other),
    }
}
