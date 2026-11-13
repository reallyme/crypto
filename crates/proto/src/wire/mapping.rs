// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::error::{CryptoWireError, CryptoWireErrorBranch};
use crate::error_types::{CryptoError, CryptoErrorBranch};

impl From<CryptoError> for CryptoWireError {
    fn from(value: CryptoError) -> Self {
        let branch = match value.reason().branch() {
            Some(CryptoErrorBranch::Primitive) => CryptoWireErrorBranch::Primitive,
            Some(CryptoErrorBranch::Provider) => CryptoWireErrorBranch::Provider,
            Some(CryptoErrorBranch::Backend) => CryptoWireErrorBranch::Backend,
            // A native error can only contain a known, nonzero reason.
            None => {
                return Self::backend_internal(
                    crate::error_types::CryptoErrorReason::BackendInternal,
                )
            }
        };
        Self::known_good(branch, value.reason())
    }
}
