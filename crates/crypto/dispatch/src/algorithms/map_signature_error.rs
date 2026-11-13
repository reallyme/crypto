// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{Algorithm, CryptoError};

use crate::AlgorithmError;

pub(crate) fn map_verify_error(_algorithm: Algorithm, error: CryptoError) -> AlgorithmError {
    error
}
