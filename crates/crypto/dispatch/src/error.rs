// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

use crypto_core::{AeadAlgorithm, Algorithm, CryptoError, HashAlgorithm, MacAlgorithm};

/// Error returned by algorithm dispatch operations.
#[derive(Debug, Error)]
pub enum AlgorithmError {
    /// The requested operation is not supported for this algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(Algorithm),

    /// The requested AEAD algorithm is not supported.
    #[error("unsupported AEAD algorithm: {0}")]
    UnsupportedAeadAlgorithm(AeadAlgorithm),

    /// The requested hash algorithm is not supported.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(HashAlgorithm),

    /// The requested MAC algorithm is not supported.
    #[error("unsupported MAC algorithm: {0}")]
    UnsupportedMacAlgorithm(MacAlgorithm),

    /// The supplied key is malformed or invalid for the algorithm.
    #[error("invalid key for algorithm: {0}")]
    InvalidKey(Algorithm),

    /// A signature failed verification (dispatch fails closed here).
    #[error("signature verification failed for {0}")]
    SignatureInvalid(Algorithm),

    /// An error propagated from an underlying crypto primitive.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
