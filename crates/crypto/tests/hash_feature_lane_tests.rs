// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed coverage for builds without hash primitive features.

#![cfg(all(feature = "dispatch", not(feature = "sha2"), not(feature = "sha3")))]

use crypto_core::HashAlgorithm;
use crypto_dispatch::AlgorithmError;
use reallyme_crypto::operations::{OperationError, ProviderErrorReason};

#[test]
fn hash_operation_rejects_feature_disabled_algorithms() {
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha2_256, b"message"),
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        }),
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha3_256, b"message"),
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        }),
    );
}

#[test]
fn root_dispatch_facade_preserves_typed_unsupported_hash_error() {
    assert!(matches!(
        reallyme_crypto::dispatch::hash_digest(HashAlgorithm::Sha2_256, b"message"),
        Err(AlgorithmError::UnsupportedHashAlgorithm(
            HashAlgorithm::Sha2_256,
        )),
    ));
    assert!(matches!(
        reallyme_crypto::dispatch::hash_digest(HashAlgorithm::Sha3_256, b"message"),
        Err(AlgorithmError::UnsupportedHashAlgorithm(
            HashAlgorithm::Sha3_256,
        )),
    ));
}
