// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(
    feature = "operation-response",
    any(feature = "sha2", feature = "sha3")
))]
#![allow(clippy::unwrap_used, missing_docs)]

use buffa::EnumValue;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoIncrementalHashFinalizeRequest, CryptoIncrementalHashStartRequest, HashAlgorithm,
};
use reallyme_crypto::operation_contract::incremental_hash::IncrementalHash;

#[test]
fn algorithm_availability_follows_enabled_leaf_features() {
    for (algorithm, enabled) in [
        (
            HashAlgorithm::HASH_ALGORITHM_SHA2_256,
            cfg!(feature = "sha2"),
        ),
        (
            HashAlgorithm::HASH_ALGORITHM_SHA3_256,
            cfg!(feature = "sha3"),
        ),
    ] {
        let request = CryptoIncrementalHashStartRequest {
            algorithm: EnumValue::from(algorithm),
        };
        let result = IncrementalHash::start(&request);
        if enabled {
            let digest = result
                .unwrap()
                .finalize(&CryptoIncrementalHashFinalizeRequest::default())
                .unwrap();
            assert_eq!(digest.digest.as_slice().len(), 32);
        } else {
            assert!(matches!(
                result,
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            ));
        }
    }
}
