// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![cfg(not(feature = "hmac"))]

//! Feature-off tests for the MAC operation owner.

use reallyme_crypto::operations::{OperationError, ProviderErrorReason};
use reallyme_crypto::MacAlgorithm;

#[test]
fn disabled_mac_provider_fails_closed_for_authenticate_and_verify() {
    for algorithm in [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ] {
        assert_eq!(
            reallyme_crypto::operations::mac::authenticate(algorithm, b"key", b"message"),
            Err(OperationError::Provider {
                reason: ProviderErrorReason::UnsupportedAlgorithm,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::mac::verify(algorithm, b"key", b"message", b"tag",),
            Err(OperationError::Provider {
                reason: ProviderErrorReason::UnsupportedAlgorithm,
            })
        );
    }
}
