// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "dispatch", feature = "hmac"))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Operation-owner tests for MAC routes.

use crypto_core::{CryptoError, MacAlgorithm, MacFailureKind};
use reallyme_crypto::dispatch::MacParams;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

#[test]
fn mac_operation_matches_root_hmac_and_dispatch_facades() {
    let key_bytes = [0x42u8; 32];
    let message = b"reallyme crypto MAC parity";
    let cases = [
        (MacAlgorithm::HmacSha256, 32usize),
        (MacAlgorithm::HmacSha384, 48usize),
        (MacAlgorithm::HmacSha512, 64usize),
    ];

    for (algorithm, expected_len) in cases {
        let operation_tag =
            reallyme_crypto::operations::mac::authenticate(algorithm, &key_bytes, message)
                .expect("operation MAC succeeds");
        let hmac_key =
            reallyme_crypto::hmac::HmacKey::from_slice(&key_bytes).expect("HMAC key is valid");
        let root_tag = reallyme_crypto::hmac::authenticate(algorithm, &hmac_key, message)
            .expect("root HMAC succeeds");
        let params = MacParams { key: &key_bytes };
        let dispatch_tag = reallyme_crypto::dispatch::mac_authenticate(algorithm, &params, message)
            .expect("dispatch MAC succeeds");

        assert_eq!(operation_tag.len(), expected_len);
        assert_eq!(operation_tag, root_tag.as_bytes());
        assert_eq!(operation_tag, dispatch_tag);
        reallyme_crypto::operations::mac::verify(algorithm, &key_bytes, message, &operation_tag)
            .expect("operation verify succeeds");
        reallyme_crypto::hmac::verify(algorithm, &hmac_key, message, &operation_tag)
            .expect("root verify succeeds");
        reallyme_crypto::dispatch::mac_verify(algorithm, &params, message, &operation_tag)
            .expect("dispatch verify succeeds");
    }
}

#[test]
fn mac_operation_reports_stable_failure_reasons_for_malicious_inputs() {
    let key = [0x11u8; 32];
    let message = b"message";
    let tag =
        reallyme_crypto::operations::mac::authenticate(MacAlgorithm::HmacSha256, &key, message)
            .expect("operation MAC succeeds");
    let mut tampered_tag = tag.clone();
    let first = tampered_tag.first_mut().expect("tag is not empty");
    *first ^= 0x01;

    assert_eq!(
        reallyme_crypto::operations::mac::authenticate(MacAlgorithm::HmacSha256, &[], message,),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        })
    );

    let oversized_key = vec![0x22u8; reallyme_crypto::hmac::HMAC_MAX_KEY_LENGTH + 1];
    assert_eq!(
        reallyme_crypto::operations::mac::authenticate(
            MacAlgorithm::HmacSha512,
            &oversized_key,
            message,
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        })
    );

    assert_eq!(
        reallyme_crypto::operations::mac::verify(
            MacAlgorithm::HmacSha256,
            &key,
            message,
            &tag[..31]
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        })
    );
    assert_eq!(
        reallyme_crypto::operations::mac::verify(
            MacAlgorithm::HmacSha256,
            &key,
            message,
            &tampered_tag,
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        })
    );
}

#[test]
fn root_facades_preserve_historical_mac_error_shapes() {
    let key = [0x33u8; 32];
    let message = b"message";
    let params = MacParams { key: &key };
    let tag =
        reallyme_crypto::dispatch::mac_authenticate(MacAlgorithm::HmacSha256, &params, message)
            .expect("dispatch MAC succeeds");
    let mut tampered_tag = tag.clone();
    let first = tampered_tag.first_mut().expect("tag is not empty");
    *first ^= 0x80;

    assert!(matches!(
        reallyme_crypto::dispatch::mac_verify(
            MacAlgorithm::HmacSha256,
            &params,
            message,
            &tampered_tag,
        ),
        Err(reallyme_crypto::dispatch::AlgorithmError::Crypto(
            CryptoError::Mac {
                kind: MacFailureKind::VerificationFailed,
                ..
            }
        ))
    ));

    let hmac_key = reallyme_crypto::hmac::HmacKey::from_slice(&key).expect("HMAC key is valid");
    assert!(matches!(
        reallyme_crypto::hmac::verify(MacAlgorithm::HmacSha256, &hmac_key, message, &tag[..31],),
        Err(CryptoError::Mac {
            kind: MacFailureKind::InvalidTagLength,
            ..
        })
    ));
}
