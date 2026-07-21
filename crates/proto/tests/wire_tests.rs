// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "generated")]
//! Boundary tests for the public crypto protobuf wire helpers.
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Message};
use crypto_core::{
    AeadBackend, AeadFailureKind, CryptoError, SignatureBackend, SignatureFailureKind,
    SignatureOperation,
};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch, CryptoError as ProtoCryptoError,
    CryptoErrorReason, CryptoHashRequest, CryptoPrimitiveError, CryptoProviderError,
};
use reallyme_crypto_proto::wire::{
    decode_protobuf, CryptoWireError, CryptoWireErrorBranch, CryptoWireErrorValidationError,
    CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT,
};

#[test]
fn public_wire_error_constructor_rejects_invalid_branch_reason_pairs() {
    let valid = CryptoWireError::try_new(
        CryptoWireErrorBranch::Provider,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
    )
    .unwrap();
    assert_eq!(valid.branch(), CryptoWireErrorBranch::Provider);
    assert_eq!(
        valid.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE
    );

    let unspecified = CryptoWireError::try_new(
        CryptoWireErrorBranch::Primitive,
        CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED,
    )
    .unwrap_err();
    assert_eq!(
        unspecified,
        CryptoWireErrorValidationError::UnspecifiedReason
    );

    let mismatch = CryptoWireError::try_new(
        CryptoWireErrorBranch::Provider,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
    )
    .unwrap_err();
    assert_eq!(
        mismatch,
        CryptoWireErrorValidationError::BranchReasonMismatch
    );
}

#[test]
fn wire_error_preserves_branch_and_reason_through_bytes() {
    let original = CryptoWireError::try_new(
        CryptoWireErrorBranch::Primitive,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
    )
    .unwrap();
    let decoded = CryptoWireError::decode(&original.encode_to_vec()).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn wire_error_preserves_unknown_reason_code_within_branch_range() {
    const FUTURE_REASON_CODE: i32 = 199;
    let error = ProtoCryptoError {
        error: Some(CryptoErrorBranch::Primitive(Box::new(
            CryptoPrimitiveError {
                reason: EnumValue::from(FUTURE_REASON_CODE),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let decoded = CryptoWireError::decode(&error.encode_to_vec()).unwrap();

    assert_eq!(decoded.branch(), CryptoWireErrorBranch::Primitive);
    assert_eq!(decoded.reason_code(), FUTURE_REASON_CODE);
    assert_eq!(decoded.known_reason(), None);
    assert_eq!(
        decoded.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED
    );
    assert_eq!(
        CryptoWireError::decode(&decoded.encode_to_vec()).unwrap(),
        decoded
    );
}

#[test]
fn wire_error_rejects_unknown_reason_code_outside_branch_range() {
    const INVALID_REASON_CODE: i32 = 777;
    let error = ProtoCryptoError {
        error: Some(CryptoErrorBranch::Primitive(Box::new(
            CryptoPrimitiveError {
                reason: EnumValue::from(INVALID_REASON_CODE),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let decoded = CryptoWireError::decode(&error.encode_to_vec()).unwrap_err();

    assert_eq!(decoded.branch(), CryptoWireErrorBranch::Primitive);
    assert_eq!(
        decoded.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
    );
}

#[test]
fn wire_error_envelope_decode_rejects_oversized_inputs() {
    let oversized = vec![0; CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT + 1];
    let decoded = CryptoWireError::decode(&oversized).unwrap_err();

    assert_eq!(decoded.branch(), CryptoWireErrorBranch::Primitive);
    assert_eq!(
        decoded.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
    );
}

#[test]
fn protobuf_decode_rejects_unknown_fields() {
    // Field 2,047 with varint wire type, followed by value zero. The bytes are
    // individually valid but executable requests reject every unknown field so
    // binary protobuf matches strict generated ProtoJSON.
    const UNKNOWN_FIELD: [u8; 3] = [0xf8, 0x7f, 0x00];

    let error = decode_protobuf::<CryptoHashRequest>(&UNKNOWN_FIELD).unwrap_err();
    assert_eq!(
        error.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
    );
}

#[test]
fn wire_error_rejects_missing_unspecified_or_mismatched_error_envelopes() {
    let missing = ProtoCryptoError {
        error: None,
        __buffa_unknown_fields: Default::default(),
    };
    let unspecified = ProtoCryptoError {
        error: Some(CryptoErrorBranch::Primitive(Box::new(
            CryptoPrimitiveError {
                reason: EnumValue::from(CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let mismatched = ProtoCryptoError {
        error: Some(CryptoErrorBranch::Provider(Box::new(CryptoProviderError {
            reason: EnumValue::from(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    for encoded in [
        missing.encode_to_vec(),
        unspecified.encode_to_vec(),
        mismatched.encode_to_vec(),
    ] {
        let decoded = CryptoWireError::decode(&encoded).unwrap_err();
        assert_eq!(decoded.branch(), CryptoWireErrorBranch::Primitive);
        assert_eq!(
            decoded.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
        );
    }
}

#[test]
fn invalid_inputs_do_not_map_to_authentication_failure() {
    let invalid_key = CryptoWireError::from(CryptoError::InvalidAeadKeyLength {
        expected: 32,
        actual: 31,
    });
    assert_eq!(
        invalid_key.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY
    );

    let invalid_nonce = CryptoWireError::from(CryptoError::InvalidAeadNonceLength {
        expected: 12,
        actual: 11,
    });
    assert_eq!(
        invalid_nonce.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE
    );

    let invalid_public_key = CryptoWireError::from(CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidPublicKey,
    });
    assert_eq!(
        invalid_public_key.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY
    );
}

#[test]
fn authentication_failures_remain_authentication_failures() {
    let auth = CryptoWireError::from(CryptoError::AeadDecrypt {
        backend: AeadBackend::Native,
        kind: AeadFailureKind::AuthenticationFailed,
    });
    assert_eq!(
        auth.reason(),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED
    );
}
