// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "operation-response")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::{EnumValue, Enumeration};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmFamily;
use reallyme_crypto::operations::OperationFamily;
#[test]
fn every_schema_operation_family_has_exact_native_parity() {
    for value in CryptoAlgorithmFamily::values() {
        let native = OperationFamily::try_from(EnumValue::from(*value));
        if value.to_i32() == 0 {
            assert_eq!(native, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
        } else {
            assert_eq!(
                CryptoAlgorithmFamily::from(native.expect("known family")),
                *value
            );
        }
    }
    for value in [-1, 12, 999_999, i32::MAX] {
        assert_eq!(
            OperationFamily::try_from(EnumValue::<CryptoAlgorithmFamily>::from(value)),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    assert_eq!(
        CryptoAlgorithmFamily::from(OperationFamily::ConstantTime).to_i32(),
        10
    );
    assert_eq!(
        CryptoAlgorithmFamily::from(OperationFamily::PlatformKey).to_i32(),
        11
    );
    assert_eq!(OperationFamily::Hash as u8, 0);
}
