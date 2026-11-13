// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated/native policy parity and closed-boundary rejection coverage.

#![cfg(feature = "operation-response")]
#![allow(missing_docs, clippy::expect_used)]

use buffa::{EnumValue, Enumeration};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::PlatformKeyOperation as ProtoPlatformKeyOperation;

#[test]
fn platform_key_operation_has_total_schema_parity() {
    assert_enum_parity::<
        ProtoPlatformKeyOperation,
        reallyme_crypto::operations::platform_key::PlatformKeyOperation,
    >();
}

fn assert_enum_parity<P, N>()
where
    P: Enumeration + From<N> + PartialEq + core::fmt::Debug + 'static,
    N: TryFrom<EnumValue<P>, Error = CryptoError> + PartialEq + core::fmt::Debug,
{
    for value in P::values() {
        let converted = N::try_from(EnumValue::from(*value));
        if value.to_i32() == 0 {
            assert_eq!(converted, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
        } else {
            let native = converted.expect("every declared nonzero policy value has a native peer");
            assert_eq!(P::from(native), *value);
        }
    }
    for unknown in [i32::MIN, -1, 1, 99, 999_999, i32::MAX] {
        let value = EnumValue::<P>::from(unknown);
        assert!(value.as_known().is_none());
        assert_eq!(
            N::try_from(value),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}
