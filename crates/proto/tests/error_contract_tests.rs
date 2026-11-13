// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared schema identity and checked native failure construction.

#![cfg(feature = "error-types")]

use reallyme_crypto_proto::error_types::{CryptoError, CryptoErrorReason};

#[test]
fn native_constants_cover_each_nonzero_schema_reason_exactly_once() {
    use std::collections::{BTreeMap, BTreeSet};

    let schema_reasons: BTreeMap<_, _> = CryptoErrorReason::VALUES
        .iter()
        .copied()
        .filter(|reason| reason.code() != 0)
        .map(|reason| (reason.code(), reason))
        .collect();
    let native_reasons: BTreeMap<_, _> = CryptoError::VALUES
        .iter()
        .copied()
        .map(|error| (error.reason().code(), error.reason()))
        .collect();
    let schema_codes: BTreeSet<_> = schema_reasons.keys().copied().collect();
    let native_codes: BTreeSet<_> = CryptoError::VALUES
        .iter()
        .copied()
        .map(CryptoError::code)
        .collect();
    assert_eq!(native_reasons.len(), CryptoError::VALUES.len());
    assert_eq!(native_codes.len(), CryptoError::VALUES.len());
    assert_eq!(native_reasons, schema_reasons);
    assert_eq!(native_codes, schema_codes);
}

#[test]
fn native_errors_accept_every_known_nonzero_reason_and_reject_zero() {
    for &reason in CryptoErrorReason::VALUES {
        assert_eq!(CryptoErrorReason::from_code(reason.code()), Some(reason));
        if reason == CryptoErrorReason::Unspecified {
            assert_eq!(
                CryptoError::try_new(reason),
                Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
            );
            assert_eq!(reason.branch(), None);
        } else {
            let expected = CryptoError::try_new(reason);
            assert_eq!(CryptoError::try_from(reason.code()), expected);
            assert_eq!(expected.map(CryptoError::reason), Ok(reason));
            assert_eq!(expected.map(CryptoError::code), Ok(reason.code()));
            assert!(reason.branch().is_some());
        }
    }
    assert_eq!(
        CryptoError::try_from(0),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for unknown in [i32::MIN, -1] {
        assert_eq!(CryptoErrorReason::from_code(unknown), None);
        assert_eq!(
            CryptoError::try_from(unknown),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    for unknown in (1..=4_096).filter(|code| CryptoErrorReason::from_code(*code).is_none()) {
        assert_eq!(
            CryptoError::try_from(unknown),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}

#[test]
fn native_diagnostics_are_schema_names_and_have_no_backend_source() {
    use std::error::Error;

    let error = CryptoError::PRIMITIVE_INVALID_PARAMETER;
    assert_eq!(error.to_string(), error.reason().name());
    assert!(error.source().is_none());
}

#[cfg(feature = "generated")]
#[test]
fn full_bindings_share_type_identity_names_and_numeric_identity() -> Result<(), CryptoError> {
    use buffa::Enumeration;
    use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoErrorReason as WireReason;

    fn same_type(reason: CryptoErrorReason) -> WireReason {
        reason
    }
    assert_eq!(WireReason::values().len(), CryptoErrorReason::VALUES.len());
    for &reason in CryptoErrorReason::VALUES {
        let wire = same_type(reason);
        assert_eq!(WireReason::from_i32(reason.code()), Some(reason));
        assert_eq!(wire.to_i32(), reason.code());
        assert_eq!(wire.proto_name(), reason.name());
        assert_eq!(WireReason::from_proto_name(reason.name()), Some(reason));
        let encoded = serde_json::to_string(&wire).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        let decoded: WireReason =
            serde_json::from_str(&encoded).map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        assert_eq!(decoded, reason);
    }
    Ok(())
}
