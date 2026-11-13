// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::Message;
use crypto_constant_time::proto_helpers::ConstantTimeInputs;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoConstantTimeCompareRequest, CryptoConstantTimeCompareResult,
    CryptoConstantTimeRequireEqualResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
fn request(left: &[u8], right: &[u8]) -> CryptoConstantTimeCompareRequest {
    CryptoConstantTimeCompareRequest {
        left: left.to_vec(),
        right: right.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}
#[test]
fn comparison_preserves_equal_mismatch_and_empty_semantics() {
    for (left, right, expected) in [
        (b"a\0\xff".as_slice(), b"a\0\xff".as_slice(), true),
        (b"a\0\xff".as_slice(), b"a\0\xfe".as_slice(), false),
        (b"a".as_slice(), b"ab".as_slice(), false),
        (b"".as_slice(), b"".as_slice(), true),
    ] {
        let inputs = ConstantTimeInputs::try_from(&request(left, right)).expect("inputs");
        assert_eq!(inputs.equal(), expected);
        assert_eq!(inputs.compare_result().equal, expected);
    }
}
#[test]
fn require_and_fixed_comparisons_keep_exact_error_reasons() {
    let equal = ConstantTimeInputs::try_from(&request(b"abc", b"abc")).expect("inputs");
    assert_eq!(equal.equal_fixed::<3>(), Ok(true));
    assert_eq!(
        equal.equal_fixed::<4>(),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    equal.require_equal().expect("native equality requirement");
    let mismatch = ConstantTimeInputs::try_from(&request(b"abc", b"abd")).expect("inputs");
    assert_eq!(mismatch.equal_fixed::<3>(), Ok(false));
    assert_eq!(
        mismatch.require_equal().err(),
        Some(CryptoError::PRIMITIVE_VERIFICATION_FAILED)
    );
    let different_width = ConstantTimeInputs::try_from(&request(b"abc", b"abcd")).expect("inputs");
    assert_eq!(
        different_width.require_equal().err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
}
#[test]
fn comparison_unknown_modifiers_fail_closed_and_owners_clear() -> Result<(), buffa::DecodeError> {
    fn cleanup<T: ZeroizeOnDrop>() {}
    cleanup::<ConstantTimeInputs>();
    cleanup::<CryptoConstantTimeCompareRequest>();
    cleanup::<CryptoConstantTimeCompareResult>();
    cleanup::<CryptoConstantTimeRequireEqualResult>();
    let mut wire = request(b"secret", b"secret");
    wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        ConstantTimeInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut owner = ConstantTimeInputs::try_from(&request(b"secret", b"other!")).expect("inputs");
    owner.zeroize();
    assert_eq!(owner.equal_fixed::<0>(), Ok(true));
    Ok(())
}
